"""
FSx for NetApp ONTAP - Monthly Audit / Capacity Report
--------------------------------------------------------
Triggered by EventBridge on the 1st of each month. Builds a daily
(day 1 -> last day) capacity/performance report for the PREVIOUS month
covering every FSx ONTAP file system, its SVMs and volumes, uploads an
HTML report to S3, signs a 7-day presigned URL, and emails it via SNS.

ENV VARS REQUIRED:
  REPORT_BUCKET          - S3 bucket to store the report
  SNS_TOPIC_ARN           - SNS topic to notify
  SIGNING_SECRET_ID       - Secrets Manager secret holding long-term IAM
                             user keys used ONLY to sign the 7-day URL
                             Secret JSON: {"aws_access_key_id": "...",
                                           "aws_secret_access_key": "..."}
  WARN_THRESHOLD_PCT      - optional, default "75"
  BAD_THRESHOLD_PCT       - optional, default "90"

KNOWN AWS LIMITATION - PLEASE VALIDATE BEFORE RELYING ON THIS IN AUDIT:
  Per-volume CloudWatch metrics (StorageCapacity/StorageUsed dimensioned
  by FileSystemId + StorageVirtualMachineId + VolumeId) are exposed by
  AWS for FSx ONTAP, but exact availability/naming can vary by file
  system creation date / AWS region rollout. This code queries CloudWatch
  first and, if that comes back empty for a volume, falls back to the
  volume's CURRENT capacity from the FSx API (describe_volumes) so the
  report never silently shows a blank month - it flags it instead as
  "CloudWatch history unavailable, showing current snapshot only."
  Check the AWS/FSx namespace in the CloudWatch console for your file
  systems and adjust METRIC_DIMENSION_SETS below if needed.

  Per-volume SNAPSHOT SIZE is NOT exposed via the FSx or CloudWatch APIs
  today - only via the ONTAP REST/CLI management API on the SVM
  management LIF, which requires network reachability into the FSx VPC.
  This report includes a "Snapshot Size" column that will show "N/A -
  requires ONTAP API" unless you implement get_snapshot_size_ontap_api()
  below (stub provided) with an ONTAP API client running from a Lambda
  attached to the FSx VPC/subnet.
"""

import os
import io
import csv
import json
import calendar
import datetime
import boto3
from botocore.exceptions import ClientError

# =============================================================================
# Shared helper code (normally in report_common.py) - inlined here so
# this single file can be pasted directly into the Lambda console.
# =============================================================================

# ---------------------------------------------------------------------------
# Date range helper
# ---------------------------------------------------------------------------

def get_previous_month_range(today=None):
    """
    Returns (start_date, end_date) as datetime.date objects covering the
    FULL previous calendar month (day 1 -> last day), regardless of which
    day the Lambda actually runs on. Intended to be triggered on the 1st,
    but is safe to re-run any day of the month.
    """
    today = today or datetime.date.today()
    first_of_this_month = today.replace(day=1)
    last_day_prev_month = first_of_this_month - datetime.timedelta(days=1)
    start_date = last_day_prev_month.replace(day=1)
    end_date = last_day_prev_month
    return start_date, end_date


def daterange_days(start_date, end_date):
    """Yield every date from start_date to end_date inclusive."""
    for n in range((end_date - start_date).days + 1):
        yield start_date + datetime.timedelta(days=n)


# ---------------------------------------------------------------------------
# CloudWatch helper
# ---------------------------------------------------------------------------

def get_daily_metric(cw_client, namespace, metric_name, dimensions,
                      start_date, end_date, stat="Average", unit=None):
    """
    Fetch one daily datapoint (period=86400s) per day for a metric across
    a date range using GetMetricData. Returns a dict {date: value_or_None}.

    dimensions: list of {"Name": ..., "Value": ...}
    """
    start_dt = datetime.datetime.combine(start_date, datetime.time.min)
    end_dt = datetime.datetime.combine(end_date, datetime.time.max)

    metric_query = {
        "Id": "m1",
        "MetricStat": {
            "Metric": {
                "Namespace": namespace,
                "MetricName": metric_name,
                "Dimensions": dimensions,
            },
            "Period": 86400,  # 1 day
            "Stat": stat,
        },
        "ReturnData": True,
    }
    if unit:
        metric_query["MetricStat"]["Unit"] = unit

    results = {}
    next_token = None
    try:
        while True:
            kwargs = dict(
                MetricDataQueries=[metric_query],
                StartTime=start_dt,
                EndTime=end_dt,
                ScanBy="TimestampAscending",
            )
            if next_token:
                kwargs["NextToken"] = next_token
            resp = cw_client.get_metric_data(**kwargs)
            for mdr in resp.get("MetricDataResults", []):
                for ts, val in zip(mdr["Timestamps"], mdr["Values"]):
                    results[ts.date()] = val
            next_token = resp.get("NextToken")
            if not next_token:
                break
    except ClientError as e:
        print(f"CloudWatch error for {metric_name} {dimensions}: {e}")

    # Fill missing days with None so the report shows gaps explicitly
    return {d: results.get(d) for d in daterange_days(start_date, end_date)}


# ---------------------------------------------------------------------------
# S3 upload
# ---------------------------------------------------------------------------

def upload_html_to_s3(s3_client, bucket, key, html_body, kms_key_id=None):
    """
    kms_key_id: ARN or key ID of the customer managed KMS key the bucket
    requires. If the bucket enforces SSE-KMS with a specific CMK (a
    common bucket-policy requirement), this MUST be passed - PutObject
    will be denied otherwise, or may be encrypted with the wrong key if
    the caller has access to more than one CMK.
    """
    put_kwargs = dict(
        Bucket=bucket,
        Key=key,
        Body=html_body.encode("utf-8"),
        ContentType="text/html",
    )
    if kms_key_id:
        put_kwargs["ServerSideEncryption"] = "aws:kms"
        put_kwargs["SSEKMSKeyId"] = kms_key_id
    else:
        put_kwargs["ServerSideEncryption"] = "AES256"

    s3_client.put_object(**put_kwargs)
    return f"s3://{bucket}/{key}"


# ---------------------------------------------------------------------------
# Presigned URL - MUST use long-term IAM user credentials.
#
# IMPORTANT: A Lambda's execution-role credentials are temporary (STS) and
# expire well before 7 days. A presigned URL signed with temporary
# credentials becomes invalid the moment those credentials expire -
# regardless of the Expires value you pass. To get a real 7-day link you
# need to sign with a long-term access key belonging to an IAM user that
# has s3:GetObject on the bucket. Store that key pair in Secrets Manager
# and only use it for signing (never for anything else).
#
# SSE-KMS WITH A CUSTOMER MANAGED KEY - SECOND REQUIREMENT:
# If the bucket enforces SSE-KMS with a customer managed key (CMK), an
# IAM policy granting s3:GetObject is NOT enough. When someone clicks the
# presigned link, S3 calls KMS to decrypt the object using the identity
# that SIGNED the URL (the signing IAM user here) - not the anonymous
# clicker. That means the signing user needs BOTH:
#   1. An IAM policy statement allowing kms:Decrypt on the CMK, AND
#   2. A statement in the CMK's own key policy (resource policy)
#      granting that same principal kms:Decrypt - IAM policy alone does
#      not satisfy this unless the key policy has a statement enabling
#      IAM policies to take effect for that principal.
# Without both, the presigned link returns a 403/KMS AccessDenied to
# whoever clicks it, even though the S3 permission looks correct.
# See iam-policy-presign-signing-user.json and kms-key-policy-snippet.json.
# ---------------------------------------------------------------------------

def get_signing_credentials(secrets_client, secret_id):
    resp = secrets_client.get_secret_value(SecretId=secret_id)
    secret = json.loads(resp["SecretString"])
    return secret["aws_access_key_id"], secret["aws_secret_access_key"]


def generate_presigned_url(bucket, key, region, secret_id, expires_seconds=7 * 24 * 60 * 60):
    secrets_client = boto3.client("secretsmanager", region_name=region)
    access_key, secret_key = get_signing_credentials(secrets_client, secret_id)

    signing_s3 = boto3.client(
        "s3",
        region_name=region,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
    )
    url = signing_s3.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=expires_seconds,
    )
    return url


# ---------------------------------------------------------------------------
# SNS
# ---------------------------------------------------------------------------

def publish_sns(sns_client, topic_arn, subject, message):
    sns_client.publish(
        TopicArn=topic_arn,
        Subject=subject[:100],
        Message=message,
    )


# ---------------------------------------------------------------------------
# HTML shell / CSS - shared corporate look for both reports
# ---------------------------------------------------------------------------

BASE_CSS = """
:root{
  --ink:#152238;
  --ink-soft:#4a5670;
  --line:#dde3ee;
  --bg:#f6f8fb;
  --panel:#ffffff;
  --accent:#0f5fa6;
  --accent-soft:#e6f0fa;
  --good:#1c8a5c;
  --warn:#c07a10;
  --bad:#c0392b;
  --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
}
*{box-sizing:border-box;}
body{
  margin:0; background:var(--bg); color:var(--ink);
  font-family: -apple-system, 'Segoe UI', Helvetica, Arial, sans-serif;
  font-size:14px; line-height:1.5;
}
.wrap{max-width:1180px; margin:0 auto; padding:32px 24px 80px;}
.header{
  display:flex; justify-content:space-between; align-items:flex-end;
  border-bottom:3px solid var(--ink); padding-bottom:18px; margin-bottom:28px;
}
.header h1{font-size:22px; margin:0 0 4px; letter-spacing:.2px;}
.header .sub{color:var(--ink-soft); font-size:13px;}
.header .period{
  text-align:right; font-family:var(--mono); font-size:12px; color:var(--ink-soft);
}
.badge{
  display:inline-block; padding:2px 8px; border-radius:3px; font-size:11px;
  font-weight:600; letter-spacing:.3px; text-transform:uppercase;
}
.badge.ok{background:#e5f4ec; color:var(--good);}
.badge.warn{background:#fbf0dd; color:var(--warn);}
.badge.bad{background:#fbe7e4; color:var(--bad);}

.summary-grid{
  display:grid; grid-template-columns:repeat(auto-fit, minmax(180px,1fr));
  gap:14px; margin-bottom:30px;
}
.stat-card{
  background:var(--panel); border:1px solid var(--line); border-left:4px solid var(--accent);
  border-radius:4px; padding:14px 16px;
}
.stat-card .label{font-size:11px; text-transform:uppercase; letter-spacing:.4px; color:var(--ink-soft); margin-bottom:6px;}
.stat-card .value{font-size:22px; font-weight:700; font-family:var(--mono);}
.stat-card .value.small{font-size:15px; font-weight:600;}

.section{margin-bottom:34px;}
.section h2{
  font-size:15px; text-transform:uppercase; letter-spacing:.5px;
  border-bottom:1px solid var(--line); padding-bottom:8px; margin-bottom:14px;
  color:var(--ink); display:flex; justify-content:space-between; align-items:center;
}
.section p.note{color:var(--ink-soft); font-size:12.5px; margin-top:-6px; margin-bottom:14px;}

table{width:100%; border-collapse:collapse; background:var(--panel); font-size:12.5px;}
table.striped tr:nth-child(even) td{background:#fafbfd;}
th{
  text-align:left; background:var(--ink); color:#fff; padding:9px 10px;
  font-weight:600; font-size:11.5px; text-transform:uppercase; letter-spacing:.3px;
  position:sticky; top:0;
}
td{padding:8px 10px; border-bottom:1px solid var(--line); font-family:var(--mono);}
td.text{font-family:inherit;}
tr:hover td{background:var(--accent-soft);}
.table-scroll{max-height:520px; overflow:auto; border:1px solid var(--line); border-radius:4px;}

.csv-btn{
  background:var(--accent); color:#fff; border:none; padding:6px 12px;
  border-radius:3px; font-size:11.5px; font-weight:600; cursor:pointer; letter-spacing:.2px;
}
.csv-btn:hover{background:#0c4d87;}

.pill-util{display:inline-block; min-width:46px; text-align:right; font-weight:700;}
.pill-util.ok{color:var(--good);}
.pill-util.warn{color:var(--warn);}
.pill-util.bad{color:var(--bad);}

.footer{
  margin-top:40px; padding-top:16px; border-top:1px solid var(--line);
  color:var(--ink-soft); font-size:11.5px; display:flex; justify-content:space-between;
}
@media print{
  .csv-btn{display:none;}
  body{background:#fff;}
}
"""

CSV_EXPORT_JS = """
function tableToCSV(tableId, filename){
  const table = document.getElementById(tableId);
  if(!table) return;
  const rows = table.querySelectorAll('tr');
  let csv = [];
  rows.forEach(row => {
    const cells = row.querySelectorAll('th,td');
    const line = Array.from(cells).map(c => {
      let t = c.innerText.replace(/"/g,'""');
      return '"' + t + '"';
    }).join(',');
    csv.push(line);
  });
  const blob = new Blob([csv.join('\\n')], {type:'text/csv;charset=utf-8;'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
"""


def util_class(pct):
    """Return CSS class + badge tier for a utilization percentage."""
    if pct is None:
        return "", "n/a"
    if pct >= 90:
        return "bad", "bad"
    if pct >= 75:
        return "warn", "warn"
    return "ok", "ok"


def fmt_bytes(n, suffix="B"):
    if n is None:
        return "N/A"
    n = float(n)
    for unit in ["", "K", "M", "G", "T", "P"]:
        if abs(n) < 1024.0:
            return f"{n:3.1f} {unit}{suffix}"
        n /= 1024.0
    return f"{n:.1f} E{suffix}"


def html_escape(s):
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )

# =============================================================================
# Handler code
# =============================================================================

REGION = os.environ.get("AWS_REGION", "us-east-1")
BUCKET = os.environ["REPORT_BUCKET"]
TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
SIGNING_SECRET_ID = os.environ["SIGNING_SECRET_ID"]
KMS_KEY_ID = os.environ["KMS_KEY_ID"]  # CMK ARN or key ID the bucket requires for SSE-KMS
WARN_PCT = float(os.environ.get("WARN_THRESHOLD_PCT", "75"))
BAD_PCT = float(os.environ.get("BAD_THRESHOLD_PCT", "90"))

fsx = boto3.client("fsx", region_name=REGION)
cw = boto3.client("cloudwatch", region_name=REGION)
s3 = boto3.client("s3", region_name=REGION)
sns = boto3.client("sns", region_name=REGION)


# ---------------------------------------------------------------------------
# Inventory collection
# ---------------------------------------------------------------------------

def get_tag_name(tags):
    for t in tags or []:
        if t.get("Key") == "Name":
            return t.get("Value")
    return ""


def list_ontap_file_systems():
    fs_list = []
    paginator = fsx.get_paginator("describe_file_systems")
    for page in paginator.paginate():
        for fs in page["FileSystems"]:
            if fs.get("FileSystemType") == "ONTAP":
                fs_list.append(fs)
    return fs_list


def list_svms(file_system_id):
    svms = []
    paginator = fsx.get_paginator("describe_storage_virtual_machines")
    for page in paginator.paginate(
        Filters=[{"Name": "file-system-id", "Values": [file_system_id]}]
    ):
        svms.extend(page["StorageVirtualMachines"])
    return svms


def list_volumes(svm_id):
    vols = []
    paginator = fsx.get_paginator("describe_volumes")
    for page in paginator.paginate(
        Filters=[{"Name": "storage-virtual-machine-id", "Values": [svm_id]}]
    ):
        vols.extend(page["Volumes"])
    return vols


def get_snapshot_size_ontap_api(volume):
    """
    STUB - AWS does not expose per-volume snapshot size via FSx or
    CloudWatch APIs. To populate this, call the ONTAP REST API
    (`/storage/volumes/{uuid}/snapshots`) against the SVM management LIF
    from a Lambda attached to the FSx VPC, using credentials from Secrets
    Manager. Left unimplemented here intentionally rather than guessing.
    """
    return None


# ---------------------------------------------------------------------------
# Metric collection per volume
# ---------------------------------------------------------------------------

def get_volume_daily_series(file_system_id, svm_id, volume_id, start_date, end_date):
    dims = [
        {"Name": "FileSystemId", "Value": file_system_id},
        {"Name": "StorageVirtualMachineId", "Value": svm_id},
        {"Name": "VolumeId", "Value": volume_id},
    ]
    capacity_series = get_daily_metric(cw, "AWS/FSx", "StorageCapacity", dims, start_date, end_date)
    used_series = get_daily_metric(cw, "AWS/FSx", "StorageUsed", dims, start_date, end_date)
    return capacity_series, used_series


# ---------------------------------------------------------------------------
# Build report data model
# ---------------------------------------------------------------------------

def build_report_data(start_date, end_date):
    file_systems = list_ontap_file_systems()
    data = []

    for fs in file_systems:
        fs_id = fs["FileSystemId"]
        fs_name = get_tag_name(fs.get("Tags"))
        ontap_cfg = fs.get("OntapConfiguration", {})

        fs_entry = {
            "id": fs_id,
            "name": fs_name or "(unnamed)",
            "deployment_type": ontap_cfg.get("DeploymentType", "N/A"),
            "storage_capacity_gib": fs.get("StorageCapacity", 0),
            "throughput_capacity": ontap_cfg.get("ThroughputCapacity", "N/A"),
            "svms": [],
        }

        for svm in list_svms(fs_id):
            svm_id = svm["StorageVirtualMachineId"]
            svm_name = svm.get("Name", "")
            svm_entry = {"id": svm_id, "name": svm_name, "volumes": []}

            for vol in list_volumes(svm_id):
                vol_id = vol["VolumeId"]
                vol_name = vol.get("Name", "")
                vconf = vol.get("OntapConfiguration", {})
                size_bytes_now = vconf.get("SizeInBytes")
                tiering_policy = (vconf.get("TieringPolicy") or {}).get("Name", "NONE")
                snapshot_policy = vconf.get("SnapshotPolicy", "N/A")
                storage_eff = vconf.get("StorageEfficiencyEnabled", False)

                cap_series, used_series = get_volume_daily_series(
                    fs_id, svm_id, vol_id, start_date, end_date
                )

                cw_has_data = any(v is not None for v in used_series.values())

                daily_rows = []
                for d in daterange_days(start_date, end_date):
                    cap = cap_series.get(d)
                    used = used_series.get(d)
                    if cap is None and not cw_has_data:
                        # Fallback: no CloudWatch history at all for this
                        # volume - show current snapshot only on the last
                        # day so the report doesn't silently look empty.
                        cap = size_bytes_now if d == end_date else None
                        used = None
                    free = (cap - used) if (cap is not None and used is not None) else None
                    util_pct = (used / cap * 100.0) if (cap and used is not None) else None
                    snap_size = get_snapshot_size_ontap_api(vol) if d == end_date else None
                    daily_rows.append({
                        "date": d, "capacity": cap, "used": used,
                        "free": free, "util_pct": util_pct, "snapshot": snap_size,
                    })

                # Month-level summary for this volume
                valid_util = [r["util_pct"] for r in daily_rows if r["util_pct"] is not None]
                latest = daily_rows[-1]
                first_valid = next((r for r in daily_rows if r["used"] is not None), None)
                growth_bytes = None
                if first_valid and latest["used"] is not None and first_valid["used"] is not None:
                    growth_bytes = latest["used"] - first_valid["used"]

                svm_entry["volumes"].append({
                    "id": vol_id,
                    "name": vol_name or "(unnamed)",
                    "tiering_policy": tiering_policy,
                    "snapshot_policy": snapshot_policy,
                    "storage_efficiency": storage_eff,
                    "size_now": size_bytes_now,
                    "cw_has_data": cw_has_data,
                    "daily": daily_rows,
                    "avg_util": sum(valid_util) / len(valid_util) if valid_util else None,
                    "max_util": max(valid_util) if valid_util else None,
                    "latest_util": latest["util_pct"],
                    "latest_free": latest["free"],
                    "latest_capacity": latest["capacity"],
                    "growth_bytes": growth_bytes,
                })

            fs_entry["svms"].append(svm_entry)
        data.append(fs_entry)

    return data


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

def render_html(data, start_date, end_date, generated_at):
    all_volumes = []
    for fs in data:
        for svm in fs["svms"]:
            for v in svm["volumes"]:
                all_volumes.append({**v, "fs_id": fs["id"], "fs_name": fs["name"], "svm_name": svm["name"]})

    # Summary ordered by current utilization, highest first
    ranked = sorted(
        [v for v in all_volumes if v["latest_util"] is not None],
        key=lambda v: v["latest_util"], reverse=True
    )

    total_capacity = sum(v["latest_capacity"] or 0 for v in all_volumes)
    total_used = sum((v["latest_capacity"] or 0) - (v["latest_free"] or 0) for v in all_volumes)
    total_free = sum(v["latest_free"] or 0 for v in all_volumes)
    over_bad = [v for v in all_volumes if v["latest_util"] is not None and v["latest_util"] >= BAD_PCT]
    over_warn = [v for v in all_volumes if v["latest_util"] is not None and WARN_PCT <= v["latest_util"] < BAD_PCT]
    no_history = [v for v in all_volumes if not v["cw_has_data"]]

    html = [f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>FSx ONTAP Capacity &amp; Performance Report - {start_date.strftime('%B %Y')}</title>
<style>{BASE_CSS}</style></head><body><div class="wrap">

<div class="header">
  <div>
    <h1>FSx for NetApp ONTAP &mdash; Monthly Capacity &amp; Performance Report</h1>
    <div class="sub">{len(data)} file system(s) &middot; {len(all_volumes)} volume(s) &middot; audit / capacity-planning record</div>
  </div>
  <div class="period">
    Period: {start_date.isoformat()} &rarr; {end_date.isoformat()}<br>
    Generated: {generated_at}<br>
    Region: {REGION}
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <div class="summary-grid">
    <div class="stat-card"><div class="label">Total File Systems</div><div class="value">{len(data)}</div></div>
    <div class="stat-card"><div class="label">Total Volumes</div><div class="value">{len(all_volumes)}</div></div>
    <div class="stat-card"><div class="label">Total Capacity</div><div class="value small">{fmt_bytes(total_capacity)}</div></div>
    <div class="stat-card"><div class="label">Total Used</div><div class="value small">{fmt_bytes(total_used)}</div></div>
    <div class="stat-card"><div class="label">Total Free</div><div class="value small">{fmt_bytes(total_free)}</div></div>
    <div class="stat-card" style="border-left-color:var(--bad)"><div class="label">Volumes &ge; {BAD_PCT:.0f}% Used</div><div class="value" style="color:var(--bad)">{len(over_bad)}</div></div>
    <div class="stat-card" style="border-left-color:var(--warn)"><div class="label">Volumes &ge; {WARN_PCT:.0f}% Used</div><div class="value" style="color:var(--warn)">{len(over_warn)}</div></div>
    <div class="stat-card"><div class="label">No CloudWatch History</div><div class="value small">{len(no_history)}</div></div>
  </div>
  <p class="note">Volumes below are ranked by current utilization (highest first) so the busiest volumes surface immediately for capacity-planning review.</p>
  <div class="table-scroll">
  <table id="summary-table" class="striped">
    <tr><th>Rank</th><th>File System</th><th>SVM</th><th>Volume</th><th>Capacity</th><th>Used</th><th>Free</th><th>Util %</th><th>Month Growth</th><th>Status</th></tr>
"""]
    for i, v in enumerate(ranked, 1):
        cls, tier = util_class(v["latest_util"])
        growth = fmt_bytes(v["growth_bytes"]) if v["growth_bytes"] is not None else "N/A"
        badge = f'<span class="badge {tier}">{tier}</span>'
        html.append(
            f'<tr><td>{i}</td><td class="text">{html_escape(v["fs_name"])} ({v["fs_id"]})</td>'
            f'<td class="text">{html_escape(v["svm_name"])}</td><td class="text">{html_escape(v["name"])} ({v["id"]})</td>'
            f'<td>{fmt_bytes(v["latest_capacity"])}</td><td>{fmt_bytes((v["latest_capacity"] or 0) - (v["latest_free"] or 0))}</td>'
            f'<td>{fmt_bytes(v["latest_free"])}</td><td class="pill-util {cls}">{v["latest_util"]:.1f}%</td>'
            f'<td>{growth}</td><td>{badge}</td></tr>'
        )
    html.append("""</table></div>
  <button class="csv-btn" onclick="tableToCSV('summary-table','fsx_summary.csv')">Download CSV</button>
</div>
""")

    # File system / SVM inventory section
    html.append('<div class="section"><h2>File System &amp; SVM Inventory</h2><div class="table-scroll"><table id="inventory-table" class="striped">')
    html.append("<tr><th>FS ID</th><th>Name</th><th>Deployment</th><th>Capacity (GiB)</th><th>Throughput (MBps)</th><th>SVM ID</th><th>SVM Name</th></tr>")
    for fs in data:
        if not fs["svms"]:
            html.append(f'<tr><td>{fs["id"]}</td><td class="text">{html_escape(fs["name"])}</td><td>{fs["deployment_type"]}</td><td>{fs["storage_capacity_gib"]}</td><td>{fs["throughput_capacity"]}</td><td colspan="2">No SVMs found</td></tr>')
        for svm in fs["svms"]:
            html.append(
                f'<tr><td>{fs["id"]}</td><td class="text">{html_escape(fs["name"])}</td><td>{fs["deployment_type"]}</td>'
                f'<td>{fs["storage_capacity_gib"]}</td><td>{fs["throughput_capacity"]}</td><td>{svm["id"]}</td><td class="text">{html_escape(svm["name"])}</td></tr>'
            )
    html.append('</table></div><button class="csv-btn" onclick="tableToCSV(\'inventory-table\',\'fsx_inventory.csv\')">Download CSV</button></div>')

    # Per-volume daily detail (day 1 -> last day)
    for fs in data:
        for svm in fs["svms"]:
            for v in svm["volumes"]:
                tbl_id = f"daily_{v['id']}"
                html.append(f"""<div class="section">
  <h2>{html_escape(fs['name'])} / {html_escape(svm['name'])} / {html_escape(v['name'])} ({v['id']}) &mdash; Daily Detail</h2>
  <p class="note">Tiering policy: {v['tiering_policy']} &middot; Snapshot policy: {v['snapshot_policy']} &middot; Storage efficiency: {'Enabled' if v['storage_efficiency'] else 'Disabled'}
  {' &middot; <span class="badge warn">CloudWatch history unavailable - showing current snapshot only</span>' if not v['cw_has_data'] else ''}</p>
  <div class="table-scroll"><table id="{tbl_id}" class="striped">
    <tr><th>Date</th><th>Capacity</th><th>Used</th><th>Free</th><th>Util %</th><th>Snapshot Size</th></tr>
""")
                for row in v["daily"]:
                    cls, _ = util_class(row["util_pct"])
                    util_disp = f'<span class="pill-util {cls}">{row["util_pct"]:.1f}%</span>' if row["util_pct"] is not None else "N/A"
                    snap_disp = fmt_bytes(row["snapshot"]) if row["snapshot"] is not None else "N/A - requires ONTAP API"
                    html.append(
                        f'<tr><td>{row["date"].isoformat()}</td><td>{fmt_bytes(row["capacity"])}</td>'
                        f'<td>{fmt_bytes(row["used"])}</td><td>{fmt_bytes(row["free"])}</td><td>{util_disp}</td><td class="text">{snap_disp}</td></tr>'
                    )
                html.append(f'</table></div><button class="csv-btn" onclick="tableToCSV(\'{tbl_id}\',\'fsx_{v["id"]}_daily.csv\')">Download CSV</button></div>')

    html.append(f"""
<div class="footer">
  <span>FSx ONTAP Monthly Report &middot; auto-generated &middot; for audit / capacity-planning use</span>
  <span>Report period {start_date.isoformat()} to {end_date.isoformat()}</span>
</div>
</div>
<script>{CSV_EXPORT_JS}</script>
</body></html>""")

    return "".join(html)


# ---------------------------------------------------------------------------
# Handler
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    start_date, end_date = get_previous_month_range()
    generated_at = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    data = build_report_data(start_date, end_date)
    html_report = render_html(data, start_date, end_date, generated_at)

    key = f"fsx-report/{start_date.strftime('%Y')}/{start_date.strftime('%m')}/fsx-report-{start_date.strftime('%Y-%m')}.html"
    s3_uri = upload_html_to_s3(s3, BUCKET, key, html_report, kms_key_id=KMS_KEY_ID)

    url = generate_presigned_url(BUCKET, key, REGION, SIGNING_SECRET_ID)

    subject = f"FSx ONTAP Monthly Report - {start_date.strftime('%B %Y')}"
    message = (
        f"The FSx for NetApp ONTAP monthly capacity & performance report for "
        f"{start_date.strftime('%B %Y')} is ready.\n\n"
        f"Report link (valid 7 days):\n{url}\n\n"
        f"S3 location: {s3_uri}\n"
    )
    publish_sns(sns, TOPIC_ARN, subject, message)

    return {"statusCode": 200, "body": f"Report uploaded to {s3_uri} and notification sent."}
