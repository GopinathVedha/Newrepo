import boto3
import json
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from botocore.exceptions import ClientError

# ============================================================
# LAMBDA 1 of 2 — "Action" function
# Triggered on your existing schedule (EventBridge rule, cron, etc).
# Evaluates instances, starts/stops them (with capacity fallback),
# then schedules Lambda 2 ("Status") to run ~3 minutes later via
# EventBridge Scheduler and exits immediately. No time.sleep(), so
# no idle billed compute.
# ============================================================

# AWS region
region = 'ap-southeast-2'

# SNS Topics
sns_topic_start_arn = 'arn:aws:sns:ap-southeast-2:050557606111:Autoscheduler_start'
sns_topic_stop_arn = 'arn:aws:sns:ap-southeast-2:050557606111:Autoscheduler_stop'
sns_topic_capacity_arn = 'arn:aws:sns:ap-southeast-2:050557606111:Autoscheduler_capacity_fallback'

# ARN of Lambda 2 ("status/health-check" function) that this function schedules
STATUS_LAMBDA_ARN = 'arn:aws:lambda:ap-southeast-2:050557606111:function:ec2_autoscheduler_status'

# IAM role that EventBridge Scheduler assumes to invoke Lambda 2
SCHEDULER_EXECUTION_ROLE_ARN = 'arn:aws:iam::050557606111:role/EC2Autoscheduler-SchedulerInvokeRole'

# How long to wait before checking instance health / sending final report
STATUS_CHECK_DELAY_SECONDS = 180

# Tag used to remember the instance's original (pre-downgrade) instance type
ORIGINAL_TYPE_TAG = 'equip:infra:original-instance-type'

# Instance size ordering (smallest -> largest) used to compute downgrade steps
SIZE_ORDER = [
    'nano', 'micro', 'small', 'medium', 'large',
    'xlarge', '2xlarge', '4xlarge', '8xlarge', '9xlarge',
    '12xlarge', '16xlarge', '18xlarge', '24xlarge', '32xlarge', '48xlarge'
]

# AWS clients
ec2_resource = boto3.resource('ec2', region_name=region)
ec2_client = boto3.client('ec2', region_name=region)
sns_client = boto3.client('sns', region_name=region)
sts_client = boto3.client('sts')
scheduler_client = boto3.client('scheduler', region_name=region)

# Instance tracking (reset each invocation)
instance_names = {}
autostart_instance_ids = []
autostop_instance_ids = []
db_instances = []
app_instances = []

# Capacity-fallback tracking (reset each invocation)
downgrade_events = []   # (instance_id, name, original_type, downgraded_type)
start_failures = []     # (instance_id, name, reason)


# ---------- Helpers ----------

def get_instance_name(instance):
    if instance.tags:
        for tag in instance.tags:
            if tag['Key'] == 'Name':
                return tag['Value']
    return 'Unnamed'


def get_instance_role(instance):
    if instance.tags:
        for tag in instance.tags:
            if tag['Key'] == 'equip:infra:role':
                return tag['Value'].lower()
    return 'unknown'


def get_tag_value(instance, key):
    if instance.tags:
        for tag in instance.tags:
            if tag['Key'] == key:
                return tag['Value']
    return None


def send_sns_notification(message, topic_arn):
    try:
        sns_client.publish(TopicArn=topic_arn, Message=message, Subject='EC2 Scheduler Notification')
    except Exception as e:
        print(f"Failed to send SNS notification: {e}")


def get_action_status_table(instance_ids, action_type):
    account_id = sts_client.get_caller_identity()["Account"]
    lines = ["Account ID     | Server Name     | Action", "-------------- | --------------- | -------"]
    for iid in instance_ids:
        name = instance_names.get(iid, 'Unnamed')
        lines.append(f"{account_id:<14} | {name:<15} | {action_type}")
    return "\n".join(lines)


def get_event_table(events, columns):
    header = " | ".join(columns)
    sep = " | ".join(["-" * len(c) for c in columns])
    lines = [header, sep]
    for row in events:
        lines.append(" | ".join(str(x) for x in row))
    return "\n".join(lines)


def get_downgrade_candidates(instance_type):
    try:
        family, size = instance_type.split('.', 1)
    except ValueError:
        return []
    if size not in SIZE_ORDER:
        return []
    idx = SIZE_ORDER.index(size)
    if idx == 0:
        return []
    smaller_sizes = list(reversed(SIZE_ORDER[:idx]))
    return [f"{family}.{s}" for s in smaller_sizes]


def is_capacity_error(client_error):
    code = client_error.response.get('Error', {}).get('Code', '')
    return code in ('InsufficientInstanceCapacity', 'InsufficientHostCapacity', 'InsufficientCapacityOnHost')


def start_instance_with_capacity_fallback(instance_id):
    instance = ec2_resource.Instance(instance_id)
    name = instance_names.get(instance_id, get_instance_name(instance))

    original_type = get_tag_value(instance, ORIGINAL_TYPE_TAG)
    if not original_type:
        original_type = instance.instance_type

    candidates = get_downgrade_candidates(original_type)
    attempt_types = [original_type] + candidates

    for attempt_type in attempt_types:
        try:
            if attempt_type != instance.instance_type:
                ec2_client.modify_instance_attribute(
                    InstanceId=instance_id, InstanceType={'Value': attempt_type}
                )
            ec2_client.start_instances(InstanceIds=[instance_id])

            if attempt_type != original_type:
                ec2_client.create_tags(
                    Resources=[instance_id],
                    Tags=[{'Key': ORIGINAL_TYPE_TAG, 'Value': original_type}]
                )
                downgrade_events.append((instance_id, name, original_type, attempt_type))
            return True

        except ClientError as e:
            if is_capacity_error(e):
                print(f"Capacity issue starting {instance_id} ({name}) as {attempt_type}, trying next smaller type")
                continue
            print(f"Error starting instance {instance_id} ({name}): {e}")
            start_failures.append((instance_id, name, str(e)))
            return False

    start_failures.append((instance_id, name, "No capacity available for original type or any smaller type in the family"))
    return False


def schedule_status_check(payload, delay_seconds=STATUS_CHECK_DELAY_SECONDS):
    """Create a one-time EventBridge schedule that invokes Lambda 2 after
    delay_seconds, then deletes itself. This replaces time.sleep()."""
    run_at = (datetime.utcnow() + timedelta(seconds=delay_seconds)).strftime('%Y-%m-%dT%H:%M:%S')
    schedule_name = f"ec2-autoscheduler-status-{uuid.uuid4().hex[:10]}"

    scheduler_client.create_schedule(
        Name=schedule_name,
        ScheduleExpression=f"at({run_at})",
        FlexibleTimeWindow={'Mode': 'OFF'},
        Target={
            'Arn': STATUS_LAMBDA_ARN,
            'RoleArn': SCHEDULER_EXECUTION_ROLE_ARN,
            'Input': json.dumps(payload)
        },
        ActionAfterCompletion='DELETE'  # auto-cleanup after it fires, no leftover schedules
    )
    print(f"Scheduled status-check Lambda as '{schedule_name}' for {run_at} UTC")


# ---------- Main handler ----------

def lambda_handler(event, context):
    trigger_type = event.get("trigger", "all")  # "db", "app", or "all"

    downgrade_events.clear()
    start_failures.clear()

    sydney_now = datetime.now(ZoneInfo("Australia/Sydney"))
    ct_sec = sydney_now.hour * 3600 + sydney_now.minute * 60
    timestamp = sydney_now.strftime("%Y-%m-%d %H:%M %Z")

    message_lines = [f"🚀 EC2 Autoscheduler Report\n\n📅 Timestamp: {timestamp}\n"]

    # Evaluate instances
    for instance in ec2_resource.instances.all():
        instance_id = instance.id
        instance_name = get_instance_name(instance)
        instance_names[instance_id] = instance_name

        scheduler_flag = autostart_flag = autostop_flag = ''
        if instance.tags:
            for tag in instance.tags:
                key, value = tag['Key'], tag['Value']
                if key == 'equip:infra:autoscheduler':
                    scheduler_flag = value.lower()
                elif key == 'equip:infratest:autostarttime':
                    autostart_flag = value
                elif key == 'equip:infratest:autostoptime':
                    autostop_flag = value

        if scheduler_flag == 'enabled':
            try:
                if autostart_flag and ':' in autostart_flag:
                    hh, mm = map(int, autostart_flag.split(':'))
                    sta_sec = hh * 3600 + mm * 60
                    if 0 <= (ct_sec - sta_sec) < 300 and instance.state['Name'] == 'stopped':
                        role = get_instance_role(instance)
                        if trigger_type == 'db' and role == 'db':
                            db_instances.append(instance_id)
                        elif trigger_type == 'app' and role == 'app':
                            app_instances.append(instance_id)
                        elif trigger_type == 'all':
                            if role == 'db':
                                db_instances.append(instance_id)
                            elif role == 'app':
                                app_instances.append(instance_id)
                        autostart_instance_ids.append(instance_id)

                if autostop_flag and ':' in autostop_flag:
                    hh, mm = map(int, autostop_flag.split(':'))
                    sto_sec = hh * 3600 + mm * 60
                    if 0 <= (ct_sec - sto_sec) < 300 and instance.state['Name'] == 'running':
                        autostop_instance_ids.append(instance_id)
            except Exception as e:
                print(f"Error parsing time for instance {instance_id}: {e}")

    notify_start = False
    notify_stop = False

    # Start actions (per-instance, with capacity fallback)
    if autostart_instance_ids:
        notify_start = True
        started_ids = []
        for instance_id in autostart_instance_ids:
            if start_instance_with_capacity_fallback(instance_id):
                started_ids.append(instance_id)

        message_lines.append("\n==============================\n🔄 Instance Start Actions\n==============================")
        started_db = [i for i in db_instances if i in started_ids]
        started_app = [i for i in app_instances if i in started_ids]
        if started_db:
            message_lines.append("\nStarted Database Servers:\n" + get_action_status_table(started_db, "Started"))
        if started_app:
            message_lines.append("\nStarted Application Servers:\n" + get_action_status_table(started_app, "Started"))

        if downgrade_events:
            message_lines.append(
                "\n⚠️ Capacity Downgrades (will auto-restore to original type on next stop):\n"
                + get_event_table(downgrade_events, ["Instance ID", "Name", "Original Type", "Started As"])
            )
        if start_failures:
            message_lines.append(
                "\n❌ Failed to Start (no capacity at any size in family):\n"
                + get_event_table(start_failures, ["Instance ID", "Name", "Reason"])
            )

        if downgrade_events or start_failures:
            capacity_lines = [f"⚠️ EC2 Capacity Fallback Report\n\n📅 Timestamp: {timestamp}\n"]
            if downgrade_events:
                capacity_lines.append(
                    "Instances downgraded due to capacity shortage:\n"
                    + get_event_table(downgrade_events, ["Instance ID", "Name", "Original Type", "Started As"])
                )
            if start_failures:
                capacity_lines.append(
                    "\nInstances that FAILED to start:\n"
                    + get_event_table(start_failures, ["Instance ID", "Name", "Reason"])
                )
            send_sns_notification("\n".join(capacity_lines), sns_topic_capacity_arn)

    # Stop actions
    if autostop_instance_ids:
        notify_stop = True
        try:
            ec2_client.stop_instances(InstanceIds=autostop_instance_ids)
            message_lines.append("\n==============================\n🔻 Instance Stop Actions\n==============================")
            message_lines.append("\nStopped Instances:\n" + get_action_status_table(autostop_instance_ids, "Stopped"))
        except Exception as e:
            print(f"Error stopping instances: {e}")

    # Nothing to check later? Don't bother scheduling Lambda 2.
    if not autostart_instance_ids and not autostop_instance_ids:
        print("No start/stop actions this cycle; skipping status-check scheduling.")
        return

    # Hand off to Lambda 2 for the delayed health check + final report,
    # instead of sleeping in this function.
    payload = {
        "trigger": trigger_type,
        "timestamp": timestamp,
        "report_header": "\n".join(message_lines),
        "autostop_instance_ids": autostop_instance_ids,
        "instance_names": instance_names,
        "notify_start": notify_start,
        "notify_stop": notify_stop,
    }
    schedule_status_check(payload)

    # Clear lists for this invocation (execution environment may be reused)
    autostart_instance_ids.clear()
    autostop_instance_ids.clear()
    db_instances.clear()
    app_instances.clear()
