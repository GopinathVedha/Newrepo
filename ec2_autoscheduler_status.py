import boto3
from botocore.exceptions import ClientError

# ============================================================
# LAMBDA 2 of 2 — "Status" function
# Invoked once, ~3 minutes after Lambda 1 ran, by a one-time
# EventBridge schedule that Lambda 1 created (and that
# self-deletes after firing). Restores any capacity-downgraded
# instances back to their original type, builds the final EC2
# status/health table, and sends the combined report over SNS.
# ============================================================

region = 'ap-southeast-2'

sns_topic_start_arn = 'arn:aws:sns:ap-southeast-2:050557606111:Autoscheduler_start'
sns_topic_stop_arn = 'arn:aws:sns:ap-southeast-2:050557606111:Autoscheduler_stop'
sns_topic_capacity_arn = 'arn:aws:sns:ap-southeast-2:050557606111:Autoscheduler_capacity_fallback'

ORIGINAL_TYPE_TAG = 'equip:infra:original-instance-type'

ec2_resource = boto3.resource('ec2', region_name=region)
ec2_client = boto3.client('ec2', region_name=region)
sns_client = boto3.client('sns', region_name=region)
sts_client = boto3.client('sts')


# ---------- Helpers ----------

def get_instance_name(instance):
    if instance.tags:
        for tag in instance.tags:
            if tag['Key'] == 'Name':
                return tag['Value']
    return 'Unnamed'


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


def get_event_table(events, columns):
    header = " | ".join(columns)
    sep = " | ".join(["-" * len(c) for c in columns])
    lines = [header, sep]
    for row in events:
        lines.append(" | ".join(str(x) for x in row))
    return "\n".join(lines)


def get_instance_status_table():
    account_id = sts_client.get_caller_identity()["Account"]
    lines = [
        "     Account ID     |     Server Name     |     Status      |   Health Check",
        "------------------- | ------------------- | --------------- | ----------------"
    ]
    total = 0
    for instance in ec2_resource.instances.all():
        total += 1
        name = get_instance_name(instance)
        status = instance.state['Name']
        health = "N/A"

        status_response = ec2_client.describe_instance_status(
            InstanceIds=[instance.id], IncludeAllInstances=True
        )
        if status_response['InstanceStatuses']:
            st = status_response['InstanceStatuses'][0]
            system = st['SystemStatus']['Status']
            instance_check = st['InstanceStatus']['Status']
            health = "2/2 Passed" if system == "ok" and instance_check == "ok" else f"{system}/{instance_check}"

        lines.append(f"{account_id:<14} | {name:<15} | {status:<11} | {health}")
    return total, "\n".join(lines)


def restore_original_type(instance_id, instance_names, restore_events, restore_failures):
    instance = ec2_resource.Instance(instance_id)
    name = instance_names.get(instance_id, get_instance_name(instance))
    original_type = get_tag_value(instance, ORIGINAL_TYPE_TAG)

    if not original_type or original_type == instance.instance_type:
        return

    try:
        ec2_client.modify_instance_attribute(InstanceId=instance_id, InstanceType={'Value': original_type})
        restore_events.append((instance_id, name, instance.instance_type, original_type))
        ec2_client.delete_tags(Resources=[instance_id], Tags=[{'Key': ORIGINAL_TYPE_TAG}])
    except ClientError as e:
        print(f"Failed to restore instance type for {instance_id} ({name}): {e}")
        restore_failures.append((instance_id, name, str(e)))


# ---------- Main handler ----------

def lambda_handler(event, context):
    # event is the payload Lambda 1 passed into the EventBridge schedule
    timestamp = event.get("timestamp", "")
    report_header = event.get("report_header", "")
    autostop_instance_ids = event.get("autostop_instance_ids", [])
    instance_names = event.get("instance_names", {})
    notify_start = event.get("notify_start", False)
    notify_stop = event.get("notify_stop", False)

    message_lines = [report_header] if report_header else []

    restore_events = []
    restore_failures = []

    # Restore any capacity-downgraded instances now that they've had time to stop
    for instance_id in autostop_instance_ids:
        try:
            instance = ec2_resource.Instance(instance_id)
            instance.reload()
            if instance.state['Name'] == 'stopped':
                restore_original_type(instance_id, instance_names, restore_events, restore_failures)
            else:
                original_type = get_tag_value(instance, ORIGINAL_TYPE_TAG)
                if original_type:
                    print(f"Instance {instance_id} not yet stopped (state={instance.state['Name']}); "
                          f"will retry restore on a future stop cycle")
        except Exception as e:
            print(f"Error checking/restoring instance {instance_id}: {e}")

    if restore_events:
        message_lines.append(
            "\n♻️ Restored to Original Instance Type:\n"
            + get_event_table(restore_events, ["Instance ID", "Name", "Ran As", "Restored To"])
        )
    if restore_failures:
        message_lines.append(
            "\n❌ Failed to Restore Original Type:\n"
            + get_event_table(restore_failures, ["Instance ID", "Name", "Reason"])
        )

    if restore_events or restore_failures:
        capacity_lines = [f"♻️ EC2 Instance Type Restore Report\n\n📅 Timestamp: {timestamp}\n"]
        if restore_events:
            capacity_lines.append(
                "Instances restored back to their original instance type:\n"
                + get_event_table(restore_events, ["Instance ID", "Name", "Ran As", "Restored To"])
            )
        if restore_failures:
            capacity_lines.append(
                "\nInstances that FAILED to restore to their original type "
                "(will retry on next stop cycle if tag is still present):\n"
                + get_event_table(restore_failures, ["Instance ID", "Name", "Reason"])
            )
        send_sns_notification("\n".join(capacity_lines), sns_topic_capacity_arn)

    # Final status table
    total_instances, status_table = get_instance_status_table()
    message_lines.append("\n==============================\n📊 All EC2 Instance Status\n==============================")
    message_lines.append(f"Total EC2 Instances: {total_instances}\n\n{status_table}")

    full_message = "\n".join(message_lines)
    print(full_message)

    if notify_start:
        send_sns_notification(full_message, sns_topic_start_arn)
    if notify_stop:
        send_sns_notification(full_message, sns_topic_stop_arn)
