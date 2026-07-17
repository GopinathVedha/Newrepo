import boto3
import json
import logging
from botocore.exceptions import ClientError

# ============================================================
# LAMBDA 2 of 2 — "Status" function
# Invoked once, ~3 minutes after Lambda 1 ran, by a one-time
# EventBridge schedule that Lambda 1 created (and that
# self-deletes after firing). Restores any capacity-downgraded
# instances back to their original type, builds the final EC2
# health-check table, and sends its OWN report via SNS.
#
# NOTE: this is now a standalone follow-up report — Lambda 1
# already sent an immediate email for the start/stop actions
# themselves. This function only covers what happens ~3 minutes
# later (restore + health check), so it does not resend Lambda 1's
# action report.
# ============================================================

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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


def send_sns_notification(message, topic_arn, subject='EC2 Scheduler Notification'):
    try:
        response = sns_client.publish(TopicArn=topic_arn, Message=message, Subject=subject)
        logger.info(f"SNS notification sent to {topic_arn} (MessageId: {response.get('MessageId')})")
    except Exception as e:
        logger.error(f"Failed to send SNS notification to {topic_arn}: {e}")


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
        logger.info(f"Restored {instance_id} ({name}) from {instance.instance_type} back to {original_type}")
        restore_events.append((instance_id, name, instance.instance_type, original_type))
        ec2_client.delete_tags(Resources=[instance_id], Tags=[{'Key': ORIGINAL_TYPE_TAG}])
    except ClientError as e:
        logger.error(f"Failed to restore instance type for {instance_id} ({name}): {e}")
        restore_failures.append((instance_id, name, str(e)))


# ---------- Main handler ----------

def lambda_handler(event, context):
    # Log the raw incoming event FIRST, before anything else can fail —
    # this alone proves Lambda 2 was actually invoked, which is the
    # first thing to check in CloudWatch if you're not seeing logs.
    logger.info(f"Lambda 2 (status) invoked. Event: {json.dumps(event)}")

    try:
        timestamp = event.get("timestamp", "")
        autostop_instance_ids = event.get("autostop_instance_ids", [])
        instance_names = event.get("instance_names", {})

        message_lines = [f"♻️ EC2 Autoscheduler — Follow-up Health Check\n\n📅 Timestamp: {timestamp}\n"]

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
                        logger.info(f"Instance {instance_id} not yet stopped (state={instance.state['Name']}); "
                                    f"will retry restore on a future stop cycle")
            except Exception as e:
                logger.error(f"Error checking/restoring instance {instance_id}: {e}")

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
            send_sns_notification("\n".join(capacity_lines), sns_topic_capacity_arn,
                                   subject='EC2 Scheduler - Instance Type Restore Report')

        # Final status table
        total_instances, status_table = get_instance_status_table()
        message_lines.append("\n==============================\n📊 All EC2 Instance Status\n==============================")
        message_lines.append(f"Total EC2 Instances: {total_instances}\n\n{status_table}")

        full_message = "\n".join(message_lines)
        logger.info(full_message)

        # This health-check report always goes out — it's not gated on
        # whether the earlier action was a start or a stop, since by this
        # point we're just reporting the resulting state of the fleet.
        send_sns_notification(full_message, sns_topic_start_arn,
                               subject='EC2 Scheduler - Follow-up Health Check')

    except Exception as e:
        # Last-resort safety net: if anything above throws, make sure at
        # least ONE signal reaches SNS instead of failing completely silent.
        logger.exception(f"Unhandled error in Lambda 2 status-check handler: {e}")
        send_sns_notification(
            f"❌ EC2 Autoscheduler Lambda 2 (status/restore) hit an unhandled error and "
            f"did not complete its health-check/restore report.\n\nError: {e}\n\n"
            f"Check CloudWatch Logs for this function for the full traceback.",
            sns_topic_capacity_arn,
            subject='EC2 Scheduler - Status Lambda FAILED'
        )
        raise
