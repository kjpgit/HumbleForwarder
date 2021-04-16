"""
Name: HumbleForwarder
Author: kjp

Humble SES email forwarder.  All forwarding goes to a single address, feel free to
fork it if you want more configurability.

Massively reworked and cleaned up version of
https://aws.amazon.com/blogs/messaging-and-targeting/forward-incoming-email-to-an-external-destination/

Setup instructions:

* Follow the AWS blog link above, but use this Lambda code (Python 3.8+) instead.

* Make sure your Lambda has a large enough size and timeout, especially if
  you want to test the error emails due to too large of body.

* Read the configuration options below, then change them in the code or use environment variables

Features:

* Don't forward emails marked as spam / virus.  Note you need to have scanning enabled.

* Don't forward using an attachment

* Send an error email if there was a problem sending (like body too large).
  You can test this by setting the env var TEST_LARGE_BODY, to generate a 20MB body.
  A 768MB Lambda takes 15 seconds for this test.

* JSON logging.  You can run this cloudwatch logs insights query to check on your emails:

     fields @timestamp, input_event.Records.0.ses.mail.commonHeaders.from.0,
        input_event.Records.0.ses.mail.commonHeaders.subject
    | filter input_event.Records.0.eventSource = 'aws:ses'
    | sort @timestamp desc
    | limit 20

Other Thanks:

* Got some inspiration from https://github.com/chrismarcellino/lambda-ses-email-forwarder/

"""

import unittest
import traceback
import json
import os
import logging
import email.policy
import email.parser
import email.message

import boto3
from botocore.exceptions import ClientError

###############################################################################
#
# Required configuration.  Can set here, or in environment var(s), your choice
#
###############################################################################
REGION = os.getenv('Region', 'us-east-1')

INCOMING_EMAIL_BUCKET = os.getenv('MailS3Bucket', 'yourbucketname')

# Don't have a leading or trailing /, it will be added automatically
INCOMING_EMAIL_PREFIX = os.getenv('MailS3Prefix', '')

# If empty, uses what was in the original 'To' header
# This must be a verified address
SENDER = os.getenv('MailSender', '')

RECIPIENT = os.getenv('MailRecipient', 'to@anywhere.com')

###############################################################################
###############################################################################

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    logger.info(json.dumps(dict(input_event=event)))

    # Get the unique ID of the message. This corresponds to the name of the file in S3.
    message_id = event['Records'][0]['ses']['mail']['messageId']
    logger.debug(json.dumps(dict(message_id=message_id)))

    # Check for spam / virus
    if is_ses_spam(event['Records'][0]['ses']['receipt']):
        logger.error(json.dumps(dict(message="rejecting spam message", message_id=message_id)))
        return

    # Retrieve the file from the S3 bucket.
    original_message = get_message_from_s3(message_id)

    # Create the message.
    config = dict(sender=SENDER, recipient=RECIPIENT)
    message = create_new_email(config, original_message['raw_bytes'])

    # Send the email
    try:
        send_raw_email(message)
    except ClientError as e:
        logger.error("error sending forwarded email", exc_info=True)
        traceback_string = traceback.format_exc()
        error_message = create_error_email(message, traceback_string)
        send_raw_email(error_message)


def get_message_from_s3(message_id):
    # NB: This is dumb, but I'm doing it to stay compatible with the original version
    if INCOMING_EMAIL_PREFIX:
        object_path = (INCOMING_EMAIL_PREFIX + "/" + message_id)
    else:
        object_path = message_id

    # Create a new S3 client.
    client_s3 = boto3.client("s3")

    # Get the email object from the S3 bucket.
    object_s3 = client_s3.get_object(Bucket=INCOMING_EMAIL_BUCKET, Key=object_path)
    raw_bytes = object_s3['Body'].read()

    ret = {
        "raw_bytes": raw_bytes,
    }
    return ret


def create_new_email(config, original_raw_bytes):
    parser = email.parser.BytesParser(policy=email.policy.SMTP)
    original_message = parser.parsebytes(original_raw_bytes, headersonly=True)
    new_message = parser.parsebytes(original_raw_bytes, headersonly=False)

    # Clear all headers, we will add only the ones we want
    # We don't need to keep anything else like DKIM, return paths, etc. from the original message.
    for header in new_message.keys():
        del new_message[header]

    # Headers we keep unchanged
    keep_headers = [
            "MIME-Version",
            "Content-Type",
            "Content-Disposition",
            "Content-Transfer-Encoding",
            "Date",
            "Subject",
            ]

    for header in keep_headers:
        if header in original_message:
            new_message[header] = original_message[header]

    # Headers that are different from the original
    new_message["To"] = config["recipient"]

    if config["sender"]:
        new_message["From"] = config["sender"]
    else:
        new_message["From"] = original_message["To"]

    if original_message["Reply-To"]:
        new_message["Reply-To"] = original_message["Reply-To"]
    else:
        new_message["Reply-To"] = original_message["From"]

    # For fault injection (Testing error emails)
    if os.getenv("TEST_LARGE_BODY"):
        logger.info("setting a huge body")
        new_message.clear_content()
        new_message.set_content("x" * 20000000)

    return new_message


def create_error_email(attempted_message, traceback_string):
    # Create a new message
    new_message = email.message.EmailMessage(policy=email.policy.SMTP)
    new_message["From"] = attempted_message["From"]
    new_message["To"] = attempted_message["To"]
    new_message["Subject"] = "Email forwarding error"

    text = f"""
There was an error forwarding an email to SES.

Original Sender: {attempted_message["Reply-To"]}
Original Subject: {attempted_message["Subject"]}

Traceback:

{traceback_string}
        """.strip()

    new_message.set_content(text)
    return new_message


def is_ses_spam(receipt):
    verdicts = ['spamVerdict', 'virusVerdict', 'spfVerdict', 'dkimVerdict', 'dmarcVerdict']
    is_fail = False
    for verdict in verdicts:
        if verdict in receipt:
            status = receipt[verdict].get("status")
            logger.debug(json.dumps(dict(verdict=verdict, status=status)))
            if status == "FAIL":
                is_fail = True
    return is_fail


def send_raw_email(message):
    client_ses = boto3.client('ses', REGION)
    response = client_ses.send_raw_email(
            Source=message['From'],
            Destinations=[message['To']],
            RawMessage={
                'Data': message.as_string()
                }
            )
    print("Email sent! MessageId:", response['MessageId'])



# TODO: Add some actual tests
class UnitTests(unittest.TestCase):
    def test_email_parser(self):
        with open("test.txt", "rb") as f:
            text = f.read()
        config = dict(sender="", recipient="Blah <blah@test.com>")
        new_message = create_new_email(config, text)
        print(new_message.as_string())
        error_message = create_error_email(new_message, "example traceback")
        print(error_message.as_string())
        #self.assertEqual(p.get_header_names(), ['From', 'Date', 'To'])


if __name__ == '__main__':
    unittest.main()
