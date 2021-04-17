"""
Name: HumbleForwarder
Author: kjp

Humble SES email forwarder.  Simple address mapping is supported.  Feel free to
fork it if you want more configurability.

Massively reworked and cleaned up version of
https://aws.amazon.com/blogs/messaging-and-targeting/forward-incoming-email-to-an-external-destination/

Setup instructions:

* Follow the AWS blog link above, but use this Lambda code (Python 3.8+) instead,
  and don't use the environment variables for settings.

* See the example "config.json" file in this directory and edit it.
  Go to the Lambda code console and do File->New->Paste Contents->Save As->"config.json"
  Don't forget to deploy again after uploading it!

* Make sure your Lambda has a large enough size and timeout, I recommend
  768MB and 60 seconds to be safe.  Python is pretty slow and bloated.

* Consider granting the Lambda `SNS:Publish` permission, and enable its Dead Letter Queue
  so you get notified via SNS if any Lambda fails after 3 async attempts.

Features:

* Don't forward emails marked as spam / virus.  Note you need to have scanning enabled.

* The body/content is not modified, all attachments are kept

* Send an error email if there was a problem sending (like body too large).
  You can test this by setting the env var TEST_LARGE_BODY, to generate a 20MB body.
  A 768MB Lambda takes 15 seconds for this test.

* JSON logging.  You can run this cloudwatch logs insights query to check on your emails:

     fields @timestamp, input_event.Records.0.ses.mail.commonHeaders.from.0,
        input_event.Records.0.ses.mail.commonHeaders.subject
    | filter input_event.Records.0.eventSource = 'aws:ses'
    | sort @timestamp desc

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


# Configuration file.  See the example config.json in this directory.
CONFIG_FILE = os.path.join(os.environ.get('LAMBDA_TASK_ROOT', ''), "config.json")

X_ENVELOPE_TO = "X-Envelope-To"

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

g_config = None


def lambda_handler(event, context):
    logger.info(json.dumps(dict(input_event=event)))

    # Only load the runtime settings file once
    global g_config
    if g_config is None:
        g_config = get_runtime_config_dict()

    # Get the unique ID of the message. This corresponds to the name of the file in S3.
    message_id = event['Records'][0]['ses']['mail']['messageId']
    logger.debug(json.dumps(dict(message_id=message_id)))

    # Check for spam / virus
    if is_ses_spam(event):
        logger.error(json.dumps(dict(message="rejecting spam message", message_id=message_id)))
        return

    # These are the valid recipient(s) for your domain.
    # Any other bogus addresses in the To: header should not be present here.
    # Note that SES can show +labels here, e.g. "code+blah@mydomain.dev".
    ses_recipients = get_ses_recipients(event)

    # This loop is inefficient, but optimizing an email to multiple users is
    # not something that's a priority for me.
    for ses_recipient in ses_recipients:
        forward_mail(ses_recipient, message_id)


def forward_mail(ses_recipient, message_id):
    # Retrieve the original message from the S3 bucket.
    message = get_message_from_s3(message_id)

    new_headers = get_new_message_headers(g_config, ses_recipient, message)
    logger.info(json.dumps(dict(new_headers=new_headers), default=str))

    # Change all the headers now.  Boom, that was easy!
    set_new_message_headers(message, new_headers)

    if os.getenv("TEST_DEBUG_BODY"):
        logger.info(json.dumps(dict(email_body=message.as_string())))

    if os.getenv("TEST_LARGE_BODY"):
        logger.info("setting a huge body, should cause an error")
        message.clear_content()
        message.set_content("x" * 20000000)

    # Send the message
    try:
        send_raw_email(message, envelope_destination=new_headers[X_ENVELOPE_TO])
    except ClientError as e:
        logger.error("error sending forwarded email", exc_info=True)
        traceback_string = traceback.format_exc()
        error_message = create_error_email(message, traceback_string)
        send_raw_email(error_message, envelope_destination=error_message["To"])


def get_message_from_s3(message_id):
    bucket = g_config["incoming_email_bucket"]
    prefix = g_config["incoming_email_prefix"]
    if prefix:
        # Normalize S3 paths to be user friendly.
        prefix = prefix.strip("/") + "/"

    object_path = prefix + message_id

    # Get the email object from the S3 bucket.
    client_s3 = boto3.client("s3")
    object_s3 = client_s3.get_object(Bucket=bucket, Key=object_path)
    raw_bytes = object_s3['Body'].read()
    return parse_message_from_bytes(raw_bytes)


def parse_message_from_bytes(raw_bytes):
    parser = email.parser.BytesParser(policy=email.policy.SMTP)
    return parser.parsebytes(raw_bytes)


def get_new_message_headers(config, ses_recipient, message):
    """
    Return the complete set of new headers.  This single function is where all the
    forwarding logic / magic happens.

    NB: This function shouldn't use any global vars, because we want it unit testable.
    Unit tests can pass in their own `config` dict.
    """
    new_headers = {}

    # Headers we keep unchanged
    headers_to_keep = [
            "Date",
            "Subject",
            "To",
            "CC",
            "MIME-Version",
            "Content-Type",
            "Content-Disposition",
            "Content-Transfer-Encoding",
            ]

    for header in headers_to_keep:
        if header in message:
            new_headers[header] = message[header]

    # The envelope destination.  Lookup in recipient_map, if not found, fall
    # back to default_destination
    new_headers[X_ENVELOPE_TO] = config["recipient_map"].get(ses_recipient,
            config["default_destination"])

    # Optional: Append envelope destination to To: header.
    # This is useful if the desination is adding a +label, and we want
    # to use gmail's built in filtering / categorization.
    if config.get("update_to_header_with_destination", False):
        new_headers["To"] = message.get("To", "")  # Don't assume To exists
        if new_headers["To"]:
            new_headers["To"] += ", "
        new_headers["To"] += new_headers[X_ENVELOPE_TO]

    # From must be a verified address
    if config["force_sender"]:
        new_headers["From"] = config["force_sender"]
    else:
        new_headers["From"] = ses_recipient

    if message["Reply-To"]:
        new_headers["Reply-To"] = message["Reply-To"]
    else:
        new_headers["Reply-To"] = message["From"]

    return new_headers


def set_new_message_headers(message, new_headers):
    # Clear all headers
    for header in message.keys():
        del message[header]
    for (name, value) in new_headers.items():
        if name == X_ENVELOPE_TO:
            # This is only used internally
            pass
        else:
            message[name] = value


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


def get_runtime_config_dict():
    # A config file is now required
    with open(CONFIG_FILE, "rb") as f:
        config = json.load(f)
    return config


def get_ses_recipients(event):
    receipt = event['Records'][0]['ses']['receipt']
    return receipt["recipients"]


def is_ses_spam(event):
    receipt = event['Records'][0]['ses']['receipt']
    verdicts = ['spamVerdict', 'virusVerdict', 'spfVerdict', 'dkimVerdict', 'dmarcVerdict']
    is_fail = False
    for verdict in verdicts:
        if verdict in receipt:
            status = receipt[verdict].get("status")
            logger.debug(json.dumps(dict(verdict=verdict, status=status)))
            if status == "FAIL":
                is_fail = True
    return is_fail


def send_raw_email(message, *, envelope_destination):
    client_ses = boto3.client('ses', g_config["region"])
    response = client_ses.send_raw_email(
            Source=message['From'],
            Destinations=[envelope_destination],
            RawMessage={
                'Data': message.as_string()
                }
            )
    print("Email sent! MessageId:", response['MessageId'])




class UnitTests(unittest.TestCase):
    def test_multiple_recipients(self):
        text = self._read_test_file("tests/multiple_recipients.txt")
        message = parse_message_from_bytes(text)
        self.assertEqual(len(message["To"].addresses), 3)

    def test_header_changes(self):
        text = self._read_test_file("tests/multiple_recipients.txt")
        message = parse_message_from_bytes(text)
        ses_recipient = "code@coder.dev"
        config = self.get_test_config()
        new_headers = get_new_message_headers(config, ses_recipient, message)
        self.assertEqual(new_headers[X_ENVELOPE_TO], "default@secret.com")
        self.assertEqual(new_headers["From"], "code@coder.dev")
        self.assertEqual(new_headers["To"], "hacker@hacker.com, code@coder.dev, code2@coder.dev")
        self.assertEqual(new_headers["Subject"], "test 3 addresses")
        self.assertEqual(new_headers["Reply-To"], "Alpha Sigma <user@users.com>")
        self.assertEqual("Content-Disposition" in new_headers, False)

        set_new_message_headers(message, new_headers)
        # We don't actually expose X_ENVELOPE_TO, it's just used internally to pass data
        self.assertEqual(message[X_ENVELOPE_TO], None)
        self.assertEqual(message["From"], "code@coder.dev")
        self.assertEqual(message["To"], "hacker@hacker.com, code@coder.dev, code2@coder.dev")
        self.assertEqual(message["Subject"], "test 3 addresses")
        self.assertEqual(message["Reply-To"], "Alpha Sigma <user@users.com>")

    def test_header_reply_to(self):
        text = self._read_test_file("tests/reply_to.txt")
        message = parse_message_from_bytes(text)
        ses_recipient = "code@coder.dev"
        config = self.get_test_config()
        new_headers = get_new_message_headers(config, ses_recipient, message)
        self.assertEqual(new_headers[X_ENVELOPE_TO], "default@secret.com")
        self.assertEqual(new_headers["From"], "code@coder.dev")
        self.assertEqual(new_headers["Subject"], "test reply-to")
        self.assertEqual(new_headers["Reply-To"], "My Alias <alias@alias.com>")

    def test_header_force_sender(self):
        text = self._read_test_file("tests/multiple_recipients.txt")
        message = parse_message_from_bytes(text)
        ses_recipient = "code@coder.dev"
        config = self.get_test_config(force_sender="fixed@coder.dev")
        new_headers = get_new_message_headers(config, ses_recipient, message)
        self.assertEqual(new_headers["From"], "fixed@coder.dev")

    def test_header_update_to(self):
        text = self._read_test_file("tests/multiple_recipients.txt")
        message = parse_message_from_bytes(text)
        ses_recipient = "code@coder.dev"
        config = self.get_test_config(default_destination="some+label@mydomain.dev")
        config.update(update_to_header_with_destination=True)
        new_headers = get_new_message_headers(config, ses_recipient, message)
        self.assertEqual(new_headers["To"], "hacker@hacker.com, code@coder.dev, code2@coder.dev, some+label@mydomain.dev")

    def test_dynamic_mapping(self):
        text = self._read_test_file("tests/multiple_recipients.txt")
        message = parse_message_from_bytes(text)
        recipient_map = {
                "hacker@hacker.com": "nowhere+label@nowhere.com",
                "code@coder.dev": "A Name <foo+bar@domain.com>",
                }
        config = self.get_test_config(recipient_map=recipient_map)
        new_headers = get_new_message_headers(config, "hacker@hacker.com", message)
        self.assertEqual(new_headers[X_ENVELOPE_TO], "nowhere+label@nowhere.com")
        new_headers = get_new_message_headers(config, "code@coder.dev", message)
        self.assertEqual(new_headers[X_ENVELOPE_TO], "A Name <foo+bar@domain.com>")
        new_headers = get_new_message_headers(config, "code123@coder.dev", message)
        self.assertEqual(new_headers[X_ENVELOPE_TO], "default@secret.com")

    def test_event_parsing(self):
        text = self._read_test_file("tests/event.json")
        event = json.loads(text)
        self.assertEqual(is_ses_spam(event), True)
        self.assertEqual(get_ses_recipients(event), ['code@coder.dev', 'code2@coder.dev'])

    def _read_test_file(self, file_name):
        with open(file_name, "rb") as f:
            return f.read()

    def get_test_config(self, force_sender="", default_destination="default@secret.com", recipient_map=None):
        config = {}
        config.update(force_sender=force_sender)
        config.update(default_destination=default_destination)
        if recipient_map is None:
            recipient_map = {}
        config.update(recipient_map=recipient_map)
        return config


if __name__ == '__main__':
    unittest.main()
