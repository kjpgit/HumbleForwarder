"""
Name: HumbleForwarder
Author: kjp

Humble SES email forwarder.  Simple address mapping is supported.  Feel free to
fork it if you want more configurability.

See README.md for full documentation
"""
import email.message
import email.parser
import email.policy
import json
import logging
import os
import unittest

import boto3


# This config file must be part of the Lambda package
CONFIG_FILE = "config.json"

# Internal use only, not an actual sent header
X_ENVELOPE_DESTINATIONS = "X-Envelope-Destinations"

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

    # Send the message
    # Note: I used to catch ClientError and send a special email on failure,
    # but I removed that code.  Using Lambda async DLQ+SNS catches all failures and
    # is significantly less complex (and more humble!).
    envelope_destinations = new_headers[X_ENVELOPE_DESTINATIONS]
    send_raw_email(message, envelope_destinations=envelope_destinations)


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

    # Headers to keep.  Other unknown headers are removed.
    headers_to_keep = [
            "Date",
            "Subject",
            "To",
            "CC",
            "MIME-Version",
            "References",   # For threading
            "In-Reply-To",   # For threading
            "Content-Type",
            "Content-Disposition",
            "Content-Transfer-Encoding",
            ]

    for header in headers_to_keep:
        if header in message:
            new_headers[header] = message[header]

    # Find the destination(s) to which we forward
    destinations = config["recipient_map"].get(ses_recipient)
    if destinations is None:
        # Lookup again without the +label
        destinations = config["recipient_map"].get(strip_ses_recipient_label(ses_recipient))
    if destinations is None:
        destinations = config["default_destination"]
    new_headers[X_ENVELOPE_DESTINATIONS] = string_to_list(destinations)

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


def string_to_list(s):
    if isinstance(s, str):
        return [s]
    return s


def set_new_message_headers(message, new_headers):
    # Clear all headers
    for header in message.keys():
        del message[header]
    for (name, value) in new_headers.items():
        if name == X_ENVELOPE_DESTINATIONS:
            # This is only used internally
            pass
        else:
            message[name] = value


def get_runtime_config_dict():
    # A config file is now required
    full_path = os.path.join(os.environ['LAMBDA_TASK_ROOT'], CONFIG_FILE)
    with open(full_path, "rb") as f:
        config = json.load(f)
        assert isinstance(config, dict)
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


def send_raw_email(message, *, envelope_destinations):
    client_ses = boto3.client('ses', g_config["region"])
    response = client_ses.send_raw_email(
            Source=message['From'],
            Destinations=envelope_destinations,
            RawMessage=dict(Data=message.as_string()),
            )
    print("Email sent! MessageId:", response['MessageId'])


def strip_ses_recipient_label(address):
    """
    Ensure `address` does not contain any +label.
    Address is a simple recipient address given by SES, it does not contain a display name.

    For example, 'coder+label@vanity.dev' -> 'coder@vanity.dev'.
    """
    name, domain = address.split("@")
    if '+' in name:
        name = name.split("+")[0]
    return name + "@" + domain



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
        self.assertEqual(new_headers[X_ENVELOPE_DESTINATIONS], ["default@secret.com"])
        self.assertEqual(new_headers["From"], "code@coder.dev")
        self.assertEqual(new_headers["To"], "hacker@hacker.com, code@coder.dev, code2@coder.dev")
        self.assertEqual(new_headers["Subject"], "test 3 addresses")
        self.assertEqual(new_headers["Reply-To"], "Alpha Sigma <user@users.com>")
        self.assertEqual("Content-Disposition" in new_headers, False)

        set_new_message_headers(message, new_headers)
        # We don't actually expose X_ENVELOPE_DESTINATIONS, it's just used internally to pass data
        self.assertEqual(message[X_ENVELOPE_DESTINATIONS], None)
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
        self.assertEqual(new_headers[X_ENVELOPE_DESTINATIONS], ["default@secret.com"])
        self.assertEqual(new_headers["From"], "code@coder.dev")
        self.assertEqual(new_headers["Subject"], "test reply-to")
        self.assertEqual(new_headers["Reply-To"], "My Alias <alias@alias.com>")

    def test_header_multiple_destinations(self):
        text = self._read_test_file("tests/reply_to.txt")
        message = parse_message_from_bytes(text)
        ses_recipient = "code@coder.dev"
        config = self.get_test_config(default_destination=["a@a.com", "b@b.com"])
        new_headers = get_new_message_headers(config, ses_recipient, message)
        self.assertEqual(new_headers[X_ENVELOPE_DESTINATIONS], ['a@a.com', 'b@b.com'])
        self.assertEqual(new_headers["To"], 'hacker@hacker.com, code@coder.dev, code2@coder.dev')

    def test_header_force_sender(self):
        text = self._read_test_file("tests/multiple_recipients.txt")
        message = parse_message_from_bytes(text)
        ses_recipient = "code@coder.dev"
        config = self.get_test_config(force_sender="fixed@coder.dev")
        new_headers = get_new_message_headers(config, ses_recipient, message)
        self.assertEqual(new_headers["From"], "fixed@coder.dev")

    def test_dynamic_mapping(self):
        text = self._read_test_file("tests/multiple_recipients.txt")
        message = parse_message_from_bytes(text)
        recipient_map = {
                "hacker@hacker.com": "nowhere+label@nowhere.com",
                "code@coder.dev": "A Name <foo+bar@domain.com>",
                }
        config = self.get_test_config(recipient_map=recipient_map)
        new_headers = get_new_message_headers(config, "hacker@hacker.com", message)
        self.assertEqual(new_headers[X_ENVELOPE_DESTINATIONS], ["nowhere+label@nowhere.com"])
        new_headers = get_new_message_headers(config, "code@coder.dev", message)
        self.assertEqual(new_headers[X_ENVELOPE_DESTINATIONS], ["A Name <foo+bar@domain.com>"])
        new_headers = get_new_message_headers(config, "code123@coder.dev", message)
        self.assertEqual(new_headers[X_ENVELOPE_DESTINATIONS], ["default@secret.com"])

    def test_event_parsing(self):
        text = self._read_test_file("tests/event.json")
        event = json.loads(text)
        self.assertEqual(is_ses_spam(event), True)
        self.assertEqual(get_ses_recipients(event), ['code@coder.dev', 'code2@coder.dev'])

    def test_plus_labels(self):
        text = self._read_test_file("tests/multiple_recipients.txt")
        message = parse_message_from_bytes(text)
        recipient_map = {
                "code@coder.dev": "base@gmail.com",
                "code+label@coder.dev": "specific@gmail.com",
                }
        config = self.get_test_config(recipient_map=recipient_map)
        new_headers = get_new_message_headers(config, "code+unknown@coder.dev", message)
        self.assertEqual(new_headers[X_ENVELOPE_DESTINATIONS], ["base@gmail.com"])
        new_headers = get_new_message_headers(config, "code+label@coder.dev", message)
        self.assertEqual(new_headers[X_ENVELOPE_DESTINATIONS], ["specific@gmail.com"])

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
