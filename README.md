# HumbleForwarder

Humble SES email forwarder

## Overview

Takes email received by SES, and sends it to a different destination via SES.
Simple address mapping is supported.  Feel free to fork it if you want more
configurability.

I use it to enable additional vanity email accounts in Gmail (these are called alias accounts in Gmail).
HumbleForwarder forwards received emails to Gmail, and [Gmail sends emails using SES's SMTP server](https://support.google.com/mail/answer/22370?hl=en).  All sent and received emails can be categorized by a `from:my@vanity.dev` filter.

## Setup Instructions

* Follow these [AWS instructions](https://aws.amazon.com/blogs/messaging-and-targeting/forward-incoming-email-to-an-external-destination/), but use this Lambda code (Python 3.8+) instead,
  and don't add the environment variables for settings.

* Copy and edit the example [config.json](config.json) file.
  Go to the Lambda code console and do File->New File->Paste Contents->Save As->"config.json"
  Don't forget to deploy again after saving!

* Make sure your Lambda has a large enough size and timeout, I recommend
  768MB (which actually has a useful CPU) and 60 seconds to be safe.  Python is very slow and bloated.

* Consider granting the Lambda `SNS:Publish` permission, and enable its async Dead Letter Queue
  so you get notified via SNS if any Lambda fails after 3 attempts.

## Features

* Doesn't forward emails marked as spam / virus.  This requires that you enable scanning in the SES console.

* The body/content is not modified, all attachments are kept.  Note that SES has a 10MB sending limit.

* JSON logging.  You can run this Cloudwatch Logs Insights query to check on your emails:

         fields @timestamp, input_event.Records.0.ses.mail.commonHeaders.from.0,
            input_event.Records.0.ses.mail.commonHeaders.subject
         | filter input_event.Records.0.eventSource = 'aws:ses'
         | sort @timestamp desc

## Configuration Reference

### recipient_map

A map of `ses_recipient` -> `envelope_destination`.
If an address containing a label like "code+label@coder.dev" was not found in
the map, it will then try "code@coder.dev".
If no address was found, it will go to `default_destination`.

Note that `envelope_destination` and `default_destination` may be a string or a
list of strings (multiple destinations are supported).

### force_sender

If this string is not empty, it is used as the `From` for all emails.
If this string is empty, `From` will be set to the SES address who received it.
Note that `From` must always be a verified address.

### incoming_email_bucket

The S3 bucket that contains the received email (required). Also set `incoming_email_prefix` if necessary.

## Other Acknowledgements

* I was inspired by these projects: [chrismarcellino](https://github.com/chrismarcellino/lambda-ses-email-forwarder/), [arithmetric](https://github.com/arithmetric/aws-lambda-ses-forwarder/issues/119)
