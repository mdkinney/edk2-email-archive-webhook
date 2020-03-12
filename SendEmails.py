## @file
# Use smptlib or SendGrid to send email messages
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

'''
SendMails
'''
from __future__ import print_function

import os
import smtplib
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Mail, From, To, Cc, Bcc, Subject, Substitution, Header,
    CustomArg, SendAt, Content, MimeType, Attachment, FileName,
    FileContent, FileType, Disposition, ContentId, TemplateId,
    Section, ReplyTo, Category, BatchId, Asm, GroupId, GroupsToDisplay,
    IpPoolName, MailSettings, BccSettings, BccSettingsEmail,
    BypassListManagement, FooterSettings, FooterText,
    FooterHtml, SandBoxMode, SpamCheck, SpamThreshold, SpamUrl,
    TrackingSettings, ClickTracking, SubscriptionTracking,
    SubscriptionText, SubscriptionHtml, SubscriptionSubstitutionTag,
    OpenTracking, OpenTrackingSubstitutionTag, Ganalytics,
    UtmSource, UtmMedium, UtmTerm, UtmContent, UtmCampaign)

SMTP_ADDRESS           = os.environ['SMTP_ADDRESS']
SMTP_PORT_NUMBER       = int(os.environ['SMTP_PORT_NUMBER'])
SMTP_USER_NAME         = os.environ['SMTP_USER_NAME']
SMTP_PASSWORD          = os.environ['SMTP_PASSWORD']
GROUPS_IO_ADDRESS      = os.environ['GROUPS_IO_ADDRESS']
SENDGRID_API_KEY       = os.environ['SENDGRID_API_KEY']

def SendEmails (EmailContents, SendMethod):
    if SendMethod == 'SMTP':
        #
        # Send emails to SMTP Server
        #
        try:
            SmtpServer = smtplib.SMTP(SMTP_ADDRESS, SMTP_PORT_NUMBER)
            SmtpServer.starttls()
            SmtpServer.ehlo()
            SmtpServer.login(SMTP_USER_NAME, SMTP_PASSWORD)
            for Email in EmailContents:
                print (Email)
                SmtpServer.sendmail('webhook@tianocore.org', GROUPS_IO_ADDRESS, Email)
            SmtpServer.quit()
        except:
            print ('SendEmails: error: can not connect or login or send messages.')
    if SendMethod == 'SendGrid':
        #
        # Send emails to SendGrid
        #
        for Email in EmailContents:
            Email = Email.splitlines (keepends=True)
            for LineNumber in range (0, len(Email)):
                Line = Email[LineNumber]
                if Line.startswith('Subject: '):
                    EmailSubject = Line.split('Subject: ', 1)[1].strip()
                    EmailContents = ''.join(Email[LineNumber + 1:])
                    break
            message = Mail()
            message.from_email = From('webhook@tianocore.org', 'TianoCore')
            message.to = To(GROUPS_IO_ADDRESS, 'edk2codereview')
            message.subject = Subject(EmailSubject)
            message.content = Content(MimeType.text, EmailContents)
            try:
                sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
                response = sendgrid_client.send(message)
                print(response.status_code)
                print(response.body)
                print(response.headers)
            except Exception as e:
                print(e.body)
