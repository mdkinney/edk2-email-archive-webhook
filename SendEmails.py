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
import email
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

def SendEmails (HubPullRequest, EmailContents, SendMethod):
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
    elif SendMethod == 'SendGrid':
        #
        # Send emails to SendGrid
        #
        for Email in EmailContents:
            Email = email.message_from_string(Email)
            message = Mail()
            message.from_email = From('webhook@tianocore.org', 'TianoCore')
            message.to = To(GROUPS_IO_ADDRESS, 'edk2codereview')
            message.subject = Subject(Email['Subject'])
            for Field in ['Message-Id', 'In-Reply-To']:
                if Field in Email:
                    message.header = Header(Field, Email[Field])
            message.content = Content(MimeType.text, Email.get_payload())
            print (message)
            try:
                sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
                response = sendgrid_client.send(message)
                print(response.status_code)
                print(response.body)
                print(response.headers)
            except Exception as e:
                print(e.body)
    else:
        Index = 0
        for Email in EmailContents:
            Index = Index + 1
            print ('pr[%d] email[%d]' % (HubPullRequest.number, Index), '----> Draft Email Start <----')
            print (Email)
            print ('pr[%d] email[%d]' % (HubPullRequest.number, Index), '----> Draft Email End   <----')
