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
import time
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

SMTP_ADDRESS     = os.environ['SMTP_ADDRESS']
SMTP_PORT_NUMBER = int(os.environ['SMTP_PORT_NUMBER'])
SMTP_USER_NAME   = os.environ['SMTP_USER_NAME']
SMTP_PASSWORD    = os.environ['SMTP_PASSWORD']
SENDGRID_API_KEY = os.environ['SENDGRID_API_KEY']

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
            Index = 0
            for Email in EmailContents:
                Index = Index + 1
                EmailMessage = email.message_from_string(Email)
                print ('pr[%d] email[%d]' % (HubPullRequest.number, Index), '----> SMTP Email Start <----')
                print (Email)
                print ('pr[%d] email[%d]' % (HubPullRequest.number, Index), '----> SMTP Email End <----')
                try:
                    SmtpServer.sendmail('webhook@tianocore.org', [EmailMessage['To']], Email)
                    print ('SMTP send mail success')
                    time.sleep(1)
                except:
                    print ('ERROR: SMTP send mail failed')

            SmtpServer.quit()
        except:
            print ('SendEmails: error: can not connect or login or send messages.')
    elif SendMethod == 'SendGrid':
        #
        # Send emails to SendGrid
        #
        Index = 0
        for Email in EmailContents:
            Index = Index + 1
            EmailMessage = email.message_from_string(Email)
            print ('pr[%d] email[%d]' % (HubPullRequest.number, Index), '----> SendGrid Email Start <----')
            print (Email)
            print ('pr[%d] email[%d]' % (HubPullRequest.number, Index), '----> SendGrid Email End   <----')
            message = Mail()
            try:
                message.from_email = From(
                   EmailMessage['From'].rsplit('<',1)[1].split('>',1)[0],
                   EmailMessage['From'].rsplit('<',1)[0] + EmailMessage['From'].rsplit('>')[1]
                   )
            except:
                print ('Bad from address')
                message.from_email = From('webhook@tianocore.org', 'From %s via TianoCore Webhook' % (HubPullRequest.user.login))
            try:
                message.to = To(
                   EmailMessage['To'].rsplit('<',1)[1].split('>',1)[0],
                   EmailMessage['To'].rsplit('<',1)[0] + EmailMessage['To'].rsplit('>')[1]
                   )
            except:
                print ('Bad to address')
                continue
            message.subject = Subject(EmailMessage['Subject'])
            for Field in ['Message-Id', 'In-Reply-To']:
                if Field in EmailMessage:
                    message.header = Header(Field, EmailMessage[Field])
            message.content = Content(MimeType.text, EmailMessage.get_payload())
            try:
                sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)
                response = sendgrid_client.send(message)
                print ('SendGridAPIClient send success')
                time.sleep(1)
            except Exception as e:
                print ('ERROR: SendGridAPIClient failed')
    else:
        Index = 0
        for Email in EmailContents:
            Index = Index + 1
            EmailMessage = email.message_from_string(Email)
            print ('pr[%d] email[%d]' % (HubPullRequest.number, Index), '----> Draft Email Start <----')
            print (Email)
            print ('pr[%d] email[%d]' % (HubPullRequest.number, Index), '----> Draft Email End   <----')
