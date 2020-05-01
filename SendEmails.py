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

def ParseEmailAddress(Address):
    EmailAddress = Address.rsplit('<',1)[1].split('>',1)[0].strip()
    EmailName    = (Address.rsplit('<',1)[0] + Address.rsplit('>')[1]).strip()
    return EmailAddress, EmailName

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
                if 'From' in EmailMessage:
                    try:
                        FromAddress, FromName = ParseEmailAddress(EmailMessage['From'])
                    except:
                        print ('Parsed From: Bad address:', EmailMessage['From'])
                        FromAddress = 'webhook@tianocore.org'
                        FromName    = 'From %s via TianoCore Webhook' % (HubPullRequest.user.login)
                else:
                    print ('Parsed From: Missing address:')
                    FromAddress = 'webhook@tianocore.org'
                    FromName    = 'From %s via TianoCore Webhook' % (HubPullRequest.user.login)
                ToList = []
                if 'To' in EmailMessage:
                    ToList = ToList + EmailMessage['To'].split(',')
                if 'Cc' in EmailMessage:
                    ToList = ToList + EmailMessage['Cc'].split(',')
                try:
                    SmtpServer.sendmail(FromAddress, ToList, Email)
                    print ('SMTP send mail success')
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
            if 'From' in EmailMessage:
                try:
                    EmailAddress, EmailName = ParseEmailAddress(EmailMessage['From'])
                    message.from_email = From(EmailAddress, EmailName)
                except:
                    print ('Parsed From: Bad address:', EmailMessage['From'])
                    message.from_email = From('webhook@tianocore.org', 'From %s via TianoCore Webhook' % (HubPullRequest.user.login))
            else:
                print ('Parsed From: Missing address:')
                message.from_email = From('webhook@tianocore.org', 'From %s via TianoCore Webhook' % (HubPullRequest.user.login))
            UniqueAddressList = []
            if 'To' in EmailMessage:
                for Address in EmailMessage['To'].split(','):
                    try:
                        EmailAddress, EmailName = ParseEmailAddress(Address)
                        if EmailAddress.lower() in UniqueAddressList:
                            continue
                        UniqueAddressList.append(EmailAddress.lower())
                        message.add_to (To(EmailAddress, EmailName))
                    except:
                        print ('Parsed To: Bad address:', Address)
                        continue
            if 'Cc' in EmailMessage:
                for Address in EmailMessage['Cc'].split(','):
                    try:
                        EmailAddress, EmailName = ParseEmailAddress(Address)
                        if EmailAddress.lower() in UniqueAddressList:
                            continue
                        UniqueAddressList.append(EmailAddress.lower())
                        message.add_cc (Cc(EmailAddress, EmailName))
                    except:
                        print ('Parsed Cc: Bad address:', Address)
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
            if 'From' in EmailMessage:
                try:
                    EmailAddress, EmailName = ParseEmailAddress(EmailMessage['From'])
                    print ('Parsed From:', EmailAddress, EmailName)
                except:
                    print ('Parsed From: Bad address:', EmailMessage['From'])
            else:
                print ('Parsed From: Missing address:')
            UniqueAddressList = []
            if 'To' in EmailMessage:
                for Address in EmailMessage['To'].split(','):
                    try:
                        EmailAddress, EmailName = ParseEmailAddress(Address)
                        if EmailAddress.lower() in UniqueAddressList:
                            continue
                        UniqueAddressList.append(EmailAddress.lower())
                        print ('Parsed To:', EmailAddress, EmailName)
                    except:
                        print ('Parsed To: Bad address:', Address)
                        continue
            if 'Cc' in EmailMessage:
                for Address in EmailMessage['Cc'].split(','):
                    try:
                        EmailAddress, EmailName = ParseEmailAddress(Address)
                        if EmailAddress.lower() in UniqueAddressList:
                            continue
                        UniqueAddressList.append(EmailAddress.lower())
                        print ('Parsed Cc:', EmailAddress, EmailName)
                    except:
                        print ('Parsed Cc: Bad address:', Address)
                        continue
            print('--------------------')
            print (Email)
            print ('pr[%d] email[%d]' % (HubPullRequest.number, Index), '----> Draft Email End   <----')
