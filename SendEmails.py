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

def ParseEmailAddress(Address):
    EmailAddress = Address.rsplit('<',1)[1].split('>',1)[0].strip()
    EmailName    = (Address.rsplit('<',1)[0] + Address.rsplit('>')[1]).strip()
    return EmailAddress, EmailName

def SendEmails (HubPullRequest, EmailContents, SendEmailEnabled, app):
    if SendEmailEnabled:
        #
        # Send emails to SMTP Server
        #
        try:
            SmtpServer = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
            SmtpServer.starttls()
            SmtpServer.ehlo()
            SmtpServer.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
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
