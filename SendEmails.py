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
from Models import LogTypeEnum, WebhookStatistics
import Globals

def ParseEmailAddress(Address):
    EmailAddress = Address.rsplit('<',1)[1].split('>',1)[0].strip()
    EmailName    = (Address.rsplit('<',1)[0] + Address.rsplit('>')[1]).strip()
    return EmailAddress, EmailName

def SendEmails (Context, EmailContents, PrUserLogin = '', PrNumber = 0):
    try:
        if Context.webhookconfiguration.SendEmail:
            #
            # Send emails to SMTP Server
            #
            SmtpServer = smtplib.SMTP(Context.app.config['MAIL_SERVER'], Context.app.config['MAIL_PORT'])
            SmtpServer.starttls()
            SmtpServer.ehlo()
            SmtpServer.login(Context.app.config['MAIL_USERNAME'], Context.app.config['MAIL_PASSWORD'])
        Index = 0
        for Email in EmailContents:
            EmailMessage = email.message_from_string(Email)
            if 'From' in EmailMessage:
                try:
                    FromAddress, FromName = ParseEmailAddress(EmailMessage['From'])
                except:
                    FromAddress = 'webhook@tianocore.org'
                    FromName    = 'From %s via TianoCore Webhook' % (PrUserLogin)
            else:
                FromAddress = 'webhook@tianocore.org'
                FromName    = 'From %s via TianoCore Webhook' % (PrUserLogin)
            ToList = []
            if 'To' in EmailMessage:
                for Address in EmailMessage['To'].split(','):
                    try:
                        EmailAddress, EmailName = ParseEmailAddress(Address)
                        if EmailAddress.lower() in ToList:
                            continue
                        ToList.append(EmailAddress.lower())
                    except:
                        continue
            if 'Cc' in EmailMessage:
                for Address in EmailMessage['Cc'].split(','):
                    try:
                        EmailAddress, EmailName = ParseEmailAddress(Address)
                        if EmailAddress.lower() in ToList:
                            continue
                        ToList.append(EmailAddress.lower())
                    except:
                        continue
            Context.eventlog.AddLogEntry (LogTypeEnum.Email, 'pr[%d] email[%d]' % (PrNumber, Index), Email)
            if Context.webhookconfiguration.SendEmail:
                try:
                    SmtpServer.sendmail(FromAddress, ToList, Email)
                    WebhookStatistics.query.all()[0].EmailSent()
                except:
                    Context.eventlog.AddLogEntry (LogTypeEnum.Email, 'pr[%d] email[%d]' % (PrNumber, Index), 'SMTP ERROR: Send message failed')
                    WebhookStatistics.query.all()[0].EmailFailed()
            else:
                WebhookStatistics.query.all()[0].EmailSent()
            Index = Index + 1
        if Context.webhookconfiguration.SendEmail:
            SmtpServer.quit()
    except:
        Context.eventlog.AddLogEntry (LogTypeEnum.Email, 'pr[%d]' % (Context.HubPullRequest.number), 'SMTP ERROR: SMTP unable to connect or login or send messages')
