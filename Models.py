## @file
# TianoCore Code Review Archive Service Flask Application
#
# Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##
'''
TianoCore Code Review Archive Service Flask Models
'''

import re
import enum
import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_user import UserManager, UserMixin
from wtforms import ValidationError

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(255), nullable=False, unique=True)
    email_confirmed_at = db.Column(db.DateTime())
    username = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False, server_default='')

    active = db.Column(db.Boolean())
    first_name = db.Column(db.String(50), nullable=False, server_default='')
    last_name = db.Column(db.String(50), nullable=False, server_default='')

class UserInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100))
    invited_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# Customize Flask-User
class CustomUserManager(UserManager):

    # Override the default password validator
    def password_validator(self, form, field):
        # Regular expression used to validate a strong password.
        #   * The password length must be greater than or equal to 8
        #   * The password must contain one or more uppercase characters
        #   * The password must contain one or more lowercase characters
        #   * The password must contain one or more numeric values
        #   * The password must contain one or more special characters
        #
        # https://www.computerworld.com/article/2833081/how-to-validate-password-strength-using-a-regular-expression.html
        #
        StrongPasswordRegex = '(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$'
        if not re.match(StrongPasswordRegex, field.data):
            raise ValidationError(('Password must be >=8 chars with one or more Upper, Lower, Number, and Special'))

class LogTypeEnum(enum.Enum):
  Request = 1
  Response = 2
  Email = 3
  Message = 4
  Payload = 5

class WebhookLog(db.Model):
    __tablename__ = 'webhook_log'
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('webhook_event_log.id'))
    TimeStamp = db.Column(db.DateTime())
    Type = db.Column(db.Enum(LogTypeEnum))
    SubType = db.Column(db.String())
    Text = db.Column(db.Text())

class WebhookEventLog(db.Model):
    __tablename__ = 'webhook_event_log'
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('webhook_configuration.id'))
    TimeStamp = db.Column(db.DateTime())
    Event = db.Column(db.Text())
    children            = db.relationship(lambda: WebhookLog)

    def AddLogEntry (self, Type, SubType, Text):
        entry = WebhookLog()
        entry.TimeStamp = datetime.datetime.now()
        entry.Type = Type
        entry.SubType = SubType
        entry.Text = Text
        db.session.add(entry)
        self.children.append (entry)
        db.session.commit()
        return entry

class WebhookConfiguration(db.Model):
    __tablename__ = 'webhook_configuration'
    id = db.Column(db.Integer, primary_key=True)
    #
    # The name of the GitHub repo for the webhook of the for OrgName/RepoName
    #
    GithubRepo            = db.Column(db.String, unique=True)
    #
    # GITHUB_TOKEN - 40 character hex string that is a Personal Access Token
    # created in GitHub in User->Settings->Developer Settings->Personal access tokens.
    # The personal access token must be generated from a user account that has
    # permissions to the GitHub repositories for which an email archive is required.
    # This token is used by the webhook service when making GitHub API calls. If
    # this environment variable is not set correctly then GitHub API calls fail.
    # Usually scoped to a GitHub organization.
    # Required to make GitHub API calls
    #
    # [Creating webHooks](https://developer.github.com/webhooks/creating/)
    #
    GithubToken         = db.Column(db.String)
    #
    # GITHUB_WEBHOOK_SECRET - 64 character hex string that is secret used to
    # validate payloads received from GitHub.  If this environment variable is not
    # set correctly, then all payloads from GitHub are rejected. This value
    # must match the GitHub repository setting  in Settings->WebHooks->Edit->Secret.
    # Scope to a single repository.
    # Required to authenticate POST payloads received from GitHub
    #
    # [Setting your secret token](https://developer.github.com/webhooks/securing/#setting-your-secret-token)
    #
    GithubWebhookSecret = db.Column(db.String)
    #
    # EMAIL_ARCHIVE_ADDRESS` - The TO address for emails address generated by this
    # webhook service.  This is typically the address of an email subscription
    # service that allows a community of developers to receive the emails generated
    # by this webhook service and for the emails to be archived.
    #
    EmailArchiveAddress = db.Column(db.String)
    # Set to True to enable sending emails to EmailArchiveList
    # Set to False to disable sending emails to EmailArchiveList
    SendEmail           = db.Column(db.Boolean)
    # Set to the maximum number of lines in a patch to send the entire patch
    # when a comment is made.  If the patch is larger than this number of lines
    # then only the specific file the comment is against will be added to the
    #  email.
    LargePatchLines     = db.Column(db.Integer)
    # Path to Maintainers.txt in the repository.  Default is Maintainters.txt
    # in the root of the repository.
    MaintainersTxtPath  = db.Column(db.String)
    # The children of this object model are a list of Github POST events
    children            = db.relationship(lambda: WebhookEventLog)

    def AddEventEntry (self):
        entry = WebhookEventLog()
        db.session.add(entry)
        self.children.append (entry)
        db.session.commit()
        return entry
