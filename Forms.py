## @file
# TianoCore Code Review Archive Service Flask Application
#
# Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##
'''
TianoCore Code Review Archive Service Flask Forms
'''
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField

class WebhookConfigurationForm(FlaskForm):
    GithubOrgName       = StringField('GithubOrgName')
    GithubToken         = StringField('GithubToken')
    GithubRepoName      = StringField('GithubRepoName')
    GithubWebhookSecret = StringField('GithubWebhookSecret')
    EmailArchiveAddress = StringField('EmailArchiveAddress')
    SendEmail           = SelectField('SendEmail', choices=[('',"False"),('1',"True")], coerce=bool)
    save                = SubmitField('Save')
    cancel              = SubmitField('Cancel')
    home                = SubmitField('Home')
