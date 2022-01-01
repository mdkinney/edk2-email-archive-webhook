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
#from email.policy import default
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, SubmitField, IntegerField
from wtforms.widgets import PasswordInput
from wtforms.validators import Email, ValidationError
from Models import WebhookConfiguration
from github import Github
import requests

class WebhookConfigurationForm(FlaskForm):
    GithubRepo          = StringField(
        'GithubRepo',
        description='Github repository name of form <organization>/<repository> (e.g. tianocore/edk2).'
        )
    GithubToken         = StringField(
        'GithubToken',
        description='40 character hex string that is a Personal Access Token created in GitHub User->Settings->Developer Settings->Personal access tokens.',
        widget=PasswordInput(hide_value=False)
        )
    GithubWebhookSecret = StringField(
        'GithubWebhookSecret',
        description='64 character hex string that is secret used to validate payloads received from GitHub.',
        widget=PasswordInput(hide_value=False)
        )
    EmailArchiveAddress = StringField(
        'EmailArchiveAddress',
        description='The TO address for emails address generated by this service.',
        validators=[Email(message='That is not a valid email address')]
        )
    SendEmail           = SelectField(
        'SendEmail',
        description = 'True to enable sending emails.  False to disable sending emails.',
        choices=[('',"False"),('1',"True")],
        coerce=bool
        )
    LargePatchLines     = IntegerField(
        'LargePatchLines',
        description='Maximum number of patch lines before file filtering is enabled.  Default is 500 lines.',
        default=500
        )
    MaintainersTxtPath  = StringField(
        'MaintainersTxtPath',
        description='Path to Maintainers.txt in the repository.  Default is Maintainters.txt in the root of the repository.',
        default='Maintainers.txt'
        )
    save                = SubmitField('Save')
    cancel              = SubmitField('Cancel')
    home                = SubmitField('Home')

    def __init__(self, original_GithubRepo, *args, **kwargs):
        super(WebhookConfigurationForm, self).__init__(*args, **kwargs)
        self.original_GithubRepo = original_GithubRepo

    def validate_GithubRepo(self, GithubRepo):
        if GithubRepo.data != self.original_GithubRepo:
            webhookconfiguration = WebhookConfiguration.query.filter_by(GithubRepo=self.GithubRepo.data).first()
            if webhookconfiguration is not None:
                raise ValidationError('Duplicate Github repository not allowed.')
        try:
            url = 'https://github.com/%s' % (GithubRepo.data)
            Response=requests.get(url)
            Response.raise_for_status()
        except:
            raise ValidationError('%s not found' % (url))

    def validate_GithubToken(self, GithubToken):
        if len(GithubToken.data) != 40:
            raise ValidationError('GithubToken must be 40 characters long.')
        try:
            Hub = Github (GithubToken.data)
            HubRepo = Hub.get_repo(self.GithubRepo.data)
        except:
            raise ValidationError('GithubToken can not be verified for repository %s' % (self.GithubRepo.data))

    def validate_GithubWebhookSecret(self, GithubWebhookSecret):
        if len(GithubWebhookSecret.data) != 64:
            raise ValidationError('GithubWebhookSecret must be 64 characters long.')

    def validate_LargePatchLines(self, LargePatchLines):
        if not LargePatchLines.data or LargePatchLines.data < 50:
            raise ValidationError('LargePatchLines must be an integer value >= 50.')

    def validate_MaintainersTxtPath(self, MaintainersTxtPath):
        if len(MaintainersTxtPath.data) == 0:
            raise ValidationError('MaintainersTxtPath must be a valid filename.')
        if '\\' in MaintainersTxtPath.data:
            raise ValidationError('MaintainersTxtPath must use / path seperators.')
        try:
            Hub = Github (self.GithubToken.data)
            HubRepo = Hub.get_repo(self.GithubRepo.data)
            ProtectedBranches = [Branch for Branch in HubRepo.get_branches() if Branch.protected]
        except:
            raise ValidationError('GithubToken can not be verified for repository %s' % (self.GithubRepo.data))
        if not ProtectedBranches:
            raise ValidationError('Repository %s must have at least one protected branch.' % (self.GithubRepo.data))
        for Branch in ProtectedBranches:
            url = 'https://raw.githubusercontent.com/%s/%s/%s' % (
                self.GithubRepo.data,
                Branch.name,
                MaintainersTxtPath.data
                )
            try:
                Response=requests.get(url)
                Response.raise_for_status()
            except:
                raise ValidationError('%s not found.' % (url))
