## @file
# TianoCore Code Review Archive Service Flask Application
#
# Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##
'''
TianoCore Code Review Archive Service Flask Application
'''
import os
import enum
import re
import datetime
import socks
import smtplib
from flask_bootstrap import Bootstrap
from flask import Flask, render_template, request, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from flask_user import UserManager, UserMixin, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, IntegerField, BooleanField, SubmitField, PasswordField, ValidationError
from wtforms.validators import DataRequired
from Server import ProcessGithubRequest

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

class WebhookConfiguration(db.Model):
    __tablename__ = 'webhook_configuration'
    id = db.Column(db.Integer, primary_key=True)
    #
    # The name of the GitHub origanization that hosts the repo for the webhook
    #
    GithubOrgName         = db.Column(db.String)
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
    # The name of the GitHub repo for the webhook
    #
    GithubRepoName        = db.Column(db.String)
    #
    # GITHUB_WEBHOOK_SECRET - 64 character hex string that is secret used to
    # validate payloads received from GitHub.  If this envirionment variable is not
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

    SendEmail           = db.Column(db.Boolean)
    children            = db.relationship(lambda: WebhookLog)

class LogTypeEnum(enum.Enum):
  Request = 1
  Response = 2
  Email = 3

class WebhookLog(db.Model):
    __tablename__ = 'webhook_log'
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey('webhook_configuration.id'))
    TimeStamp = db.Column(db.DateTime())
    Type = db.Column(db.Enum(LogTypeEnum))
    Text = db.Column(db.Text())

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

def create_app():
    app = Flask(__name__)
    bootstrap = Bootstrap(app)
    app.config.from_pyfile('config.py')

    if 'HTTP_PROXY' in app.config and app.config['HTTP_PROXY']:
        socks.setdefaultproxy(
            socks.HTTP,
            app.config['HTTP_PROXY'].rsplit(':',1)[0],
            int(app.config['HTTP_PROXY'].rsplit(':',1)[1])
            )
        socks.wrapmodule(smtplib)

    db.init_app(app)
    with app.app_context():
        db.create_all()

    user_manager = CustomUserManager(app, db, User, UserInvitationClass=UserInvitation)

    @app.route('/')
    def home_page():
        return render_template('index.html')

    @app.route('/config/listusers', methods=['GET', 'POST'])
    @login_required
    def webhook_users():
        users = User.query.all()
        return render_template('webhooklistusers.html', users=users)

    @app.route('/config/deleteuser/<id>', methods=['GET', 'POST'])
    @login_required
    def webhook_deleteuser(id):
        if request.method == 'POST':
            user = User.query.get_or_404(id)
            if user.id != current_user.id:
                db.session.delete(user)
                db.session.commit()
        return redirect('/config/listusers')

    @app.route('/config/listrepos', methods=['GET', 'POST'])
    @login_required
    def webhook_repos():
        webhookconfigurations = WebhookConfiguration.query.all()
        return render_template('webhooklistrepos.html', webhookconfigurations=webhookconfigurations)

    @app.route('/config/addrepo', methods=['GET', 'POST'])
    @login_required
    def webhook_addrepo():
        form = WebhookConfigurationForm(request.form)
        if request.method == 'GET':
            return render_template('webhookaddrepo.html', form=form, title="Add Repository")
        if request.method == 'POST' and form.validate_on_submit():
            if 'home' in request.form:
                return redirect('/')
            if 'cancel' in request.form:
                return redirect('/config/listrepos')
            webhookconfiguration = WebhookConfiguration()
            form.populate_obj(webhookconfiguration)
            db.session.add(webhookconfiguration)
            db.session.commit()
        return redirect('/config/listrepos')

    @app.route('/config/updaterepo/<id>', methods=['GET', 'POST'])
    @login_required
    def webhook_updaterepo(id):
        webhookconfiguration = WebhookConfiguration.query.get_or_404(id)
        form = WebhookConfigurationForm(obj=webhookconfiguration)
        text = 'Update ' + str(webhookconfiguration) + ' ' + str(form) + '\n\n'
        text += '''
kldj fdslk dsl lkdsmld lksdj lfd lds lkfdjfd ldsjlkfd lkdslkddskl dsl
sdkf sd;l dsl; kd;l;dls ;ldsk ;lfsd  asjkhkas daskjd
daskj dsakkashk dsajkdh sakd
askdhkajs dlkas d

ajkdash kjd as

asjkdh askjd kjas hdkjas

jasd hakjh dkajs dkjas kjdh askjdkasj dhkjas hdkjha skjd hkajsh dkja hskjdas
asjkdh aksjd kjas kda sk kd sakjdhkash dkjas dka skhd askjahkajdashkdh skjdskajdhaskj hdkjas hdkjas hdkjahs kjda hk
'''
        webhook_addlogentry (webhookconfiguration.GithubOrgName, webhookconfiguration.GithubRepoName, text)
        if request.method == 'GET':
            return render_template('webhookaddrepo.html', form=form, title="Update Repository Settings")
        if request.method == 'POST' and form.validate_on_submit():
            if 'home' in request.form:
                return redirect('/')
            if 'cancel' in request.form:
                return redirect('/config/listrepos')
            form.populate_obj(webhookconfiguration)
            db.session.commit()
        return redirect('/config/listrepos')

    @app.route('/config/deleterepo/<id>', methods=['GET', 'POST'])
    @login_required
    def webhook_deleterepo(id):
        if request.method == 'POST':
            webhookconfiguration = WebhookConfiguration.query.get_or_404(id)
            db.session.delete(webhookconfiguration)
            db.session.commit()
        return redirect('/config/listrepos')

    def webhook_addlogentry (OrgName, RepoName, Text):
        webhookconfiguration = WebhookConfiguration.query.filter_by(GithubOrgName = OrgName, GithubRepoName = RepoName).first()
        print ('add log query result = ', webhookconfiguration)
        entry = WebhookLog()
        entry.TimeStamp = datetime.datetime.now()
        entry.Text = Text
        entry.Type = LogTypeEnum.Request
        db.session.add(entry)
        webhookconfiguration.children.append (entry)
        db.session.commit()

    @app.route('/config/logsrepo/<repoid>', methods=['GET', 'POST'])
    @app.route('/config/logsrepo/<repoid>/<logid>', methods=['GET', 'POST'])
    @login_required
    def webhook_logsrepo(repoid, logid=None):
        print (repoid, logid)
        webhookconfiguration = WebhookConfiguration.query.get_or_404(repoid)
        print (webhookconfiguration)
        print (webhookconfiguration.children)
        if logid:
            text = WebhookLog.query.get_or_404(logid).Text
        elif webhookconfiguration.children:
            text = webhookconfiguration.children[0].Text
        else:
            text = ''
        return render_template('webhooklogs.html',
            webhookconfiguration=webhookconfiguration,
            logs=webhookconfiguration.children,
            text=text,
            rows=len(text.splitlines()) + 1
            )

    @app.route('/config/clearlogrepo/<repoid>', methods=['GET', 'POST'])
    @login_required
    def webhook_clearlogrepo(repoid):
        if request.method == 'POST':
            webhookconfiguration = WebhookConfiguration.query.get_or_404(repoid)
            for log in webhookconfiguration.children:
                db.session.delete(log)
            db.session.commit()
        return redirect('/config/logsrepo/'+str(repoid))

    @app.route('/webhook/<OrgName>/<RepoName>', methods=['GET', 'POST'])
    def webhook(OrgName, RepoName):
        try:
            webhookconfiguration = WebhookConfiguration.query.filter_by(GithubOrgName = OrgName, GithubRepoName = RepoName).first()
        except:
            abort(400, "Unsupported repo")
#def ProcessGithubRequest(GITHUB_TOKEN, GITHUB_WEBHOOK_SECRET, GITHUB_REPO_WHITE_LIST, EmailArchiveAddress, SendEmailEnabled, app, Verbose):
        response = ProcessGithubRequest (
            webhookconfiguration.GithubToken,
            webhookconfiguration.GithubWebhookSecret,
            [webhookconfiguration.GithubOrgName + '/' + webhookconfiguration.GithubRepoName],
            webhookconfiguration.EmailArchiveAddress,
            webhookconfiguration.SendEmail,
            app,
            True
        )
        return response

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host="127.0.0.1", port=5000, threaded=True, debug=True)
