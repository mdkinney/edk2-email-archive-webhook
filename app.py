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
import socks
import smtplib
from collections import OrderedDict
from json import dumps
from flask_bootstrap import Bootstrap
from flask import Flask, render_template, request, redirect, abort, send_from_directory, make_response
from flask_user import login_required, current_user
from FetchPullRequest import DeleteRepositoryCache
from Models import db, User, UserInvitation, CustomUserManager, LogTypeEnum, WebhookLog, WebhookConfiguration
from Forms import WebhookConfigurationForm
from Server import ProcessGithubRequest

class WebhookContext(object):
    def __init__(self, app, webhookconfiguration, eventlog):
        self.app                     = app
        self.webhookconfiguration    = webhookconfiguration
        self.eventlog                = eventlog
        self.event                   = ''
        self.action                  = ''
        self.payload                 = None
        self.Hub                     = None
        self.GitRepo                 = None
        self.HubRepo                 = None
        self.HubPullRequest          = None
        self.CommitList              = []
        self.CommitAddressDict       = OrderedDict()
        self.CommitGitHubIdDict      = OrderedDict()
        self.PullRequestAddressList  = []
        self.PullRequestGitHubIdList = []
        self.NewPatchSeries          = False
        self.PatchSeriesVersion      = 0

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

    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

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

    @app.route('/config/logsrepo/<repoid>', methods=['GET', 'POST'])
    @app.route('/config/logsrepo/<repoid>/<logid>', methods=['GET', 'POST'])
    @login_required
    def webhook_logsrepo(repoid, logid=None):
        webhookconfiguration = WebhookConfiguration.query.get_or_404(repoid)
        logs = []
        for eventlog in reversed(webhookconfiguration.children):
            logs = logs + eventlog.children
        if logid:
            text = WebhookLog.query.get_or_404(logid).Text
        elif logs:
            text = logs[0].Text
        else:
            text = ''
        return render_template('webhooklogs.html',
            webhookconfiguration=webhookconfiguration,
            events=reversed(webhookconfiguration.children),
            logs=logs,
            text=text,
            rows=len(text.splitlines()) + 1
            )

    @app.route('/config/clearlogrepo/<repoid>', methods=['POST'])
    @login_required
    def webhook_clearlogrepo(repoid):
        if request.method == 'POST':
            webhookconfiguration = WebhookConfiguration.query.get_or_404(repoid)
            for log in webhookconfiguration.children:
                db.session.delete(log)
            db.session.commit()
            eventlog = webhookconfiguration.AddEventEntry ()
            eventlog.AddLogEntry (LogTypeEnum.Message, 'Clear log', '')
        return redirect('/config/logsrepo/'+str(repoid))

    @app.route('/config/deletegitrepocache/<repoid>', methods=['POST'])
    @login_required
    def webhook_deletegitrepocache(repoid):
        if request.method == 'POST':
            webhookconfiguration = WebhookConfiguration.query.get_or_404(repoid)
            Status = DeleteRepositoryCache (webhookconfiguration)
            eventlog = webhookconfiguration.AddEventEntry ()
            if Status:
                eventlog.AddLogEntry (LogTypeEnum.Message, 'Delete Repo PASS', '')
            else:
                eventlog.AddLogEntry (LogTypeEnum.Message, 'Delete Repo FAIL', '')
        return redirect('/config/logsrepo/'+str(repoid))

    @app.route('/webhook/<OrgName>/<RepoName>', methods=['POST'])
    def webhook(OrgName, RepoName):
        try:
            webhookconfiguration = WebhookConfiguration.query.filter_by(GithubOrgName = OrgName, GithubRepoName = RepoName).first()
        except:
            abort(400, 'Unsupported repo')
        if not webhookconfiguration:
            abort(400, 'Unsupported repo')
        eventlog = webhookconfiguration.AddEventEntry ()

        Context = WebhookContext (app, webhookconfiguration, eventlog)

        status, message = ProcessGithubRequest (Context)
        response = make_response({'message': message}, status)
        #
        # Add response header and json payload to the log
        #
        eventlog.AddLogEntry (LogTypeEnum.Response, request.headers.get('X-GitHub-Event', 'ping'), str(response.headers) + dumps(response.get_json(), indent=2))
        return response

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host="127.0.0.1", port=5000, threaded=True, debug=True)
