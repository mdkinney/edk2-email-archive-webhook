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
import sys
import socks
import smtplib
import time
from datetime import datetime
from json import dumps
from flask_bootstrap import Bootstrap
from flask import Flask, render_template, request, redirect, abort, send_from_directory, make_response
from flask_user import login_required, current_user
from Models import db, User, UserInvitation, CustomUserManager, LogTypeEnum, WebhookEventLog, WebhookLog, WebhookConfiguration, WebhookStatistics
from Forms import WebhookConfigurationForm
from Server import GuthubRequest
from threading import Thread, Timer
import Globals
from SendEmails import SendEmails

#
# Flask Application Settings
# Update version when a new release is published
#
USER_APP_NAME         = 'TianoCore Code Review Archive Service'
USER_APP_VERSION      = '0.1'
USER_COPYRIGHT_YEAR   = '2021'
USER_CORPORATION_NAME = 'TianoCore'

def create_app():
    # Initialize Flask Application
    app = Flask(__name__)
    Bootstrap(app)
    # Load Flask Application configuration settings from file
    app.config.from_pyfile('config.py')
    # Flask Application Settings
    app.config['USER_APP_NAME']         = USER_APP_NAME
    app.config['USER_APP_VERSION']      = USER_APP_VERSION
    app.config['USER_COPYRIGHT_YEAR']   = USER_COPYRIGHT_YEAR
    app.config['USER_CORPORATION_NAME'] = USER_CORPORATION_NAME
    # SQL Alchemy Database Settings
    #  Database in same directory as python script
    app.config['SQLALCHEMY_DATABASE_URI']        = 'sqlite:///database.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Flask UserManager Settings
    app.config['USER_ENABLE_EMAIL']                    = True
    app.config['USER_ENABLE_USERNAME']                 = True
    app.config['USER_REQUIRE_RETYPE_PASSWORD']         = True
    app.config['USER_ENABLE_CHANGE_USERNAME']          = True
    app.config['USER_ENABLE_CHANGE_PASSWORD']          = True
    app.config['USER_AUTO_LOGIN_AFTER_CONFIRM']        = True
    app.config['USER_AUTO_LOGIN_AFTER_REGISTER']       = True
    app.config['USER_AUTO_LOGIN_AFTER_RESET_PASSWORD'] = True
    app.config['USER_AUTO_LOGIN']                      = True
    app.config['USER_AUTO_LOGIN_AT_LOGIN']             = True
    app.config['USER_ENABLE_INVITE_USER']              = True
    app.config['USER_REQUIRE_INVITATION']              = True
    app.config['USER_EMAIL_SENDER_NAME']                = USER_APP_NAME
    # Initialize db
    db.init_app(app)
    with app.app_context():
        db.create_all()
    # Initialize Flask User Manager
    CustomUserManager(app, db, User, UserInvitationClass=UserInvitation)
    # Apply proxy to smtplib if email server
    if 'MAIL_HTTP_PROXY' in app.config and app.config['MAIL_HTTP_PROXY']:
        socks.setdefaultproxy(
            socks.HTTP,
            app.config['MAIL_HTTP_PROXY'].rsplit(':',1)[0],
            int(app.config['MAIL_HTTP_PROXY'].rsplit(':',1)[1])
            )
        socks.wrapmodule(smtplib)

    @app.route('/')
    def home_page():
        return render_template('index.html')

    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

    @app.route('/config/listusers', methods=['GET'])
    @login_required
    def webhook_users():
        users = User.query.all()
        return render_template('webhooklistusers.html', users=users)

    @app.route('/config/deleteuser/<id>', methods=['POST'])
    @login_required
    def webhook_deleteuser(id):
        if request.method == 'POST':
            user = User.query.get_or_404(id)
            if user.id != current_user.id:
                db.session.delete(user)
                db.session.commit()
        return redirect('/config/listusers')

    @app.route('/config/listrepos', methods=['GET'])
    @login_required
    def webhook_repos():
        webhookconfigurations = WebhookConfiguration.query.all()
        for webhookconfiguration in webhookconfigurations:
            queue = Globals.GetRepositoryQueue(webhookconfiguration.GithubRepo)
            webhookconfiguration.QueueDepth = queue.active_size()
        Statistics = WebhookStatistics.query.all()[0]
        return render_template(
                   'webhooklistrepos.html',
                   NumberOfUpgrades        = Statistics.NumberOfUpgrades,
                   LastUpgradeTime         = Statistics.LastUpgradeTimeStamp,
                   NumberOfRestarts        = Statistics.NumberOfRestarts,
                   ServiceUpTime           = datetime.now() - Statistics.LastRestartTimeStamp,
                   webhookconfigurations   = webhookconfigurations,
                   EmailQueueDepth         = Globals.GetEmailQueue().active_size(),
                   EmailsSent              = Statistics.EmailsSent,
                   EmailsFailed            = Statistics.EmailsFailed,
                   GitHubRequestsReceived  = Statistics.GitHubRequestsReceived,
                   GitHubRequestsQueued    = Statistics.GitHubRequestsQueued,
                   GitHubRequestsProcessed = Statistics.GitHubRequestsProcessed,
                   )

    @app.route('/config/resetstatistics', methods=['POST'])
    @login_required
    def webhook_resetstatistics():
        WebhookStatistics.query.all()[0].ResetStatistics()
        return redirect('/config/listrepos')

    @app.route('/config/addrepo', methods=['GET', 'POST'])
    @login_required
    def webhook_addrepo():
        form = WebhookConfigurationForm(request.form)
        if request.method == 'POST':
            if 'home' in request.form:
                return redirect('/')
            if 'cancel' in request.form:
                return redirect('/config/listrepos')
        if request.method == 'GET' or not form.validate_on_submit():
            return render_template('webhookaddrepo.html', form=form, title="Add Repository")
        webhookconfiguration = WebhookConfiguration()
        form.populate_obj(webhookconfiguration)
        db.session.add(webhookconfiguration)
        db.session.commit()
        return redirect('/config/listrepos')

    @app.route('/config/updaterepo/<id>', methods=['GET', 'POST'])
    @login_required
    def webhook_updaterepo(id):
        webhookconfiguration = WebhookConfiguration.query.get_or_404(id)
        form = WebhookConfigurationForm(webhookconfiguration.GithubRepo, obj=webhookconfiguration)
        if request.method == 'POST':
            if 'home' in request.form:
                return redirect('/')
            if 'cancel' in request.form:
                return redirect('/config/listrepos')
        if request.method == 'GET' or not form.validate_on_submit():
            return render_template('webhookaddrepo.html', form=form, title="Update Repository Settings")
        form.populate_obj(webhookconfiguration)
        db.session.commit()
        return redirect('/config/listrepos')

    @app.route('/config/deleterepo/<id>', methods=['POST'])
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
            eventlog = webhookconfiguration.AddEventEntry()
            Context = GuthubRequest(app, webhookconfiguration, eventlog)
            Context.event   = 'CUSTOM'
            Context.action  = 'ClearLogs'
            Context.payload = ''
            eventlog.AddLogEntry(LogTypeEnum.Request, Context.event, Context.action)
            WebhookStatistics.query.all()[0].RequestReceived()
            Status, Message = Context.QueueGithubRequest()
            eventlog.AddLogEntry(LogTypeEnum.Response, str(Status), Message)
        return redirect('/config/logsrepo/'+str(repoid))

    @app.route('/config/deletegitrepocache/<repoid>', methods=['POST'])
    @login_required
    def webhook_deletegitrepocache(repoid):
        if request.method == 'POST':
            webhookconfiguration = WebhookConfiguration.query.get_or_404(repoid)
            eventlog = webhookconfiguration.AddEventEntry()
            Context = GuthubRequest(app, webhookconfiguration, eventlog)
            Context.event   = 'CUSTOM'
            Context.action  = 'DeleteRepositoryCache'
            Context.payload = ''
            eventlog.AddLogEntry(LogTypeEnum.Request, Context.event, Context.action)
            WebhookStatistics.query.all()[0].RequestReceived()
            Status, Message = Context.QueueGithubRequest()
            eventlog.AddLogEntry(LogTypeEnum.Response, str(Status), Message)
        return redirect('/config/logsrepo/'+str(repoid))

    @app.route('/webhook/<OrgName>/<RepoName>', methods=['POST'])
    def webhook(OrgName, RepoName):
        WebhookStatistics.query.all()[0].RequestReceived()
        try:
            webhookconfiguration = WebhookConfiguration.query.filter_by(GithubRepo = OrgName + '/' + RepoName).first()
        except:
            abort(400, 'Unsupported repo')
        if not webhookconfiguration:
            abort(400, 'Unsupported repo')
        eventlog = webhookconfiguration.AddEventEntry()
        Context = GuthubRequest(app, webhookconfiguration, eventlog)
        Status, Message = Context.ProcessGithubRequest()
        Response = make_response({'message': Message}, Status)
        # Add response header and json payload to the log
        eventlog.AddLogEntry(LogTypeEnum.Response, str(Status), str(Response.headers) + dumps(Response.get_json(), indent=2))
        return Response

    return app

def WaitForGitHubRequest():
    with app.app_context():
        while True:
            # Loop through all configured repos looking for work to do
            for webhookconfiguration in WebhookConfiguration.query.all():
                queue = Globals.GetRepositoryQueue(webhookconfiguration.GithubRepo)
                if queue.empty():
                    time.sleep(0.1)
                    continue
                item = queue.get()
                eventlog = WebhookEventLog.query.get(item[0])
                if not eventlog:
                    eventlog = webhookconfiguration.AddEventEntry()
                Context = GuthubRequest(app, webhookconfiguration, eventlog)
                Context.event   = item[1]
                Context.action  = item[2]
                Context.payload = item[3]
                Status, Message = Context.DispatchGithubRequest()
                eventlog.AddLogEntry(LogTypeEnum.Finished, str(Status), Message)
                queue.ack(item)
                WebhookStatistics.query.all()[0].RequestProcessed()

def WaitForSendEmailsRequest():
    with app.app_context():
        while True:
            queue = Globals.GetEmailQueue()
            if queue.empty():
                time.sleep(0.1)
                continue
            item = queue.get()
            webhookconfiguration = WebhookConfiguration.query.get(item[1])
            if not webhookconfiguration:
                queue.ack(item)
                continue
            eventlog = WebhookEventLog.query.get(item[0])
            if not eventlog:
                eventlog = webhookconfiguration.AddEventEntry()
            Context = GuthubRequest(app, webhookconfiguration, eventlog)
            SendEmails(Context, item[4], item[2], item[3])
            eventlog.AddLogEntry(LogTypeEnum.Finished, 200, 'Emails sent')
            queue.ack(item)

def StartQueueListeners():
    print('Start Queue Listeners')
    Thread(target=WaitForGitHubRequest, daemon=True).start()
    Thread(target=WaitForSendEmailsRequest, daemon=True).start()

if __name__ == '__main__':
    Globals.Initialize()
    app = create_app()
    with app.app_context():
        if User.query.all() == []:
            print('ERROR: No users in database.')
            sys.exit(1)
        # Retrieve existing statistics records
        StatisticList = WebhookStatistics.query.all()
        # If there are none, then create one
        if not StatisticList:
            Statistic = WebhookStatistics()
            StatisticList = WebhookStatistics.query.all()
        # Delete any extra statistics records. Only the first one is used.
        for Statistic in StatisticList[1:]:
            db.session.delete(Statistic)
            db.session.commit()
        # Update service restart count and last restart time
        StatisticList[0].RestartService((app.config['USER_APP_NAME'] + ' ' + app.config['USER_APP_VERSION']).strip())

    Timer(5.0, StartQueueListeners).start()

    app.run(host="127.0.0.1", port=5000, threaded=True, debug=True)
