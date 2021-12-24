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
from flask_bootstrap import Bootstrap
from flask import Flask, render_template, request, redirect, abort, send_from_directory
from flask_user import login_required, current_user
from Models import db, User, UserInvitation, CustomUserManager, LogTypeEnum, WebhookLog, WebhookConfiguration
from Forms import WebhookConfigurationForm
from Server import ProcessGithubRequest

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
        for eventlog in webhookconfiguration.children:
            logs = logs + eventlog.children
        if logid:
            text = WebhookLog.query.get_or_404(logid).Text
        elif logs:
            text = logs[0].Text
        else:
            text = ''
        return render_template('webhooklogs.html',
            webhookconfiguration=webhookconfiguration,
            logs=logs,
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
        if not webhookconfiguration:
            abort(400, "Unsupported repo")
        eventlog = webhookconfiguration.AddEventEntry ()
        #
        # Add request headers to the log
        #
        eventlog.AddLogEntry (LogTypeEnum.Request, request.headers.get('X-GitHub-Event', 'ping'), str(request.headers))
        response = ProcessGithubRequest (app, webhookconfiguration, eventlog)
        #
        # Add response headers to the log
        #
        eventlog.AddLogEntry (LogTypeEnum.Response, request.headers.get('X-GitHub-Event', 'ping'), str(response))
        return response

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(host="127.0.0.1", port=5000, threaded=True, debug=True)
