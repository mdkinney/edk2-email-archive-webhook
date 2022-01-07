## @file
# Assign reviewers to commits in a GitHub pull request based on assignments
# documented in Maintainers.txt and generate email archive of all review
# activities.
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

import sys
import hmac
import time
from json   import dumps
from github import Github
from flask  import request, abort
from Models import LogTypeEnum

def AuthenticateGithubRequestHeader(self):
    # Only POST is supported
    if request.method != 'POST':
        abort(501, 'only POST is supported')
    # Enforce secret, so not just anybody can trigger these hooks
    if self.webhookconfiguration.GithubWebhookSecret:
        # Check for SHA256 signature
        header_signature = request.headers.get('X-Hub-Signature-256')
        if header_signature is None:
            # Check for SHA1 signature
            header_signature = request.headers.get('X-Hub-Signature')
            if header_signature is None:
                abort(403, 'No header signature found')
        sha_name, signature = header_signature.split('=')
        if sha_name not in ['sha256', 'sha1']:
            abort(501, 'Only SHA256 and SHA1 are supported')
        # HMAC requires the key to be bytes, but data is string
        mac = hmac.new(
                bytes(self.webhookconfiguration.GithubWebhookSecret, 'utf-8'),
                msg=request.get_data(),
                digestmod=sha_name
                )
        # Python does not have hmac.compare_digest prior to 2.7.7
        if sys.hexversion >= 0x020707F0:
            if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
                abort(403, 'hmac compare digest failed')
        else:
            # What compare_digest provides is protection against timing
            # attacks; we can live without this protection for a web-based
            # application
            if not str(mac.hexdigest()) == str(signature):
                abort(403, 'hmac compare digest failed')
    # Update self with event from the request header.
    # Default is a 'ping' event
    self.event = request.headers.get('X-GitHub-Event', 'ping')
    # Add request headers to the log
    # Delayed to this point to prevent logging rejected requests
    self.eventlog.AddLogEntry(LogTypeEnum.Request, self.event, str(request.headers))

def VerifyPayload(self):
    # If event is ping, then generate a pong response
    if self.event == 'ping':
        return 200, 'pong'
    # If event is meta, then generate a meta response
    if self.event == 'meta':
        self.Message = 'meta'
        return 200, 'meta'
    # Parse request payload as json
    try:
        payload = request.get_json()
    except Exception:
        abort(400, 'Request parsing failed')
    # Add payload to the log
    if 'action' in payload:
        self.eventlog.AddLogEntry(LogTypeEnum.Payload, payload['action'], dumps(payload, indent=2))
    else:
        # Skip payload that does not provide an action
        self.eventlog.AddLogEntry(LogTypeEnum.Payload, 'None', dumps(payload, indent=2))
        return 200, 'ignore event %s with no action' % (self.event)
    # Ignore push and create events
    if self.event in ['push', 'create']:
        return 200,'ignore event %s' % (self.event)
    # Skip payload that does not provide a repository
    if 'repository' not in payload:
        return 200, 'ignore event %s with no repository' % (self.event)
    # Skip payload that does not provide a repository full name
    if 'full_name' not in payload['repository']:
        return 200, 'ignore event %s with no repository full name' % (self.event)
    # Skip requests that are not for the configured repository
    if payload['repository']['full_name'] != self.webhookconfiguration.GithubRepo:
        return 200, 'ignore event %s for incorrect repository %s' % (self.event, payload['repository']['full_name'])
    # Update self structure
    self.action  = payload['action']
    self.payload = payload
    return 0, ''

def VerifyPullRequest(self, Issue = None):
    # Retrieve Hub object for this repo
    if not self.Hub:
        try:
            self.Hub = Github(self.webhookconfiguration.GithubToken)
        except:
            return 200, 'Unable to retrieve Hub object using GITHUB_TOKEN'
    # Use GitHub API to get the Repo and Pull Request objects
    HubRepo        = None
    HubPullRequest = None
    try:
        if Issue:
            # Skip Issue with same commit SHA that is for a different repository
            if Issue.repository.full_name != self.payload['repository']['full_name']:
                return 200, 'ignore %s event for a different repository %s' % (self.event, Issue.repository.full_name)
            HubRepo = Issue.repository
            HubPullRequest = Issue.as_pull_request()
        elif self.Hub:
            HubRepo = self.Hub.get_repo(self.payload['repository']['full_name'])
            if 'pull_request' in self.payload:
                HubPullRequest = HubRepo.get_pull(self.payload['pull_request']['number'])
            elif 'issue' in self.payload:
                HubPullRequest = HubRepo.get_pull(self.payload['issue']['number'])
    except:
        pass
    if not HubRepo or not HubPullRequest:
        # Skip requests if the PyGitHub objects can not be retrieved
        return 200, 'ignore %s event for which the GitHub objects can not be retrieved' % (self.event)
    # Skip pull request that is a draft
    if HubPullRequest.draft:
        return 200, 'ignore %s event against a draft pull request' % (self.event)
    # Skip pull request that is not open unless the pull request is being closed
    if self.event != 'pull_request' or self.action != 'closed':
        if HubPullRequest.state != 'open':
            return 200, 'ignore %s event against a pull request with state %s that is not open' % (self.event, HubPullRequest.state)
    # Skip pull request with a base repo that is different than the expected repo
    if HubPullRequest.base.repo.full_name != HubRepo.full_name:
        return 200, 'ignore %s event against unexpected repo %s' % (self.event, HubPullRequest.base.repo.full_name)
    # Skip pull requests with a base branch that is not protected or the default branch
    Branch = HubRepo.get_branch(HubPullRequest.base.ref)
    if not Branch or not Branch.protected:
        if HubPullRequest.base.ref != HubRepo.default_branch:
            return 200, 'ignore %s event against base branch %s that is not protected or the default branch' % (self.event, HubPullRequest.base.ref)
    # Update context structure
    self.HubRepo            = HubRepo
    self.HubPullRequest     = HubPullRequest
    # Fetch the git commits for the pull request and return a git repo
    # object and the contents of Maintainers.txt
    for Retry in range(1, 3):
        Status, Message = self.FetchPullRequest()
        if not Status:
            break
        print ('Error in FetchPullRequest().  Sleep 1 second and retry')
        time.sleep(1)
    if Status:
        return Status, Message
    # Determine if this is a new patch series and the version of the patch series
    NewPatchSeries = False
    PatchSeriesVersion = 1;
    if self.event == 'pull_request' and self.action in ['opened', 'reopened', 'ready_for_review']:
        # New pull request was created
        NewPatchSeries = True
    if self.event != 'pull_request' or self.action in ['synchronize', 'edited', 'closed', 'reopened', 'ready_for_review']:
        # Existing pull request was updated.
        # Commits were added to an existing pull request or an existing pull
        # request was forced push. Get events to determine what happened
        for Event in HubPullRequest.get_issue_events():
            # Count head_ref_force_pushed and reopened events to determine
            # the version of the patch series.
            if Event.event in ['head_ref_force_pushed', 'reopened']:
                PatchSeriesVersion = PatchSeriesVersion + 1;
            if Event.event in ['head_ref_force_pushed']:
                # If the head_ref_force_pushed event occurred at the exact
                # same date/time (or within 2 seconds) that the pull request
                # was updated, then this was a forced push and the entire
                # patch series should be emailed again.
                if abs(Event.created_at - HubPullRequest.updated_at).seconds <= 2:
                    NewPatchSeries = True
    # Update context structure
    self.NewPatchSeries     = NewPatchSeries
    self.PatchSeriesVersion = PatchSeriesVersion
    return 0, ''
