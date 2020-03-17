## @file
# Assign reviewers to commits in a GitHub pull request based on assignments
# documented in Maintainers.txt and generate email archive of all review
# activities.
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

'''
TianoCore GitHub Webhook
'''
from __future__ import print_function

import os
import sys
import argparse
import hmac
from json import dumps
from flask import Flask, request, abort
from github import Github
from GetMaintainers import GetMaintainers
from GetMaintainers import ParseMaintainerAddresses
from SendEmails import SendEmails
from FetchPullRequest import FetchPullRequest
from FetchPullRequest import FormatPatch
from FetchPullRequest import FormatPatchSummary

#
# Globals for help information
#
__prog__        = 'TianoCoreGitHubWebHookServer'
__copyright__   = 'Copyright (c) 2020, Intel Corporation. All rights reserved.'
__description__ = 'Assign reviewers to commits in a GitHub pull request based on assignments documented in Maintainers.txt and generate email archive of all review activities.\n'

GITHUB_TOKEN               = os.environ['GITHUB_TOKEN']
GITHUB_WEBHOOK_SECRET      = os.environ['GITHUB_WEBHOOK_SECRET']
GITHUB_WEBHOOK_ROUTE       = os.environ['GITHUB_WEBHOOK_ROUTE']
GITHUB_WEBHOOK_PORT_NUMBER = int(os.environ['GITHUB_WEBHOOK_PORT_NUMBER'])
GITHUB_REPO_WHITE_LIST     = os.environ['GITHUB_REPO_WHITE_LIST']

REVIEW_REQUEST     = '[CodeReview] Review-request @'
REVIEWED_BY        = '[CodeReview] Reviewed-by'
SERIES_REVIEWED_BY = '[CodeReview] Series-reviewed-by'
ACKED_BY           = '[CodeReview] Acked-by'
TESTED_BY          = '[CodeReview] Acked-by'

def UpdatePullRequestCommitReviewers (Commit, GitHubIdList):
    #
    # Retrieve all review comments for this commit
    #
    Body = []
    for Comment in Commit.get_comments():
        Body = Body + [Line.strip() for Line in Comment.body.splitlines()]

    #
    # Determine if any reviewers need to be added to this commit
    #
    AddReviewers = []
    for Reviewer in GitHubIdList:
        if REVIEW_REQUEST + Reviewer not in Body:
            AddReviewers.append(REVIEW_REQUEST + Reviewer + '\n')
    if AddReviewers != []:
        for Reviewer in AddReviewers:
            print ('  ' + '  '.join(AddReviewers))
        #
        # NOTE: This triggers a recursion into this webhook that needs to be
        # ignored
        #
        Commit.create_comment (''.join(AddReviewers))

    #
    # Return True if reviewers were added to this commit
    #
    return AddReviewers != []

def UpdatePullRequestReviewers (Hub, HubPullRequest, PullRequestGitHubIdList):
    #
    # Get list of reviewers already requested for the pull request
    #
    RequestedReviewers = HubPullRequest.get_review_requests()[0]

    #
    # Determine if any reviewers need to be removed
    #
    RemoveReviewerList = []
    for Reviewer in RequestedReviewers:
        if Reviewer.login not in PullRequestGitHubIdList:
            print ('pr[%d]' % (HubPullRequest.number), 'Remove Reviewer    : @' + Reviewer.login)
            RemoveReviewerList.append(Reviewer.login)

    #
    # Determine if any reviewers need to be added
    #
    AddReviewerList = []
    for Login in PullRequestGitHubIdList:
        Reviewer = Hub.get_user(Login)
        if Reviewer == HubPullRequest.user:
            print ('pr[%d]' % (HubPullRequest.number), 'Reviewer is Author : @' + Reviewer.login)
        elif Reviewer not in RequestedReviewers:
            print ('pr[%d]' % (HubPullRequest.number), 'Add Reviewer       : @' + Reviewer.login)
            AddReviewerList.append (Reviewer.login)
        else:
            print ('pr[%d]' % (HubPullRequest.number), 'Already Assigned   : @' + Reviewer.login)

    #
    # Update review requests
    #
    if RemoveReviewerList != []:
        #
        # NOTE: This may trigger recursion into this webhook
        #
        HubPullRequest.delete_review_request (RemoveReviewerList)
    if AddReviewerList != []:
        #
        # NOTE: This may trigger recursion into this webhook
        #
        HubPullRequest.create_review_request (AddReviewerList)

application = Flask(__name__)

@application.route(GITHUB_WEBHOOK_ROUTE, methods=['GET', 'POST'])
def index():
    """
    Main WSGI application entry.
    """
    if args.Verbose:
        print (request.headers)

    # Only POST is implemented
    if request.method != 'POST':
        print (501, "only POST is supported")
        abort(501, "only POST is supported")

    # Enforce secret, so not just anybody can trigger these hooks
    secret = GITHUB_WEBHOOK_SECRET
    if secret:
        # Only SHA1 is supported
        header_signature = request.headers.get('X-Hub-Signature')
        if header_signature is None:
            print (403, "No header signature found")
            abort(403, "No header signature found")

        sha_name, signature = header_signature.split('=')
        if sha_name != 'sha1':
            print(501, "Only SHA1 is supported")
            abort(501, "Only SHA1 is supported")

        # HMAC requires the key to be bytes, but data is string
        mac = hmac.new(bytes(secret, 'utf-8'), msg=request.data, digestmod='sha1')

        # Python does not have hmac.compare_digest prior to 2.7.7
        if sys.hexversion >= 0x020707F0:
            if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
                print(403, "hmac compare digest failed")
                abort(403)
        else:
            # What compare_digest provides is protection against timing
            # attacks; we can live without this protection for a web-based
            # application
            if not str(mac.hexdigest()) == str(signature):
                print(403, "hmac compare digest failed")
                abort(403)

    # Implement ping
    event = request.headers.get('X-GitHub-Event', 'ping')
    if event == 'ping':
        print ('ping request.  respond with pong')
        return dumps({'msg': 'pong'})

    # Implement meta
    if event == 'meta':
        return dumps({'msg': 'meta'})

    # Gather data
    try:
        payload = request.get_json()
    except Exception:
        print(400, "Request parsing failed")
        abort(400, "Request parsing failed")

    # Determining the branch can be tricky, as it only appears for certain event
    # types, and at different levels
    branch = None
    try:
        # Case 1: a ref_type indicates the type of ref.
        # This true for create and delete events.
        if 'ref_type' in payload:
            if payload['ref_type'] == 'branch':
                branch = payload['ref']

        # Case 2: a pull_request object is involved. This is pull_request and
        # pull_request_review_comment events.
        elif 'pull_request' in payload:
            # This is the TARGET branch for the pull-request, not the source
            # branch
            branch = payload['pull_request']['base']['ref']

        elif event in ['push']:
            # Push events provide a full Git ref in 'ref' and not a 'ref_type'.
            branch = payload['ref'].split('/', 2)[2]

    except KeyError:
        # If the payload structure isn't what we expect, we'll live without
        # the branch name
        pass

    #
    # Skip push and create events
    #
    if event in ['push', 'create']:
        print ('skip event', event)
        return dumps({'status': 'skipped'})

    #
    # Skip payload that does not provide a repository
    #
    if 'repository' not in payload:
        print ('skip payload that does not provide a repository', event)
        return dumps({'status': 'skipped'})

    #
    # Skip payload that does not provide a repository full name
    #
    if 'full_name' not in payload['repository']:
        print ('skip payload that does not provide a repository full name', event)
        return dumps({'status': 'skipped'})

    #
    # Skip requests that are not in GITHUB_REPO_WHITE_LIST
    #
    if payload['repository']['full_name'] not in GITHUB_REPO_WHITE_LIST:
        print ('skip event for different repo')
        return dumps({'status': 'skipped'})


    print ('----> Process Event <----', event, payload['action'])

    ############################################################################
    # Process issue comment events
    # These are comments against the entire pull request
    # Quote Patch #0 Body and add comment below below with commenters GitHubID
    ############################################################################
    if event == 'issue_comment':
        action = payload['action']
        if action not in ['created', 'edited']:
            print ('skip issue_comment event with action other than created or edited')
            return dumps({'status': 'skipped'})
        if 'pull_request' not in payload['issue']:
            print ('skip issue_comment event without an associated pull request')
            return dumps({'status': 'skipped'})

        #
        # Use GitHub API to get Pull Request
        #
        try:
            HubRepo = Hub.get_repo (payload['repository']['full_name'])
            HubPullRequest = HubRepo.get_pull(payload['issue']['number'])
        except:
            #
            # Skip requests if the PyGitHub objects can not be retrieved
            #
            print ('skip issue_comment event for which the PyGitHub objects can not be retrieved')
            return dumps({'status': 'skipped'})

        #
        # Skip pull request with a base repo that is different than the expected repo
        #
        if HubPullRequest.base.repo.full_name != HubRepo.full_name:
            print ('Skip PR event against a different repo', HubPullRequest.base.repo.full_name)
            return dumps({'status': 'skipped'})

        #
        # Skip pull requests with a base branch that is not the default branch
        #
        if HubPullRequest.base.ref != HubRepo.default_branch:
            print ('Skip PR event against non-default base branch', HubPullRequest.base.ref)
            return dumps({'status': 'skipped'})

        #
        # Fetch the git commits for the pull request and return a git repo
        # object and the contents of Maintainers.txt
        #
        GitRepo, Maintainers = FetchPullRequest (HubPullRequest)

        #
        # Count head_ref_force_pushed events to determine the version of
        # the patch series.
        #
        PatchSeriesVersion = 1;
        Events = HubPullRequest.get_issue_events()
        for Event in Events:
            if Event.event == 'head_ref_force_pushed':
                PatchSeriesVersion = PatchSeriesVersion + 1;


        PullRequestAddressList = []
        for Commit in HubPullRequest.get_commits():
            #
            # Get list of files modifies by commit from GIT repository
            #
            CommitFiles = GitRepo.commit(Commit.sha).stats.files

            #
            # Get maintainers and reviewers for all files in this commit
            #
            Addresses = GetMaintainers (Maintainers, CommitFiles)
            AddressList, GitHubIdList, EmailList = ParseMaintainerAddresses(Addresses)
            PullRequestAddressList  = list(set(PullRequestAddressList  + AddressList))

        #
        # Generate the summary email patch #0 with body of email prefixed with >.
        #
        Summary = FormatPatchSummary (
                    event,
                    GitRepo,
                    HubRepo,
                    HubPullRequest,
                    PullRequestAddressList,
                    PatchSeriesVersion,
                    CommitRange = HubPullRequest.base.sha + '..' + HubPullRequest.head.sha,
                    CommentId = payload['comment']['id'],
                    CommentPosition = None,
                    CommentPath = None,
                    Prefix = '> '
                    )

        #
        # Send any generated emails
        #
        SendEmails (HubPullRequest, [Summary], args.EmailServer)

        print ('----> Process Event Done <----', event, payload['action'])
        return dumps({'msg': 'issue_comment created or edited'})

    ############################################################################
    # Process commit comment events
    # These are comments against a specific commit
    # Quote Patch #n commit message and add comment below below with commenters GitHubID
    ############################################################################
    if event == 'commit_comment':
        action = payload['action']
        if action not in ['created', 'edited']:
            print ('skip commit_comment event with action other than created or edited')
            return dumps({'status': 'skipped'})

        #
        # Skip REVIEW_REQUEST comments made by the webhook itself.  This same
        # information is always present in the patch emails, so filtering these
        # comments prevent double emails when a pull request is opened or
        # synchronized.
        #
        Body = payload['comment']['body'].splitlines()
        for Line in payload['comment']['body'].splitlines():
            if Line.startswith (REVIEW_REQUEST):
                print ('skip commit_comment event with review request body from this webhook')
                return dumps({'status': 'skipped'})

        #
        # Search for issues/pull requests that contain the comment's commit_id
        #
        CommitId        = payload['comment']['commit_id']
        CommentId       = payload['comment']['id']
        CommentPosition = payload['comment']['position']
        CommentPath     = payload['comment']['path']
        EmailContents   = []
        for Issue in Hub.search_issues('SHA:' + CommitId):
            #
            # Skip Issue for a different repository
            #
            if Issue.repository.full_name != payload['repository']['full_name']:
                print ('Skip commit_comment event against a different repo', HubPullRequest.base.repo.full_name)
                continue

            #
            # Use GitHub API to get Pull Request
            #
            try:
                HubRepo = Issue.repository
                HubPullRequest = Issue.as_pull_request()
            except:
                print ('skip commit_comment event for which the PyGitHub objects can not be retrieved')
                continue

            #
            # Skip commit_comment with a base repo that is different than the expected repo
            #
            if HubPullRequest.base.repo.full_name != HubRepo.full_name:
                print ('Skip commit_comment event against a different repo', HubPullRequest.base.repo.full_name)
                continue

            #
            # Skip commit_comment with a base branch that is not the default branch
            #
            if HubPullRequest.base.ref != HubRepo.default_branch:
                print ('Skip commit_comment event against non-default base branch', HubPullRequest.base.ref)
                continue

            #
            # Fetch the git commits for the pull request and return a git repo
            # object and the contents of Maintainers.txt
            #
            GitRepo, Maintainers = FetchPullRequest (HubPullRequest)

            #
            # Count head_ref_force_pushed events to determine the version of
            # the patch series.
            #
            PatchSeriesVersion = 1;
            Events = HubPullRequest.get_issue_events()
            for Event in Events:
                if Event.event == 'head_ref_force_pushed':
                    PatchSeriesVersion = PatchSeriesVersion + 1;

            #
            # Determine the patch number of the commit with the comment
            #
            PatchNumber = 0
            for Commit in HubPullRequest.get_commits():
                PatchNumber = PatchNumber + 1
                if Commit.sha == CommitId:
                    break

            #
            # Get commit from GIT repository
            #
            CommitFiles = GitRepo.commit(Commit.sha).stats.files

            #
            # Get maintainers and reviewers for all files in this commit
            #
            Addresses = GetMaintainers (Maintainers, CommitFiles)
            AddressList, GitHubIdList, EmailList = ParseMaintainerAddresses(Addresses)

            Email = FormatPatch (
                        event,
                        GitRepo,
                        HubRepo,
                        HubPullRequest,
                        Commit,
                        AddressList,
                        PatchSeriesVersion,
                        PatchNumber,
                        CommentId = CommentId,
                        CommentPosition = CommentPosition,
                        CommentPath = CommentPath,
                        Prefix = '> '
                        )

            EmailContents.append (Email)

        if EmailContents == []:
            print ('skip commit_comment that is not for any supported repo')
            return dumps({'status': 'skipped'})

        #
        # Send any generated emails
        #
        SendEmails (HubPullRequest, EmailContents, args.EmailServer)

        print ('----> Process Event Done <----', event, payload['action'])
        return dumps({'msg': 'commit_comment created or edited'})

    ############################################################################
    # Process pull_request_review_comment events
    # Quote Patch #n commit message and add comment below below with commenters GitHubID
    ############################################################################
    if event == 'pull_request_review_comment':
        action = payload['action']
        if action not in ['created', 'edited']:
            print ('skip pull_request_review_comment event with action other than created or edited')
            return dumps({'status': 'skipped'})

        #
        # Skip REVIEW_REQUEST comments made by the webhook itself.  This same
        # information is always present in the patch emails, so filtering these
        # comments prevent double emails when a pull request is opened or
        # synchronized.
        #
        Body = payload['comment']['body'].splitlines()
        for Line in payload['comment']['body'].splitlines():
            if Line.startswith (REVIEW_REQUEST):
                print ('skip pull_request_review_comment event with review request body from this webhook')
                return dumps({'status': 'skipped'})

        CommitId           = payload['comment']['commit_id']
        CommentId          = payload['comment']['id']
        CommentPosition    = payload['comment']['position']
        CommentPath        = payload['comment']['path']
        CommentInReplyToId = None
        if 'in_reply_to_id' in payload['comment']:
            CommentInReplyToId = payload['comment']['in_reply_to_id']

        EmailContents   = []

        #
        # Use GitHub API to get Pull Request
        #
        try:
            HubRepo = Hub.get_repo (payload['repository']['full_name'])
            HubPullRequest = HubRepo.get_pull(payload['pull_request']['number'])
        except:
            print ('skip pull_request_review_comment event for which the PyGitHub objects can not be retrieved')
            return dumps({'status': 'skipped'})

        #
        # Skip pull_request_review_comment with a base repo that is different than the expected repo
        #
        if HubPullRequest.base.repo.full_name != HubRepo.full_name:
            print ('Skip pull_request_review_comment event against a different repo', HubPullRequest.base.repo.full_name)
            return dumps({'status': 'skipped'})

        #
        # Skip pull_request_review_comment with a base branch that is not the default branch
        #
        if HubPullRequest.base.ref != HubRepo.default_branch:
            print ('Skip pull_request_review_comment event against non-default base branch', HubPullRequest.base.ref)
            return dumps({'status': 'skipped'})

        #
        # Fetch the git commits for the pull request and return a git repo
        # object and the contents of Maintainers.txt
        #
        GitRepo, Maintainers = FetchPullRequest (HubPullRequest)

        #
        # Count head_ref_force_pushed events to determine the version of
        # the patch series.
        #
        PatchSeriesVersion = 1;
        Events = HubPullRequest.get_issue_events()
        for Event in Events:
            if Event.event == 'head_ref_force_pushed':
                PatchSeriesVersion = PatchSeriesVersion + 1;

        #
        # All pull request review comments are against patch #0
        #
        PatchNumber = 0

        #
        # Build dictionary of files in range of commits from the pull request
        # base sha up to the commit id of the pull request review comment.
        #
        CommitFiles = {}
        for Commit in HubPullRequest.get_commits():
            CommitFiles.update (GitRepo.commit(Commit.sha).stats.files)
            if Commit.sha == CommitId:
                break

        #
        # Get maintainers and reviewers for all files in this commit
        #
        Addresses = GetMaintainers (Maintainers, CommitFiles)
        AddressList, GitHubIdList, EmailList = ParseMaintainerAddresses(Addresses)

        #
        # Generate the summary email patch #0 with body of email prefixed with >.
        #
        Email = FormatPatchSummary (
                  event,
                  GitRepo,
                  HubRepo,
                  HubPullRequest,
                  AddressList,
                  PatchSeriesVersion,
                  CommitRange = HubPullRequest.base.sha + '..' + CommitId,
                  CommentId = CommentId,
                  CommentPosition = CommentPosition,
                  CommentPath = CommentPath,
                  Prefix = '> ',
                  CommentInReplyToId = CommentInReplyToId
                  )

        EmailContents.append (Email)

        #
        # Send any generated emails
        #
        SendEmails (HubPullRequest, EmailContents, args.EmailServer)

        print ('----> Process Event Done <----', event, payload['action'])
        return dumps({'msg': 'pull_request_review_comment created or edited'})

    ############################################################################
    # Process pull request events
    ############################################################################
    if event == 'pull_request':
        action = payload['action']
        if action not in ['opened', 'synchronize']:
            print ('skip pull_request event with action other than opened or synchronized')
            return dumps({'status': 'skipped'})

        #
        # Use GitHub API to get Pull Request
        #
        try:
            HubRepo = Hub.get_repo (payload['repository']['full_name'])
            HubPullRequest = HubRepo.get_pull(payload['pull_request']['number'])
        except:
            #
            # Skip requests if the PyGitHub objects can not be retrieved
            #
            print ('skip pull_request event for which the PyGitHub objects can not be retrieved')
            return dumps({'status': 'skipped'})

        #
        # Skip pull request with a base repo that is different than the expected repo
        #
        if HubPullRequest.base.repo.full_name != HubRepo.full_name:
            print ('Skip PR event against a different repo', HubPullRequest.base.repo.full_name)
            return dumps({'status': 'skipped'})

        #
        # Skip pull requests with a base branch that is not the default branch
        #
        if HubPullRequest.base.ref != HubRepo.default_branch:
            print ('Skip PR event against non-default base branch', HubPullRequest.base.ref)
            return dumps({'status': 'skipped'})

        #
        # Fetch the git commits for the pull request and return a git repo
        # object and the contents of Maintainers.txt
        #
        GitRepo, Maintainers = FetchPullRequest (HubPullRequest)

        NewPatchSeries = False
        PatchSeriesVersion = 1;
        if action == 'opened':
            #
            # New pull request was created
            #
            NewPatchSeries = True
        if action == 'synchronize':
            #
            # Existing pull request was updated.
            # Commits were added to an existing pull request or an existing pull
            # request was forced push.  Get events to determine what happened
            #
            Events = HubPullRequest.get_issue_events()
            for Event in Events:
                #
                # Count head_ref_force_pushed events to determine the version of
                # the patch series.
                #
                if Event.event == 'head_ref_force_pushed':
                    PatchSeriesVersion = PatchSeriesVersion + 1;
                    #
                    # If the head_ref_force_pushed event occurred at the exact
                    # same date/time (or within 2 seconds) that the pull request
                    # was updated, then this was a forced push and the entire
                    # patch series should be emailed again.
                    #
                    if abs(Event.created_at - HubPullRequest.updated_at).seconds <= 2:
                        NewPatchSeries = True

        PullRequestAddressList = []
        PullRequestGitHubIdList = []
        PullRequestEmailList = []
        EmailContents = []
        PatchNumber = 0
        for Commit in HubPullRequest.get_commits():

            PatchNumber = PatchNumber + 1

            #
            # Get list of files modified by commit from GIT repository
            #
            CommitFiles = GitRepo.commit(Commit.sha).stats.files

            #
            # Get maintainers and reviewers for all files in this commit
            #
            Addresses = GetMaintainers (Maintainers, CommitFiles)
            AddressList, GitHubIdList, EmailList = ParseMaintainerAddresses(Addresses)
            PullRequestAddressList  = list(set(PullRequestAddressList  + AddressList))
            PullRequestGitHubIdList = list(set(PullRequestGitHubIdList + GitHubIdList))
            PullRequestEmailList    = list(set(PullRequestEmailList    + EmailList))

            print ('pr[%d]' % (HubPullRequest.number), Commit.sha, ' @' + ' @'.join(PullRequestGitHubIdList))

            #
            # Update the list of required reviewers for this commit
            #
            ReviewersUpdated = UpdatePullRequestCommitReviewers (Commit, GitHubIdList)

            #
            # Generate email contents for all commits in a pull request if this is
            # a new pull request or a forced push was done to an existing pull request.
            # Generate email contents for patches that add new reviewers.  This
            # occurs when when new commits are added to an existing pull request.
            #
            if NewPatchSeries or ReviewersUpdated:
                Email = FormatPatch (event, GitRepo, HubRepo, HubPullRequest, Commit, AddressList, PatchSeriesVersion, PatchNumber)
                EmailContents.append (Email)

        #
        # Update the list of required reviewers for the pull request
        #
        UpdatePullRequestReviewers (Hub, HubPullRequest, PullRequestGitHubIdList)

        #
        # If this is a new pull request or a forced push on a pull request, then
        # generate the summary email patch #0 and add to be beginning of the
        # list of emails to send.
        #
        if NewPatchSeries:
            Summary = FormatPatchSummary (
                          event,
                          GitRepo,
                          HubRepo,
                          HubPullRequest,
                          PullRequestAddressList,
                          PatchSeriesVersion
                          )
            EmailContents.insert (0, Summary)

        #
        # Send any generated emails
        #
        SendEmails (HubPullRequest, EmailContents, args.EmailServer)

        print ('----> Process Event Done <----', event, payload['action'])
        return dumps({'msg': 'pull_request opened or synchronize'})

    print ('skip unsupported event')
    return dumps({'status': 'skipped'})

if __name__ == '__main__':
    #
    # Create command line argument parser object
    #
    parser = argparse.ArgumentParser (prog = __prog__,
                                      description = __description__ + __copyright__,
                                      conflict_handler = 'resolve')
    parser.add_argument ("-e", "--email-server", dest = 'EmailServer', choices = ['Off', 'SMTP', 'SendGrid'], default = 'Off',
                         help = "Email server type used to send emails.")
    parser.add_argument ("-v", "--verbose", dest = 'Verbose', action = "store_true",
                         help = "Increase output messages")
    parser.add_argument ("-q", "--quiet", dest = 'Quiet', action = "store_true",
                         help = "Reduce output messages")
    parser.add_argument ("--debug", dest = 'Debug', type = int, metavar = '[0-9]', choices = range (0, 10), default = 0,
                         help = "Set debug level")

    #
    # Parse command line arguments
    #
    args = parser.parse_args ()

    #
    # Create GitHub object authenticated using GitHub Token for the webhook
    #
    try:
        Hub = Github (GITHUB_TOKEN)
    except:
        print ('can not access GitHub APIs')
        sys.exit(1)

    try:
        application.run(debug=False, host='localhost', port=GITHUB_WEBHOOK_PORT_NUMBER, threaded=False)
    except:
        print ('can not create listener for GitHub HTTP requests')
        sys.exit(1)
