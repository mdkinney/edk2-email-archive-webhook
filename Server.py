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

import sys
import hmac
import datetime
from json import dumps
from flask import request, abort
from github import Github
from GetMaintainers import GetMaintainers
from GetMaintainers import ParseMaintainerAddresses
from SendEmails import SendEmails
from FetchPullRequest import FetchPullRequest
from FetchPullRequest import FormatPatch
from FetchPullRequest import FormatPatchSummary
from Models import LogTypeEnum

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
        if Comment.body is not None:
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

def UpdatePullRequestReviewers (Hub, HubRepo, HubPullRequest, PullRequestGitHubIdList):
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
    Collaborators = HubRepo.get_collaborators()
    for Login in PullRequestGitHubIdList:
        Reviewer = Hub.get_user(Login)
        if Reviewer == HubPullRequest.user:
            print ('pr[%d]' % (HubPullRequest.number), 'Reviewer is Author : @' + Reviewer.login)
        elif Reviewer not in RequestedReviewers:
            if Reviewer in Collaborators:
                print ('pr[%d]' % (HubPullRequest.number), 'Add Reviewer       : @' + Reviewer.login)
                AddReviewerList.append (Reviewer.login)
            else:
                print ('pr[%d]' % (HubPullRequest.number), 'Reviewer is not a collaborator : @' + Reviewer.login)
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

def GetReviewComments(Comment, ReviewComments, CommentIdDict):
    if Comment in ReviewComments:
        return
    ReviewComments.append(Comment)
    #
    # Add peer comments
    #
    if Comment.pull_request_review_id:
        for PeerComment in CommentIdDict.values():
            if PeerComment.pull_request_review_id == Comment.pull_request_review_id:
                GetReviewComments (PeerComment, ReviewComments, CommentIdDict)
    #
    # Add child comments
    #
    for ChildComment in CommentIdDict.values():
        if ChildComment.in_reply_to_id == Comment.id:
            GetReviewComments (ChildComment, ReviewComments, CommentIdDict)
    #
    # Add parent comment
    #
    if Comment.in_reply_to_id and Comment.in_reply_to_id in CommentIdDict:
        ParentComment = CommentIdDict[Comment.in_reply_to_id]
        GetReviewComments (ParentComment, ReviewComments, CommentIdDict)

def GetReviewCommentsFromReview(Review, CommentId, CommentInReplyToId, CommentIdDict):
    ReviewComments = []
    for Comment in CommentIdDict.values():
        if Review:
            if Comment.pull_request_review_id == Review.id:
                GetReviewComments (Comment, ReviewComments, CommentIdDict)
        if CommentId:
            if Comment.in_reply_to_id == CommentId:
                GetReviewComments (Comment, ReviewComments, CommentIdDict)
        if CommentInReplyToId:
            if Comment.id == CommentInReplyToId:
                GetReviewComments (Comment, ReviewComments, CommentIdDict)
    return ReviewComments

def ProcessGithubRequest(app, webhookconfiguration):
    GITHUB_TOKEN           = webhookconfiguration.GithubToken
    GITHUB_WEBHOOK_SECRET  = webhookconfiguration.GithubWebhookSecret
    GITHUB_REPO_WHITE_LIST = [webhookconfiguration.GithubOrgName + '/' + webhookconfiguration.GithubRepoName]
    EmailArchiveAddress    = webhookconfiguration.EmailArchiveAddress
    SendEmailEnabled       = webhookconfiguration.SendEmail

    webhookconfiguration.AddLogEntry (LogTypeEnum.Request, str(request.headers))

    # Only POST is implemented
    if request.method != 'POST':
        print (501, "only POST is supported")
        abort(501, "only POST is supported")

    # Enforce secret, so not just anybody can trigger these hooks
    secret = GITHUB_WEBHOOK_SECRET
    if secret:
        # Check for SHA256 signature
        header_signature = request.headers.get('X-Hub-Signature-256')
        if header_signature is None:
            # Check for SHA1 signature
            header_signature = request.headers.get('X-Hub-Signature')
            if header_signature is None:
                print (403, "No header signature found")
                abort(403, "No header signature found")

        sha_name, signature = header_signature.split('=')
        if sha_name not in ['sha256', 'sha1']:
            print(501, "Only SHA256 and SHA1 are supported")
            abort(501, "Only SHA256 and SHA1 are supported")

        # HMAC requires the key to be bytes, but data is string
        mac = hmac.new(bytes(secret, 'utf-8'), msg=request.get_data(), digestmod=sha_name)

        # Python does not have hmac.compare_digest prior to 2.7.7
        if sys.hexversion >= 0x020707F0:
            if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
                print(403, "hmac compare digest failed")
                abort(403, "hmac compare digest failed")
        else:
            # What compare_digest provides is protection against timing
            # attacks; we can live without this protection for a web-based
            # application
            if not str(mac.hexdigest()) == str(signature):
                print(403, "hmac compare digest failed")
                abort(403, "hmac compare digest failed")

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

    webhookconfiguration.AddLogEntry (LogTypeEnum.Payload, dumps(payload, indent=2))

    #
    # Skip push and create events
    #
    if event in ['push', 'create']:
        print ('skip event', event)
        return dumps({'status': 'skipped'})

    #
    # Skip payload that does not provide an action
    #
    if 'action' not in payload:
        print ('skip payload that does not provide an action.  event =', event)
        return dumps({'status': 'skipped'})

    #
    # Skip payload that does not provide a repository
    #
    if 'repository' not in payload:
        print ('skip payload that does not provide a repository.  event=', event)
        return dumps({'status': 'skipped'})

    #
    # Skip payload that does not provide a repository full name
    #
    if 'full_name' not in payload['repository']:
        print ('skip payload that does not provide a repository full name.  event=', event)
        return dumps({'status': 'skipped'})

    #
    # Skip requests that are not in GITHUB_REPO_WHITE_LIST
    #
    if payload['repository']['full_name'] not in GITHUB_REPO_WHITE_LIST:
        print ('skip event for different repo')
        return dumps({'status': 'skipped'})

    #
    # Retrieve Hub object for this repo
    #
    try:
        Hub = Github (GITHUB_TOKEN)
    except:
        print(400, "Invalid GITHUB_TOKEN")
        abort(400, "Invalid GITHUB_TOKEN")

    print ('----> Process Event <----', event, payload['action'])

    ############################################################################
    # Process issue comment events
    # These are comments against the entire pull request
    # Quote Patch #0 Body and add comment below below with commenters GitHubID
    ############################################################################
    if event == 'issue_comment':
        action = payload['action']
        if action not in ['created', 'edited', 'deleted']:
            return dumps({'status': 'ignore issue_comment event with action other than created or edited'})
        if 'pull_request' not in payload['issue']:
            return dumps({'status': 'ignore issue_comment event without an associated pull request'})

        #
        # Use GitHub API to get Pull Request
        #
        try:
            HubRepo = Hub.get_repo (payload['repository']['full_name'])
            HubPullRequest = HubRepo.get_pull(payload['issue']['number'])
        except:
            raise
            #
            # Skip requests if the PyGitHub objects can not be retrieved
            #
            return dumps({'status': 'ignore issue_comment event for which the PyGitHub objects can not be retrieved'})

        #
        # Skip pull request that is not open
        #
        if HubPullRequest.state != 'open':
            return dumps({'status': 'ignore issue_comment event against a pull request that is not open'})

        #
        # Skip pull request with a base repo that is different than the expected repo
        #
        if HubPullRequest.base.repo.full_name != HubRepo.full_name:
            print ('Skip issue_comment event against a different repo', HubPullRequest.base.repo.full_name)
            return dumps({'status': 'skipped'})

        #
        # Skip pull requests with a base branch that is not the default branch
        #
        if HubPullRequest.base.ref != HubRepo.default_branch:
            print ('Skip issue_comment event against non-default base branch', HubPullRequest.base.ref)
            return dumps({'status': 'skipped'})

        #
        # Fetch the git commits for the pull request and return a git repo
        # object and the contents of Maintainers.txt
        #
        GitRepo, Maintainers = FetchPullRequest (HubPullRequest)
        if GitRepo is None or Maintainers is None:
            print ('Skip issue_comment event that can not be fetched')
            return dumps({'status': 'skipped'})

        #
        # Count head_ref_force_pushed and reopened events to determine the
        # version of the patch series.
        #
        PatchSeriesVersion = 1;
        Events = HubPullRequest.get_issue_events()
        for Event in Events:
            if Event.event in ['head_ref_force_pushed', 'reopened']:
                PatchSeriesVersion = PatchSeriesVersion + 1;


        PullRequestAddressList = []
        CommitShaList = []
        for Commit in HubPullRequest.get_commits():
            CommitShaList.append(Commit.sha)
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

        #
        # Generate the summary email patch #0 with body of email prefixed with >.
        #
        UpdateDeltaTime = 0
        if action == 'edited':
            #
            # The delta time is the number of seconds from the time the comment
            # was created to the time the comment was edited
            #
            UpdatedAt = datetime.datetime.strptime(payload['comment']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
            CreatedAt = datetime.datetime.strptime(payload['comment']['created_at'], "%Y-%m-%dT%H:%M:%SZ")
            UpdateDeltaTime = (UpdatedAt - CreatedAt).seconds
        if action == 'deleted':
            UpdateDeltaTime = -1
        Summary = FormatPatchSummary (
                    EmailArchiveAddress,
                    event,
                    GitRepo,
                    HubRepo,
                    HubPullRequest,
                    PullRequestAddressList,
                    PatchSeriesVersion,
                    CommitRange = CommitShaList[0] + '..' + CommitShaList[-1],
                    CommentUser = payload['comment']['user']['login'],
                    CommentId = payload['comment']['id'],
                    CommentPosition = None,
                    CommentPath = None,
                    Prefix = '> ',
                    UpdateDeltaTime = UpdateDeltaTime
                    )

        #
        # Send any generated emails
        #
        SendEmails (HubPullRequest, [Summary], SendEmailEnabled, app)

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
            # Skip pull request that is not open
            #
            if HubPullRequest.state != 'open':
                print ('Skip commit_comment event against a pull request that is not open')
                return dumps({'status': 'skipped'})

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
            if GitRepo is None or Maintainers is None:
                print ('Skip commit_comment event that can not be fetched')
                continue

            #
            # Count head_ref_force_pushed and reopened events to determine the
            # version of the patch series.
            #
            PatchSeriesVersion = 1;
            Events = HubPullRequest.get_issue_events()
            for Event in Events:
                if Event.event in ['head_ref_force_pushed', 'reopened']:
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
                        EmailArchiveAddress,
                        event,
                        GitRepo,
                        HubRepo,
                        HubPullRequest,
                        Commit,
                        AddressList,
                        PatchSeriesVersion,
                        PatchNumber,
                        CommentUser = payload['comment']['user']['login'],
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
        SendEmails (HubPullRequest, EmailContents, SendEmailEnabled, app)

        print ('----> Process Event Done <----', event, payload['action'])
        return dumps({'msg': 'commit_comment created or edited'})

    ############################################################################
    # Process pull_request_review_comment and pull_request_review events
    # Quote Patch #0 commit message and patch diff of file comment is against
    ############################################################################
    if event in ['pull_request_review_comment', 'pull_request_review']:
        action = payload['action']
        Review = None
        ReviewComments = []
        DeleteId = None
        ParentReviewId = None
        UpdateDeltaTime = 0
        if event in ['pull_request_review_comment']:
            if action not in ['edited', 'deleted']:
                print ('skip pull_request_review_comment event with action other than edited or deleted')
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

        if event in ['pull_request_review']:
            if action not in ['submitted', 'edited']:
                print ('skip pull_request_review event with action other than submitted or edited')
                return dumps({'status': 'skipped'})
            if action == 'edited' and payload['changes'] == {}:
                print ('skip pull_request_review event edited action that has no changes')
                return dumps({'status': 'skipped'})

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
        # Skip pull request that is not open
        #
        if HubPullRequest.state != 'open':
            print ('Skip pull_request_review_comment event against a pull request that is not open')
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
        # Build dictionary of review comments
        #
        CommentIdDict = {}
        for Comment in HubPullRequest.get_review_comments():
            Comment.pull_request_review_id = None
            if 'pull_request_review_id' in Comment.raw_data:
                Comment.pull_request_review_id = Comment.raw_data['pull_request_review_id']
            CommentIdDict[Comment.id] = Comment

        #
        # Determine if review has a parent review, is being deleted, or has
        # an update time.
        #
        if event in ['pull_request_review']:
            CommitId           = payload['review']['commit_id']
            CommentUser        = payload['review']['user']['login'],
            CommentId          = None
            CommentPosition    = None
            CommentPath        = None
            CommentInReplyToId = None
            ReviewId           = payload['review']['id']
            try:
                Review = HubPullRequest.get_review(ReviewId)
            except:
                Review = None
            ReviewComments = GetReviewCommentsFromReview(Review, CommentId, CommentInReplyToId, CommentIdDict)
            if payload['action'] == 'submitted':
                UpdateDeltaTime = 0
                for ReviewComment in ReviewComments:
                    if ReviewComment.pull_request_review_id == ReviewId:
                        if ReviewComment.in_reply_to_id and ReviewComment.in_reply_to_id in CommentIdDict:
                            ParentReviewId = CommentIdDict[ReviewComment.in_reply_to_id].pull_request_review_id
                            if ParentReviewId and ParentReviewId != ReviewId:
                                break
            if payload['action'] == 'edited' and Review:
                UpdatedAt = datetime.datetime.strptime(payload['pull_request']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
                UpdateDeltaTime = (UpdatedAt - Review.submitted_at).seconds
        if event in ['pull_request_review_comment']:
            CommitId           = payload['comment']['commit_id']
            CommentId          = payload['comment']['id']
            CommentUser        = payload['comment']['user']['login'],
            CommentPosition    = payload['comment']['position']
            CommentPath        = payload['comment']['path']
            CommentInReplyToId = None
            ReviewId           = None
            if 'in_reply_to_id' in payload['comment']:
                CommentInReplyToId = payload['comment']['in_reply_to_id']
            if 'pull_request_review_id' in payload['comment']:
                ReviewId = payload['comment']['pull_request_review_id']
                try:
                    Review = HubPullRequest.get_review(ReviewId)
                except:
                    Review = None
            ReviewComments = GetReviewCommentsFromReview(Review, CommentId, CommentInReplyToId, CommentIdDict)
            if payload['action'] == 'deleted':
                UpdateDeltaTime = 0
                DeleteId = payload['comment']['id']
            if payload['action'] == 'edited' and Review:
                UpdatedAt = datetime.datetime.strptime(payload['comment']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
                UpdateDeltaTime = (UpdatedAt - Review.submitted_at).seconds

        #
        # Fetch the git commits for the pull request and return a git repo
        # object and the contents of Maintainers.txt
        #
        GitRepo, Maintainers = FetchPullRequest (HubPullRequest)
        if GitRepo is None or Maintainers is None:
            print ('Skip pull_request_review_comment event that can not be fetched')
            return dumps({'status': 'skipped'})

        #
        # Count head_ref_force_pushed and reopened events to determine the
        # version of the patch series.
        #
        PatchSeriesVersion = 1;
        Events = HubPullRequest.get_issue_events()
        for Event in Events:
            if Event.event in ['head_ref_force_pushed', 'reopened']:
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
        CommitShaList = []
        for Commit in HubPullRequest.get_commits():
            CommitShaList.append (Commit.sha)
            CommitFiles.update (GitRepo.commit(Commit.sha).stats.files)

        #
        # Get maintainers and reviewers for all files in this commit
        #
        Addresses = GetMaintainers (Maintainers, CommitFiles)
        AddressList, GitHubIdList, EmailList = ParseMaintainerAddresses(Addresses)

        #
        # Generate the summary email patch #0 with body of email prefixed with >.
        #
        Email = FormatPatchSummary (
                  EmailArchiveAddress,
                  event,
                  GitRepo,
                  HubRepo,
                  HubPullRequest,
                  AddressList,
                  PatchSeriesVersion,
                  CommitRange = CommitShaList[0] + '..' + CommitShaList[-1],
                  CommentUser = CommentUser,
                  CommentId = CommentId,
                  CommentPosition = CommentPosition,
                  CommentPath = CommentPath,
                  Prefix = '> ',
                  CommentInReplyToId = CommentInReplyToId,
                  UpdateDeltaTime = UpdateDeltaTime,
                  Review = Review,
                  ReviewId = ReviewId,
                  ReviewComments = ReviewComments,
                  DeleteId = DeleteId,
                  ParentReviewId = ParentReviewId
                  )

        EmailContents.append (Email)

        #
        # Send any generated emails
        #
        SendEmails (HubPullRequest, EmailContents, SendEmailEnabled, app)

        print ('----> Process Event Done <----', event, payload['action'])
        return dumps({'msg': event + ' created or edited or deleted'})

    ############################################################################
    # Process pull request events
    ############################################################################
    if event == 'pull_request':
        action = payload['action']
        if action not in ['opened', 'synchronize', 'edited', 'closed', 'reopened']:
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
        # Skip pull request that is not open unless this is the event that is
        # closing the pull request
        #
        if action != 'closed':
            if HubPullRequest.state != 'open':
                print ('Skip pull_request event against a pull request that is not open')
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
        if GitRepo is None or Maintainers is None:
            print ('Skip pull_request_review event that can not be fetched')
            return dumps({'status': 'skipped'})

        NewPatchSeries = False
        PatchSeriesVersion = 1;
        if action in ['opened', 'reopened']:
            #
            # New pull request was created
            #
            NewPatchSeries = True
        if action in ['synchronize', 'edited', 'closed', 'reopened']:
            #
            # Existing pull request was updated.
            # Commits were added to an existing pull request or an existing pull
            # request was forced push.  Get events to determine what happened
            #
            Events = HubPullRequest.get_issue_events()
            for Event in Events:
                #
                # Count head_ref_force_pushed and reopened events to determine
                # the version of the patch series.
                #
                if Event.event in  ['head_ref_force_pushed', 'reopened']:
                    PatchSeriesVersion = PatchSeriesVersion + 1;
                if Event.event in  ['head_ref_force_pushed']:
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

            if action in ['opened', 'synchronize', 'reopened']:

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
                    Email = FormatPatch (
                                EmailArchiveAddress,
                                event,
                                GitRepo,
                                HubRepo,
                                HubPullRequest,
                                Commit,
                                AddressList,
                                PatchSeriesVersion,
                                PatchNumber
                                )
                    EmailContents.append (Email)

        if action in ['opened', 'synchronize', 'reopened']:
            #
            # Update the list of required reviewers for the pull request
            #
            UpdatePullRequestReviewers (Hub, HubRepo, HubPullRequest, PullRequestGitHubIdList)

        #
        # If this is a new pull request or a forced push on a pull request or an
        # edit of the pulle request title or description, then generate the
        # summary email patch #0 and add to be beginning of the list of emails
        # to send.
        #
        if NewPatchSeries or action in ['edited', 'closed']:
            UpdateDeltaTime = 0
            if action in ['edited', 'closed']:
                UpdateDeltaTime = (HubPullRequest.updated_at - HubPullRequest.created_at).seconds
            Summary = FormatPatchSummary (
                          EmailArchiveAddress,
                          event,
                          GitRepo,
                          HubRepo,
                          HubPullRequest,
                          PullRequestAddressList,
                          PatchSeriesVersion,
                          UpdateDeltaTime = UpdateDeltaTime
                          )
            EmailContents.insert (0, Summary)
        #
        # Send any generated emails
        #
        SendEmails (HubPullRequest, EmailContents, SendEmailEnabled, app)

        print ('----> Process Event Done <----', event, payload['action'])
        return dumps({'msg': 'pull_request opened or synchronize'})

    print ('skip unsupported event')
    return dumps({'status': 'skipped'})
