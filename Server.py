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
TESTED_BY          = '[CodeReview] Tested-by'

def UpdatePullRequestCommitReviewers (Commit, GitHubIdList, eventlog):
    # Retrieve all review comments for this commit
    Body = []
    for Comment in Commit.get_comments():
        if Comment.body is not None:
            Body = Body + [Line.strip() for Line in Comment.body.splitlines()]
    # Determine if any reviewers need to be added to this commit
    Message = ''
    AddReviewers = []
    for Reviewer in GitHubIdList:
        Message = Message + REVIEW_REQUEST + Reviewer
        if REVIEW_REQUEST + Reviewer not in Body:
            AddReviewers.append(REVIEW_REQUEST + Reviewer + '\n')
            Message = Message + 'ADD'
        Message = Message + '\n'
    if AddReviewers != []:
        # NOTE: This triggers a recursion into this webhook that needs to be
        # ignored
        Commit.create_comment (''.join(AddReviewers))
        # Add reviewers to the log
        eventlog.AddLogEntry (LogTypeEnum.Message, 'Commit Reviewers', Message)
    # Return True if reviewers were added to this commit
    return AddReviewers != []

def UpdatePullRequestReviewers (Hub, HubRepo, HubPullRequest, PullRequestGitHubIdList, eventlog):
    Message = ''
    # Get list of collaborators for this repository
    Collaborators = HubRepo.get_collaborators()
    # Get list of reviewers already requested for the pull request
    RequestedReviewers = HubPullRequest.get_review_requests()[0]
    # Determine if any reviewers need to be removed
    RemoveReviewerList = []
    for Reviewer in RequestedReviewers:
        if Reviewer.login not in PullRequestGitHubIdList:
            # Remove assigned reviewer that no longer required.
            # Occurs if files/packages are removed from the PR that no longer
            # require a specific reviewer. Can also occur if Maintainers.txt
            # is updated with new maintainer/reviewer assignments.
            RemoveReviewerList.append(Reviewer.login)
            Message = Message + 'REMOVE REVIEWER  : ' + Reviewer.login + '\n'
            continue
        if Reviewer == HubPullRequest.user:
            # Author of PR can not be reviewer of PR
            # Should never occur
            RemoveReviewerList.append(Reviewer.login)
            Message = Message + 'REMOVE AUTHOR     : ' + Reviewer.login + '\n'
            continue
        if Reviewer not in Collaborators:
            # Reviewer of PR must be a member of repository collborators.
            # Occurs if reviewer was previously assigned as a collborator, but
            # was later removed from the list of collborators.
            Message = Message + 'NOT A COLLABORATOR: ' + Reviewer.login + '\n'
            continue
    # Determine if any reviewers need to be added
    AddReviewerList = []
    for Login in PullRequestGitHubIdList:
        Reviewer = Hub.get_user(Login)
        if Reviewer == HubPullRequest.user:
            # Author of PR can not be reviewer of PR
            Message = Message + 'AUTHOR            : ' + Reviewer.login + '\n'
            continue
        if Reviewer in RequestedReviewers:
            # Reviewer is already in set of requested reviewers for this PR
            Message = Message + 'ALREADY ASSIGNED  : ' + Reviewer.login + '\n'
            continue
        if Reviewer not in Collaborators:
            # Reviewer of PR must be a member of repository collborators
            # Only occurs if reviewer is present in Maintainers.txt, but is
            # not a GitHub maintainer for the repository.
            Message = Message + 'NOT A COLLABORATOR: ' + Reviewer.login + '\n'
            continue
        AddReviewerList.append (Reviewer.login)
        Message = Message + 'ADD REVIEWER     : ' + Reviewer.login + '\n'
    # Update review requests
    if RemoveReviewerList != []:
        # NOTE: This may trigger recursion into this webhook
        HubPullRequest.delete_review_request (RemoveReviewerList)
    if AddReviewerList != []:
        # NOTE: This may trigger recursion into this webhook
        HubPullRequest.create_review_request (AddReviewerList)
    # Log reviewer updates
    eventlog.AddLogEntry (LogTypeEnum.Message, 'PR[%d] Update Reviewers' % (HubPullRequest.number), Message)

def GetReviewComments(Comment, ReviewComments, CommentIdDict):
    if Comment in ReviewComments:
        return
    ReviewComments.append(Comment)
    # Add peer comments
    if Comment.pull_request_review_id:
        for PeerComment in CommentIdDict.values():
            if PeerComment.pull_request_review_id == Comment.pull_request_review_id:
                GetReviewComments (PeerComment, ReviewComments, CommentIdDict)
    # Add child comments
    for ChildComment in CommentIdDict.values():
        if ChildComment.in_reply_to_id == Comment.id:
            GetReviewComments (ChildComment, ReviewComments, CommentIdDict)
    # Add parent comment
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

def AuthenticateGithubRequestHeader(app, webhookconfiguration, eventlog):
    # Only POST is supported
    if request.method != 'POST':
        abort(501, 'only POST is supported')

    # Enforce secret, so not just anybody can trigger these hooks
    if webhookconfiguration.GithubWebhookSecret:
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
        mac = hmac.new(bytes(webhookconfiguration.GithubWebhookSecret, 'utf-8'), msg=request.get_data(), digestmod=sha_name)

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
    # Add request headers to the log
    # Delayed to this point to prevent logging rejected requests
    eventlog.AddLogEntry (LogTypeEnum.Request, request.headers.get('X-GitHub-Event', 'ping'), str(request.headers))

def VerifyPayload(event, eventlog, webhookconfiguration):
    # If event is ping, then generate a pong response
    if event == 'ping':
        return None, None, 200, 'pong'
    # If event is meta, then generate a meta response
    if event == 'meta':
        return None, None, 200, 'meta'
    # Parse request payload as json
    try:
        payload = request.get_json()
    except Exception:
        abort(400, 'Request parsing failed')
    # Add payload to the log
    if 'action' in payload:
        eventlog.AddLogEntry (LogTypeEnum.Payload, payload['action'], dumps(payload, indent=2))
    else:
        # Skip payload that does not provide an action
        eventlog.AddLogEntry (LogTypeEnum.Payload, 'None', dumps(payload, indent=2))
        return None, None, 200, 'ignore event %s with no action' % (event)
    # Ignore push and create events
    if event in ['push', 'create']:
        return None, None, 200,'ignore event %s' % (event)
    # Skip payload that does not provide a repository
    if 'repository' not in payload:
        return None, None, 200, 'ignore event %s with no repository' % (event)
    # Skip payload that does not provide a repository full name
    if 'full_name' not in payload['repository']:
        return None, None, 200, 'ignore event %s with no repository full name' % (event)
    # Skip requests that are not for the configured repository
    if payload['repository']['full_name'] != webhookconfiguration.GithubOrgName + '/' + webhookconfiguration.GithubRepoName:
        return None, None, 200, 'ignore event %s for incorrect repository %s' % (event, payload['repository']['full_name'])
    # Retrieve Hub object for this repo
    try:
        Hub = Github (webhookconfiguration.GithubToken)
    except:
        abort(400, 'Unable to retrieve Hub object using GITHUB_TOKEN')
    return payload, Hub, 0, ''

def VerifyPullRequest(event, action, payload, HubOrIssue, eventlog):
    # Use GitHub API to get the Repo and Pull Request objects
    try:
        # First try as a Hub object, then as an Issue object
        try:
            HubRepo = HubOrIssue.get_repo(payload['repository']['full_name'])
            HubPullRequest = HubRepo.get_pull(payload['issue']['number'])
        except:
            # Skip Issue with same commit SHA that is for a different repository
            if HubOrIssue.repository.full_name != payload['repository']['full_name']:
                return None, None, None, None, 200, 'ignore %s event for a different repository %s' % (event, HubOrIssue.repository.full_name)
            HubRepo = HubOrIssue.repository
            HubPullRequest = HubOrIssue.as_pull_request()
    except:
        # Skip requests if the PyGitHub objects can not be retrieved
        return None, None, None, None, 200, 'ignore %s event for which the GitHub objects can not be retrieved' % (event)
    # Skip pull request that is not open
    if event != 'pull_request' or action != 'closed':
        if HubPullRequest.state != 'open':
            return None, None, None, None, 200, 'ignore %s event against a pull request with state %s that is not open' % (event, HubPullRequest.state)
    # Skip pull request with a base repo that is different than the expected repo
    if HubPullRequest.base.repo.full_name != HubRepo.full_name:
        return None, None, None, None, 200, 'ignore %s event against unexpected repo %s' % (event, HubPullRequest.base.repo.full_name)
    # Skip pull requests with a base branch that is not the default branch
    if HubPullRequest.base.ref != HubRepo.default_branch:
        return None, None, None, None, 200, 'ignore %s event against non-default base branch %s' % (event, HubPullRequest.base.ref)
    # Fetch the git commits for the pull request and return a git repo
    # object and the contents of Maintainers.txt
    GitRepo, Maintainers = FetchPullRequest (HubPullRequest, eventlog)
    if GitRepo is None or Maintainers is None:
        return None, None, None, None, 200, 'ignore %s event for a PR that can not be fetched' % (event)
    return HubRepo, HubPullRequest, GitRepo, Maintainers, 0, ''

def GetPatchSeriesInformation(event, action, HubPullRequest):
    NewPatchSeries = False
    PatchSeriesVersion = 1;
    if event == 'pull_request' and action in ['opened', 'reopened']:
        # New pull request was created
        NewPatchSeries = True
    if event != 'pull_request' or action in ['synchronize', 'edited', 'closed', 'reopened']:
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
    return NewPatchSeries, PatchSeriesVersion

def ProcessIssueComment(event, action, payload, Hub, app, webhookconfiguration, eventlog):
    # Verify the pull request referenced in the payload
    HubRepo, HubPullRequest, GitRepo, Maintainers, Status, Message = VerifyPullRequest(event, action, payload, Hub, eventlog)
    if Status:
        return Status, Message
    # Determine if this is a new patch series and the version of the patch series
    NewPatchSeries, PatchSeriesVersion = GetPatchSeriesInformation(event, action, HubPullRequest)
    # Build list of commit SHA values and list of all maintainers/reviewers
    CommitShaList = []
    PullRequestAddressList = []
    for Commit in HubPullRequest.get_commits():
        CommitShaList.append(Commit.sha)
        # Get list of files modified by commit from GIT repository
        CommitFiles = GitRepo.commit(Commit.sha).stats.files
        # Get maintainers and reviewers for all files in this commit
        Addresses = GetMaintainers (Maintainers, CommitFiles)
        AddressList, GitHubIdList, EmailList = ParseMaintainerAddresses(Addresses)
        PullRequestAddressList = list(set(PullRequestAddressList + AddressList))
    # Generate the summary email patch #0 with body of email prefixed with >.
    UpdateDeltaTime = 0
    if action == 'edited':
        # The delta time is the number of seconds from the time the comment
        # was created to the time the comment was edited
        UpdatedAt = datetime.datetime.strptime(payload['comment']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
        CreatedAt = datetime.datetime.strptime(payload['comment']['created_at'], "%Y-%m-%dT%H:%M:%SZ")
        UpdateDeltaTime = (UpdatedAt - CreatedAt).seconds
    if action == 'deleted':
        UpdateDeltaTime = -1
    Summary = FormatPatchSummary (
                webhookconfiguration.EmailArchiveAddress,
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
    # Send generated emails
    SendEmails (HubPullRequest, [Summary], app, webhookconfiguration, eventlog)
    return 200, 'successfully processed %s event with action %s' % (event, payload['action'])

def ProcessCommitComment(event, action, payload, Hub, app, webhookconfiguration, eventlog):
    # Search for issues/pull requests that contain the comment's commit_id
    CommitId        = payload['comment']['commit_id']
    CommentId       = payload['comment']['id']
    CommentPosition = payload['comment']['position']
    CommentPath     = payload['comment']['path']
    EmailContents   = []
    for Issue in Hub.search_issues('SHA:' + CommitId):
        # Verify pull request referenced in Issue
        HubRepo, HubPullRequest, GitRepo, Maintainers, Status, Message = VerifyPullRequest(event, action, payload, Issue, eventlog)
        if Status:
            eventlog.AddLogEntry (LogTypeEnum.Message, 'PR[%d]' % (Issue.id), Message)
            continue
        # Determine if this is a new patch series and the version of the patch series
        NewPatchSeries, PatchSeriesVersion = GetPatchSeriesInformation(event, action, HubPullRequest)
        # Determine the patch number of the commit with the comment
        PatchNumber = 0
        for Commit in HubPullRequest.get_commits():
            PatchNumber = PatchNumber + 1
            if Commit.sha == CommitId:
                break
        # Get commit from GIT repository
        CommitFiles = GitRepo.commit(Commit.sha).stats.files
        # Get maintainers and reviewers for all files in this commit
        Addresses = GetMaintainers (Maintainers, CommitFiles)
        AddressList, GitHubIdList, EmailList = ParseMaintainerAddresses(Addresses)

        Email = FormatPatch (
                    webhookconfiguration.EmailArchiveAddress,
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
        return 200, 'ignore %s event with action %s for which there are no matching issues' % (event, action)
    # Send generated emails
    SendEmails (HubPullRequest, EmailContents, app, webhookconfiguration, eventlog)
    return 200, 'successfully processed %s event with action %s' % (event, action)

def ProcessPullRequestReview(event, action, payload, Hub, app, webhookconfiguration, eventlog):
    # Verify the pull request referenced in the payload
    HubRepo, HubPullRequest, GitRepo, Maintainers, Status, Message = VerifyPullRequest(event, action, payload, Hub, eventlog)
    if Status:
        return Status, Message
    # Build dictionary of review comments
    CommentIdDict = {}
    for Comment in HubPullRequest.get_review_comments():
        Comment.pull_request_review_id = None
        if 'pull_request_review_id' in Comment.raw_data:
            Comment.pull_request_review_id = Comment.raw_data['pull_request_review_id']
        CommentIdDict[Comment.id] = Comment
    # Determine if review has a parent review, is being deleted, or has
    # an update time.
    Review = None
    ReviewComments = []
    DeleteId = None
    ParentReviewId = None
    UpdateDeltaTime = 0
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
        if action == 'submitted':
            UpdateDeltaTime = 0
            for ReviewComment in ReviewComments:
                if ReviewComment.pull_request_review_id == ReviewId:
                    if ReviewComment.in_reply_to_id and ReviewComment.in_reply_to_id in CommentIdDict:
                        ParentReviewId = CommentIdDict[ReviewComment.in_reply_to_id].pull_request_review_id
                        if ParentReviewId and ParentReviewId != ReviewId:
                            break
        if action == 'edited' and Review:
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
        if action == 'deleted':
            UpdateDeltaTime = 0
            DeleteId = payload['comment']['id']
        if action == 'edited' and Review:
            UpdatedAt = datetime.datetime.strptime(payload['comment']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
            UpdateDeltaTime = (UpdatedAt - Review.submitted_at).seconds
    # Determine if this is a new patch series and the version of the patch series
    NewPatchSeries, PatchSeriesVersion = GetPatchSeriesInformation(event, action, HubPullRequest)
    # All pull request review comments are against patch #0
    PatchNumber = 0
    # Build dictionary of files in range of commits from the pull request
    # base sha up to the commit id of the pull request review comment.
    CommitFiles = {}
    CommitShaList = []
    for Commit in HubPullRequest.get_commits():
        CommitShaList.append (Commit.sha)
        CommitFiles.update (GitRepo.commit(Commit.sha).stats.files)
    # Get maintainers and reviewers for all files in this commit
    Addresses = GetMaintainers (Maintainers, CommitFiles)
    AddressList, GitHubIdList, EmailList = ParseMaintainerAddresses(Addresses)
    # Generate the summary email patch #0 with body of email prefixed with >.
    Email = FormatPatchSummary (
                webhookconfiguration.EmailArchiveAddress,
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
    # Send any generated emails
    SendEmails (HubPullRequest, [Email], app, webhookconfiguration, eventlog)
    return 200, 'successfully processed %s event with action %s' % (event, action)

def ProcessPullRequest(event, action, payload, Hub, app, webhookconfiguration, eventlog):
    # Verify the pull request referenced in the payload
    HubRepo, HubPullRequest, GitRepo, Maintainers, Status, Message = VerifyPullRequest(event, action, payload, Hub, eventlog)
    if Status:
        return Status, Message
    # Determine if this is a new patch series and the version of the patch series
    NewPatchSeries, PatchSeriesVersion = GetPatchSeriesInformation(event, action, HubPullRequest)

    PullRequestAddressList = []
    PullRequestGitHubIdList = []
    PullRequestEmailList = []
    EmailContents = []
    PatchNumber = 0
    for Commit in HubPullRequest.get_commits():
        PatchNumber = PatchNumber + 1
        # Get list of files modified by commit from GIT repository
        CommitFiles = GitRepo.commit(Commit.sha).stats.files
        # Get maintainers and reviewers for all files in this commit
        Addresses = GetMaintainers (Maintainers, CommitFiles)
        AddressList, GitHubIdList, EmailList = ParseMaintainerAddresses(Addresses)
        PullRequestAddressList  = list(set(PullRequestAddressList  + AddressList))
        PullRequestGitHubIdList = list(set(PullRequestGitHubIdList + GitHubIdList))
        PullRequestEmailList    = list(set(PullRequestEmailList    + EmailList))
        if action in ['opened', 'synchronize', 'reopened']:
            # Update the list of required reviewers for this commit
            ReviewersUpdated = UpdatePullRequestCommitReviewers (Commit, GitHubIdList, eventlog)
            # Generate email contents for all commits in a pull request if this is
            # a new pull request or a forced push was done to an existing pull request.
            # Generate email contents for patches that add new reviewers. This
            # occurs when when new commits are added to an existing pull request.
            if NewPatchSeries or ReviewersUpdated:
                Email = FormatPatch (
                            webhookconfiguration.EmailArchiveAddress,
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
        # Update the list of required reviewers for the pull request
        UpdatePullRequestReviewers (Hub, HubRepo, HubPullRequest, PullRequestGitHubIdList, eventlog)

    # If this is a new pull request or a forced push on a pull request or an
    # edit of the pull request title or description, then generate the
    # summary email patch #0 and add to be beginning of the list of emails
    # to send.
    if NewPatchSeries or action in ['edited', 'closed']:
        UpdateDeltaTime = 0
        if action in ['edited', 'closed']:
            UpdateDeltaTime = (HubPullRequest.updated_at - HubPullRequest.created_at).seconds
        Summary = FormatPatchSummary (
                        webhookconfiguration.EmailArchiveAddress,
                        event,
                        GitRepo,
                        HubRepo,
                        HubPullRequest,
                        PullRequestAddressList,
                        PatchSeriesVersion,
                        UpdateDeltaTime = UpdateDeltaTime
                        )
        EmailContents.insert (0, Summary)
    # Send generated emails
    SendEmails (HubPullRequest, EmailContents, app, webhookconfiguration, eventlog)
    return 200, 'successfully processed %s event with action %s' % (event, action)

def ProcessGithubRequest(app, webhookconfiguration, eventlog):
    #
    # Authenticate the request header.
    #
    AuthenticateGithubRequestHeader(app, webhookconfiguration, eventlog)

    #
    # Retrieve Github event from the request header. Default is a 'ping' event
    #
    event = request.headers.get('X-GitHub-Event', 'ping')

    #
    # Parse and verify the GitHub payload is for this webhook
    #
    payload, Hub, Status, Message = VerifyPayload(event, eventlog, webhookconfiguration)
    if Status:
        return Status, Message

    #
    # Retrieve GitHub action from payload.
    #
    action = payload['action']

    # Process issue comment events
    # These are comments against the entire pull request
    # Quote Patch #0 Body and add comment below below with commenters GitHubID
    if event == 'issue_comment':
        if action not in ['created', 'edited', 'deleted']:
            return 200, 'ignore %s event with action %s. Only created, edited, and deleted are supported.' % (event, action)
        if 'pull_request' not in payload['issue']:
            return 200, 'ignore %s event without an associated pull request' % (event)
        return ProcessIssueComment(event, action, payload, Hub, app, webhookconfiguration, eventlog)

    # Process commit comment events
    # These are comments against a specific commit
    # Quote Patch #n commit message and add comment below below with commenters GitHubID
    if event == 'commit_comment':
        if action not in ['created', 'edited']:
            return 200, 'ignore %s event with action %s. Only created and edited are supported.' % (event, action)
        # Skip REVIEW_REQUEST comments made by the webhook itself. This same
        # information is always present in the patch emails, so filtering these
        # comments prevents double emails when a pull request is opened or
        # synchronized.
        for Line in payload['comment']['body'].splitlines():
            if Line.startswith (REVIEW_REQUEST):
                return 200, 'ignore %s event with REVIEW_REQUEST body generated by this webhook' % (event)
        return ProcessCommitComment(event, action, payload, Hub, app, webhookconfiguration, eventlog)

    # Process pull_request_review events
    # Quote Patch #0 commit message and patch diff of file comment is against
    if event == 'pull_request_review':
        if action not in ['submitted', 'edited']:
            return 200, 'ignore %s event with action %s. Only submitted and deleted are supported.' % (event, action)
        if action == 'edited' and payload['changes'] == {}:
            return 200, 'ignore %s event with action %s that has no changes.' % (event, action)
        return ProcessPullRequestReview(event, action, payload, Hub, app, webhookconfiguration, eventlog)

    # Process pull_request_review_comment events
    # Quote Patch #0 commit message and patch diff of file comment is against
    if event == 'pull_request_review_comment':
        if action not in ['edited', 'deleted']:
            return 200, 'ignore %s event with action %s. Only edited and deleted are supported.' % (event, action)
        # Skip REVIEW_REQUEST comments made by the webhook itself. This same
        # information is always present in the patch emails, so filtering these
        # comments prevents double emails when a pull request is opened or
        # synchronized.
        for Line in payload['comment']['body'].splitlines():
            if Line.startswith (REVIEW_REQUEST):
                return 200, 'ignore %s event with REVIEW_REQUEST body generated by this webhook' % (event)
        return ProcessPullRequestReview(event, action, payload, Hub, app, webhookconfiguration, eventlog)

    # Process pull request events
    if event == 'pull_request':
        if action not in ['opened', 'synchronize', 'edited', 'closed', 'reopened']:
            return 200, 'ignore %s event with action %s. Only opened, synchronize, edited, closed, and reopened are supported.' % (event, action)
        return ProcessPullRequest(event, action, payload, Hub, app, webhookconfiguration, eventlog)

    return 200, 'ignore unsupported event %s with action %s' % (event, action)
