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
from GetMaintainers import GetMaintainers, ParseMaintainerAddresses
from SendEmails import SendEmails
from FetchPullRequest import FetchPullRequest, GitRepositoryLock
from FetchPullRequest import FormatPatch
from FetchPullRequest import FormatPatchSummary
from Models import LogTypeEnum

REVIEW_REQUEST     = '[CodeReview] Review-request @'
REVIEWED_BY        = '[CodeReview] Reviewed-by'
SERIES_REVIEWED_BY = '[CodeReview] Series-reviewed-by'
ACKED_BY           = '[CodeReview] Acked-by'
TESTED_BY          = '[CodeReview] Tested-by'

def UpdatePullRequestCommitReviewers (Context, Commit):
    # Retrieve all review comments for this commit
    Body = []
    for Comment in Commit.get_comments():
        if Comment.body is not None:
            Body = Body + [Line.strip() for Line in Comment.body.splitlines()]
    # Determine if any reviewers need to be added to this commit
    Message = ''
    AddReviewers = []
    for Reviewer in Context.CommitGitHubIdDict[Commit.sha]:
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
        Context.eventlog.AddLogEntry (LogTypeEnum.Message, 'Commit Reviewers', Message)
    # Return True if reviewers were added to this commit
    return AddReviewers != []

def UpdatePullRequestReviewers (Context):
    Message = ''
    # Get list of collaborators for this repository
    Collaborators = Context.HubRepo.get_collaborators()
    # Get list of reviewers already requested for the pull request
    RequestedReviewers = Context.HubPullRequest.get_review_requests()[0]
    # Determine if any reviewers need to be removed
    RemoveReviewerList = []
    for Reviewer in RequestedReviewers:
        if Reviewer.login not in Context.PullRequestGitHubIdList:
            # Remove assigned reviewer that no longer required.
            # Occurs if files/packages are removed from the PR that no longer
            # require a specific reviewer. Can also occur if Maintainers.txt
            # is updated with new maintainer/reviewer assignments.
            RemoveReviewerList.append(Reviewer.login)
            Message = Message + 'REMOVE REVIEWER  : ' + Reviewer.login + '\n'
            continue
        if Reviewer == Context.HubPullRequest.user:
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
    for Login in Context.PullRequestGitHubIdList:
        Reviewer = Context.Hub.get_user(Login)
        if Reviewer == Context.HubPullRequest.user:
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
        Context.HubPullRequest.delete_review_request (RemoveReviewerList)
    if AddReviewerList != []:
        # NOTE: This may trigger recursion into this webhook
        Context.HubPullRequest.create_review_request (AddReviewerList)
    # Log reviewer updates
    Context.eventlog.AddLogEntry (LogTypeEnum.Message, 'PR[%d] Update Reviewers' % (Context.HubPullRequest.number), Message)

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

def AuthenticateGithubRequestHeader(Context):
    # Only POST is supported
    if request.method != 'POST':
        abort(501, 'only POST is supported')
    # Enforce secret, so not just anybody can trigger these hooks
    if Context.webhookconfiguration.GithubWebhookSecret:
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
                  bytes(Context.webhookconfiguration.GithubWebhookSecret, 'utf-8'),
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
    # Update Context structure with event from the request header.
    # Default is a 'ping' event
    Context.event = request.headers.get('X-GitHub-Event', 'ping')
    # Add request headers to the log
    # Delayed to this point to prevent logging rejected requests
    Context.eventlog.AddLogEntry (LogTypeEnum.Request, Context.event, str(request.headers))

def VerifyPayload(Context):
    # If event is ping, then generate a pong response
    if Context.event == 'ping':
        return 200, 'pong'
    # If event is meta, then generate a meta response
    if Context.event == 'meta':
        Context.Message = 'meta'
        return 200, 'meta'
    # Parse request payload as json
    try:
        payload = request.get_json()
    except Exception:
        abort(400, 'Request parsing failed')
    # Add payload to the log
    if 'action' in payload:
        Context.eventlog.AddLogEntry (LogTypeEnum.Payload, payload['action'], dumps(payload, indent=2))
    else:
        # Skip payload that does not provide an action
        Context.eventlog.AddLogEntry (LogTypeEnum.Payload, 'None', dumps(payload, indent=2))
        return 200, 'ignore event %s with no action' % (Context.event)
    # Ignore push and create events
    if Context.event in ['push', 'create']:
        return 200,'ignore event %s' % (Context.event)
    # Skip payload that does not provide a repository
    if 'repository' not in payload:
        return 200, 'ignore event %s with no repository' % (Context.event)
    # Skip payload that does not provide a repository full name
    if 'full_name' not in payload['repository']:
        return 200, 'ignore event %s with no repository full name' % (Context.event)
    # Skip requests that are not for the configured repository
    if payload['repository']['full_name'] != Context.webhookconfiguration.GithubOrgName + '/' + Context.webhookconfiguration.GithubRepoName:
        return 200, 'ignore event %s for incorrect repository %s' % (Context.event, payload['repository']['full_name'])
    # Retrieve Hub object for this repo
    try:
        Context.Hub = Github (Context.webhookconfiguration.GithubToken)
    except:
        abort(400, 'Unable to retrieve Hub object using GITHUB_TOKEN')
    # Update Context structure
    Context.action  = payload['action']
    Context.payload = payload
    return 0, ''

def VerifyPullRequest(Context, Issue = None):
    # Use GitHub API to get the Repo and Pull Request objects
    HubRepo        = None
    HubPullRequest = None
    try:
        if Issue:
            # Skip Issue with same commit SHA that is for a different repository
            if Issue.repository.full_name != Context.payload['repository']['full_name']:
                return 200, 'ignore %s event for a different repository %s' % (Context.event, Issue.repository.full_name)
            HubRepo = Issue.repository
            HubPullRequest = Issue.as_pull_request()
        elif Context.Hub:
            HubRepo = Context.Hub.get_repo(Context.payload['repository']['full_name'])
            if 'pull_request' in Context.payload:
                HubPullRequest = HubRepo.get_pull(Context.payload['pull_request']['number'])
            elif 'issue' in Context.payload:
                HubPullRequest = HubRepo.get_pull(Context.payload['issue']['number'])
    except:
        pass
    if not HubRepo or not HubPullRequest:
        # Skip requests if the PyGitHub objects can not be retrieved
        return 200, 'ignore %s event for which the GitHub objects can not be retrieved' % (Context.event)
    # Skip pull request that is a draft
    if HubPullRequest.draft:
        return 200, 'ignore %s event against a draft pull request' % (Context.event)
    # Skip pull request that is not open unless the pull request is being closed
    if Context.event != 'pull_request' or Context.action != 'closed':
        if HubPullRequest.state != 'open':
            return 200, 'ignore %s event against a pull request with state %s that is not open' % (Context.event, HubPullRequest.state)
    # Skip pull request with a base repo that is different than the expected repo
    if HubPullRequest.base.repo.full_name != HubRepo.full_name:
        return 200, 'ignore %s event against unexpected repo %s' % (Context.event, HubPullRequest.base.repo.full_name)
    # Skip pull requests with a base branch that is not protected or the default branch
    Branch = HubRepo.get_branch(HubPullRequest.base.ref)
    if not Branch or not Branch.protected:
        if HubPullRequest.base.ref != HubRepo.default_branch:
            return 200, 'ignore %s event against base branch %s that is not protected or the default branch' % (Context.event, HubPullRequest.base.ref)
    # Fetch the git commits for the pull request and return a git repo
    # object and the contents of Maintainers.txt
    GitRepo, CommitList, CommitAddressDict, CommitGitHubIdDict, PullRequestAddressList, PullRequestGitHubIdList = FetchPullRequest (HubPullRequest, Context.eventlog)
    if GitRepo is None:
        return 200, 'ignore %s event for a PR that can not be fetched' % (Context.event)

    # Determine if this is a new patch series and the version of the patch series
    NewPatchSeries = False
    PatchSeriesVersion = 1;
    if Context.event == 'pull_request' and Context.action in ['opened', 'reopened', 'ready_for_review']:
        # New pull request was created
        NewPatchSeries = True
    if Context.event != 'pull_request' or Context.action in ['synchronize', 'edited', 'closed', 'reopened', 'ready_for_review']:
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
    Context.HubRepo                 = HubRepo
    Context.HubPullRequest          = HubPullRequest
    Context.GitRepo                 = GitRepo
    Context.CommitList              = CommitList
    Context.CommitAddressDict       = CommitAddressDict
    Context.CommitGitHubIdDict      = CommitGitHubIdDict
    Context.PullRequestAddressList  = PullRequestAddressList
    Context.PullRequestGitHubIdList = PullRequestGitHubIdList
    Context.NewPatchSeries          = NewPatchSeries
    Context.PatchSeriesVersion      = PatchSeriesVersion
    return 0, ''

def ProcessIssueComment(Context):
    # Verify the pull request referenced in the payload
    Status, Message = VerifyPullRequest(Context)
    if Status:
        return Status, Message
    # Generate the summary email patch #0 with body of email prefixed with >.
    UpdateDeltaTime = 0
    if Context.action == 'edited':
        # The delta time is the number of seconds from the time the comment
        # was created to the time the comment was edited
        UpdatedAt = datetime.datetime.strptime(Context.payload['comment']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
        CreatedAt = datetime.datetime.strptime(Context.payload['comment']['created_at'], "%Y-%m-%dT%H:%M:%SZ")
        UpdateDeltaTime = (UpdatedAt - CreatedAt).seconds
    if Context.action == 'deleted':
        UpdateDeltaTime = -1
    Summary = FormatPatchSummary (
                  Context,
                  CommentUser     = Context.payload['comment']['user']['login'],
                  CommentId       = Context.payload['comment']['id'],
                  Prefix          = '> ',
                  UpdateDeltaTime = UpdateDeltaTime
                  )
    # Send generated emails
    SendEmails (Context, [Summary])
    return 200, 'successfully processed %s event with action %s' % (Context.event, Context.action)

def ProcessCommitComment(Context):
    # Search for issues/pull requests that contain the comment's commit_id
    CommitId = Context.payload['comment']['commit_id']
    EmailContents = []
    for Issue in Context.Hub.search_issues('SHA:' + CommitId):
        # Verify pull request referenced in Issue
        Status, Message = VerifyPullRequest(Context, Issue)
        if Status:
            Context.eventlog.AddLogEntry (LogTypeEnum.Message, 'PR[%d]' % (Issue.id), Message)
            continue
        # Determine the patch number of the commit with the comment
        PatchNumber = 0
        for Commit in Context.CommitList:
            PatchNumber = PatchNumber + 1
            if Commit.sha == CommitId:
                break
        Email = FormatPatch (
                    Context,
                    Commit,
                    PatchNumber,
                    CommentUser     = Context.payload['comment']['user']['login'],
                    CommentId       = Context.payload['comment']['id'],
                    CommentPosition = Context.payload['comment']['position'],
                    CommentPath     = Context.payload['comment']['path'],
                    Prefix          = '> '
                    )
        EmailContents.append (Email)
    # Check to make sure there is at least 1 email generated
    if EmailContents == []:
        return 200, 'ignore %s event with action %s for which there are no matching issues' % (Context.event, Context.action)
    # Send generated emails
    SendEmails (Context, EmailContents)
    return 200, 'successfully processed %s event with action %s' % (Context.event, Context.action)

def ProcessPullRequestReview(Context):
    # Verify the pull request referenced in the payload
    Status, Message = VerifyPullRequest(Context)
    if Status:
        return Status, Message
    # Build dictionary of review comments
    CommentIdDict = {}
    for Comment in Context.HubPullRequest.get_review_comments():
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
    if Context.event in ['pull_request_review']:
        CommentUser        = Context.payload['review']['user']['login'],
        CommentId          = None
        CommentPosition    = None
        CommentPath        = None
        CommentInReplyToId = None
        ReviewId           = Context.payload['review']['id']
        try:
            Review = Context.HubPullRequest.get_review(ReviewId)
        except:
            Review = None
        ReviewComments = GetReviewCommentsFromReview(Review, CommentId, CommentInReplyToId, CommentIdDict)
        if Context.action == 'submitted':
            UpdateDeltaTime = 0
            for ReviewComment in ReviewComments:
                if ReviewComment.pull_request_review_id == ReviewId:
                    if ReviewComment.in_reply_to_id and ReviewComment.in_reply_to_id in CommentIdDict:
                        ParentReviewId = CommentIdDict[ReviewComment.in_reply_to_id].pull_request_review_id
                        if ParentReviewId and ParentReviewId != ReviewId:
                            break
        if Context.action == 'edited' and Review:
            UpdatedAt = datetime.datetime.strptime(Context.payload['pull_request']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
            UpdateDeltaTime = (UpdatedAt - Review.submitted_at).seconds
    if Context.event in ['pull_request_review_comment']:
        CommentId          = Context.payload['comment']['id']
        CommentUser        = Context.payload['comment']['user']['login'],
        CommentPosition    = Context.payload['comment']['position']
        CommentPath        = Context.payload['comment']['path']
        CommentInReplyToId = None
        ReviewId           = None
        if 'in_reply_to_id' in Context.payload['comment']:
            CommentInReplyToId = Context.payload['comment']['in_reply_to_id']
        if 'pull_request_review_id' in Context.payload['comment']:
            ReviewId = Context.payload['comment']['pull_request_review_id']
            try:
                Review = Context.HubPullRequest.get_review(ReviewId)
            except:
                Review = None
        ReviewComments = GetReviewCommentsFromReview(Review, CommentId, CommentInReplyToId, CommentIdDict)
        if Context.action == 'deleted':
            UpdateDeltaTime = 0
            DeleteId = Context.payload['comment']['id']
        if Context.action == 'edited' and Review:
            UpdatedAt = datetime.datetime.strptime(Context.payload['comment']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
            UpdateDeltaTime = (UpdatedAt - Review.submitted_at).seconds

    Email = FormatPatchSummary (
                Context,
                CommentUser        = CommentUser,
                CommentId          = CommentId,
                CommentPosition    = CommentPosition,
                CommentPath        = CommentPath,
                Prefix             = '> ',
                CommentInReplyToId = CommentInReplyToId,
                UpdateDeltaTime    = UpdateDeltaTime,
                Review             = Review,
                ReviewId           = ReviewId,
                ReviewComments     = ReviewComments,
                DeleteId           = DeleteId,
                ParentReviewId     = ParentReviewId
                )
    # Send any generated emails
    SendEmails (Context, [Email])
    return 200, 'successfully processed %s event with action %s' % (Context.event, Context.action)

def ProcessPullRequest(Context):
    # Verify the pull request referenced in the payload
    Status, Message = VerifyPullRequest(Context)
    if Status:
        return Status, Message
    EmailContents = []
    PatchNumber = 0
    for Commit in Context.CommitList:
        PatchNumber = PatchNumber + 1
        if Context.action in ['opened', 'synchronize', 'reopened', 'ready_for_review']:
            # Update the list of required reviewers for this commit
            ReviewersUpdated = UpdatePullRequestCommitReviewers (Context, Commit)
            # Generate email contents for all commits in a pull request if this is
            # a new pull request or a forced push was done to an existing pull request.
            # Generate email contents for patches that add new reviewers. This
            # occurs when when new commits are added to an existing pull request.
            if Context.NewPatchSeries or ReviewersUpdated:
                Email = FormatPatch (Context, Commit, PatchNumber)
                EmailContents.append (Email)
    if Context.action in ['opened', 'synchronize', 'reopened', 'ready_for_review']:
        # Update the list of required reviewers for the pull request
        UpdatePullRequestReviewers (Context)
    # If this is a new pull request or a forced push on a pull request or an
    # edit of the pull request title or description, then generate the
    # summary email patch #0 and add to be beginning of the list of emails
    # to send.
    if Context.NewPatchSeries or Context.action in ['edited', 'closed']:
        UpdateDeltaTime = 0
        if Context.action in ['edited', 'closed']:
            UpdateDeltaTime = (Context.HubPullRequest.updated_at - Context.HubPullRequest.created_at).seconds
        Summary = FormatPatchSummary (Context, UpdateDeltaTime = UpdateDeltaTime)
        EmailContents.insert (0, Summary)
    # Send generated emails
    SendEmails (Context, EmailContents)
    return 200, 'successfully processed %s event with action %s' % (Context.event, Context.action)

def ProcessGithubRequest(Context):
    # Authenticate the request header.
    AuthenticateGithubRequestHeader(Context)
    # Parse and verify the GitHub payload is for this webhook
    Status, Message = VerifyPayload(Context)
    if Status:
        return Status, Message
    # Process issue_comment events
    # These are comments against the entire pull request
    # Quote Patch #0 Body and add comment below below with commenters GitHubID
    if Context.event == 'issue_comment':
        if Context.action not in ['created', 'edited', 'deleted']:
            return 200, 'ignore %s event with action %s. Only created, edited, and deleted are supported.' % (Context.event, Context.action)
        if 'pull_request' not in Context.payload['issue']:
            return 200, 'ignore %s event without an associated pull request' % (Context.event)
        return ProcessIssueComment(Context)
    # Process commit_comment events
    # These are comments against a specific commit
    # Quote Patch #n commit message and add comment below below with commenters GitHubID
    if Context.event == 'commit_comment':
        if Context.action not in ['created', 'edited']:
            return 200, 'ignore %s event with action %s. Only created and edited are supported.' % (Context.event, Context.action)
        # Skip REVIEW_REQUEST comments made by the webhook itself. This same
        # information is always present in the patch emails, so filtering these
        # comments prevents double emails when a pull request is opened or
        # synchronized.
        for Line in Context.payload['comment']['body'].splitlines():
            if Line.startswith (REVIEW_REQUEST):
                return 200, 'ignore %s event with REVIEW_REQUEST body generated by this webhook' % (Context.event)
        return ProcessCommitComment(Context)
    # Process pull_request_review events
    # Quote Patch #0 commit message and patch diff of file comment is against
    if Context.event == 'pull_request_review':
        if Context.action not in ['submitted', 'edited']:
            return 200, 'ignore %s event with action %s. Only submitted and deleted are supported.' % (Context.event, Context.action)
        if Context.action == 'edited' and Context.payload['changes'] == {}:
            return 200, 'ignore %s event with action %s that has no changes.' % (Context.event, Context.action)
        return ProcessPullRequestReview(Context)
    # Process pull_request_review_comment events
    # Quote Patch #0 commit message and patch diff of file comment is against
    if Context.event == 'pull_request_review_comment':
        if Context.action not in ['edited', 'deleted']:
            return 200, 'ignore %s event with action %s. Only edited and deleted are supported.' % (Context.event, Context.action)
        # Skip REVIEW_REQUEST comments made by the webhook itself. This same
        # information is always present in the patch emails, so filtering these
        # comments prevents double emails when a pull request is opened or
        # synchronized.
        for Line in Context.payload['comment']['body'].splitlines():
            if Line.startswith (REVIEW_REQUEST):
                return 200, 'ignore %s event with REVIEW_REQUEST body generated by this webhook' % (Context.event)
        return ProcessPullRequestReview(Context.event)
    # Process pull_request events
    if Context.event == 'pull_request':
        if Context.action not in ['opened', 'synchronize', 'edited', 'closed', 'reopened', 'ready_for_review']:
            return 200, 'ignore %s event with action %s. Only opened, synchronize, edited, closed, reopened, and ready_for_review are supported.' % (Context.event, Context.action)
        return ProcessPullRequest(Context)
    return 200, 'ignore unsupported event %s with action %s' % (Context.event, Context.action)
