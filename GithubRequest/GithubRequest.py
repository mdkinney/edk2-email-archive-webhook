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

from datetime import datetime
from Models   import LogTypeEnum, WebhookStatistics, db
from Globals  import GetEmailQueue
from Globals  import GetRepositoryQueue

class GithubRequest(object):
    def __init__(self, app, webhookconfiguration, eventlog, event='', action='',payload=None):
        self.app                     = app
        self.webhookconfiguration    = webhookconfiguration
        self.eventlog                = eventlog
        self.event                   = event
        self.action                  = action
        self.payload                 = payload
        self.GitRepo                 = None
        self.Hub                     = None
        self.HubRepo                 = None
        self.HubPullRequest          = None
        self.CommitList              = []
        self.CommitAddressDict       = {}
        self.CommitGitHubIdDict      = {}
        self.PullRequestAddressList  = []
        self.PullRequestGitHubIdList = []
        self.NewPatchSeries          = False
        self.PatchSeriesVersion      = 0

    REVIEW_REQUEST     = '[CodeReview] Review-request @'
    REVIEWED_BY        = '[CodeReview] Reviewed-by'
    SERIES_REVIEWED_BY = '[CodeReview] Series-reviewed-by'
    ACKED_BY           = '[CodeReview] Acked-by'
    TESTED_BY          = '[CodeReview] Tested-by'

    from .FetchPullRequest      import FetchPullRequest
    from .FetchPullRequest      import DeleteRepositoryCache
    from .FetchPullRequest      import FormatPatchSummary
    from .FetchPullRequest      import FormatPatch
    from .EvaluateGithubRequest import AuthenticateGithubRequestHeader
    from .EvaluateGithubRequest import VerifyPayload
    from .EvaluateGithubRequest import VerifyPullRequest
    from .SendEmails            import SendEmails

    def UpdatePullRequestCommitReviewers(self, Commit):
        # Retrieve all review comments for this commit
        Body = []
        for Comment in Commit.get_comments():
            if Comment.body is not None:
                Body = Body + [Line.strip() for Line in Comment.body.splitlines()]
        # Determine if any reviewers need to be added to this commit
        Message = ''
        AddReviewers = []
        for Reviewer in self.CommitGitHubIdDict[Commit.sha]:
            Message = Message + self.REVIEW_REQUEST + Reviewer
            if self.REVIEW_REQUEST + Reviewer not in Body:
                AddReviewers.append(self.REVIEW_REQUEST + Reviewer + '\n')
                Message = Message + 'ADD'
            Message = Message + '\n'
        if AddReviewers != []:
            # NOTE: This triggers a recursion into this webhook that needs to be
            # ignored
            Commit.create_comment(''.join(AddReviewers))
            # Add reviewers to the log
            self.eventlog.AddLogEntry(LogTypeEnum.Message, 'Commit Reviewers', Message)
        # Return True if reviewers were added to this commit
        return AddReviewers != []

    def UpdatePullRequestReviewers(self):
        Message = ''
        # Get list of collaborators for this repository
        Collaborators = self.HubRepo.get_collaborators()
        # Get list of reviewers already requested for the pull request
        RequestedReviewers = self.HubPullRequest.get_review_requests()[0]
        # Determine if any reviewers need to be removed
        RemoveReviewerList = []
        for Reviewer in RequestedReviewers:
            if Reviewer.login not in self.PullRequestGitHubIdList:
                # Remove assigned reviewer that no longer required.
                # Occurs if files/packages are removed from the PR that no longer
                # require a specific reviewer. Can also occur if Maintainers.txt
                # is updated with new maintainer/reviewer assignments.
                RemoveReviewerList.append(Reviewer.login)
                Message = Message + 'REMOVE REVIEWER  : ' + Reviewer.login + '\n'
                continue
            if Reviewer == self.HubPullRequest.user:
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
        for Login in self.PullRequestGitHubIdList:
            Reviewer = self.Hub.get_user(Login)
            if Reviewer == self.HubPullRequest.user:
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
            AddReviewerList.append(Reviewer.login)
            Message = Message + 'ADD REVIEWER     : ' + Reviewer.login + '\n'
        # Update review requests
        if RemoveReviewerList != []:
            # NOTE: This may trigger recursion into this webhook
            self.HubPullRequest.delete_review_request(RemoveReviewerList)
        if AddReviewerList != []:
            # NOTE: This may trigger recursion into this webhook
            self.HubPullRequest.create_review_request(AddReviewerList)
        # Log reviewer updates
        self.eventlog.AddLogEntry(LogTypeEnum.Message, 'PR[%d] Update Reviewers' % (self.HubPullRequest.number), Message)

    def GetReviewComments(self, Comment, ReviewComments, CommentIdDict):
        if Comment in ReviewComments:
            return
        ReviewComments.append(Comment)
        # Add peer comments
        if Comment.pull_request_review_id:
            for PeerComment in CommentIdDict.values():
                if PeerComment.pull_request_review_id == Comment.pull_request_review_id:
                    self.GetReviewComments(PeerComment, ReviewComments, CommentIdDict)
        # Add child comments
        for ChildComment in CommentIdDict.values():
            if ChildComment.in_reply_to_id == Comment.id:
                self.GetReviewComments(ChildComment, ReviewComments, CommentIdDict)
        # Add parent comment
        if Comment.in_reply_to_id and Comment.in_reply_to_id in CommentIdDict:
            ParentComment = CommentIdDict[Comment.in_reply_to_id]
            self.GetReviewComments(ParentComment, ReviewComments, CommentIdDict)

    def GetReviewCommentsFromReview(self, Review, CommentId, CommentInReplyToId, CommentIdDict):
        ReviewComments = []
        for Comment in CommentIdDict.values():
            if Review:
                if Comment.pull_request_review_id == Review.id:
                    self.GetReviewComments(Comment, ReviewComments, CommentIdDict)
            if CommentId:
                if Comment.in_reply_to_id == CommentId:
                    self.GetReviewComments(Comment, ReviewComments, CommentIdDict)
            if CommentInReplyToId:
                if Comment.id == CommentInReplyToId:
                    self.GetReviewComments(Comment, ReviewComments, CommentIdDict)
        return ReviewComments

    def ProcessIssueComment(self):
        # Verify the pull request referenced in the payload
        Status, Message = self.VerifyPullRequest()
        if Status:
            return Status, Message
        # Generate the summary email patch #0 with body of email prefixed with >.
        UpdateDeltaTime = 0
        if self.action == 'edited':
            # The delta time is the number of seconds from the time the comment
            # was created to the time the comment was edited
            UpdatedAt = datetime.strptime(self.payload['comment']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
            CreatedAt = datetime.strptime(self.payload['comment']['created_at'], "%Y-%m-%dT%H:%M:%SZ")
            UpdateDeltaTime = (UpdatedAt - CreatedAt).seconds
        if self.action == 'deleted':
            UpdateDeltaTime = -1
        Summary = self.FormatPatchSummary(
                    CommentUser     = self.payload['comment']['user']['login'],
                    CommentId       = self.payload['comment']['id'],
                    Prefix          = '> ',
                    UpdateDeltaTime = UpdateDeltaTime
                    )
        # Release the local git repository
        self.GitRepo.__del__()
        # Queue sending of generated emails
        GetEmailQueue().put((
            self.eventlog.id,
            self.webhookconfiguration.id,
            self.HubPullRequest.user.login,
            self.HubPullRequest.number,
            [Summary]
            ))
        return 200, 'successfully processed %s event with action %s' % (self.event, self.action)

    def ProcessCommitComment(self):
        # Search for issues/pull requests that contain the comment's commit_id
        CommitId = self.payload['comment']['commit_id']
        EmailContents = []
        for Issue in self.Hub.search_issues('SHA:' + CommitId):
            # Verify pull request referenced in Issue
            Status, Message = self.VerifyPullRequest(Issue)
            if Status:
                self.eventlog.AddLogEntry(LogTypeEnum.Message, 'PR[%d]' % (Issue.id), Message)
                continue
            # Determine the patch number of the commit with the comment
            PatchNumber = 0
            for Commit in self.CommitList:
                PatchNumber = PatchNumber + 1
                if Commit.sha == CommitId:
                    break
            Email = self.FormatPatch(
                        Commit,
                        PatchNumber,
                        CommentUser     = self.payload['comment']['user']['login'],
                        CommentId       = self.payload['comment']['id'],
                        CommentPosition = self.payload['comment']['position'],
                        CommentPath     = self.payload['comment']['path'],
                        Prefix          = '> '
                        )
            EmailContents.append(Email)
        # Check to make sure there is at least 1 email generated
        if EmailContents == []:
            return 200, 'ignore %s event with action %s for which there are no matching issues' % (self.event, self.action)
        # Release the local git repository
        self.GitRepo.__del__()
        # Queue sending of generated emails
        GetEmailQueue().put((
            self.eventlog.id,
            self.webhookconfiguration.id,
            self.HubPullRequest.user.login,
            self.HubPullRequest.number,
            EmailContents
            ))
        return 200, 'successfully processed %s event with action %s' % (self.event, self.action)

    def ProcessPullRequestReview(self):
        # Verify the pull request referenced in the payload
        Status, Message = self.VerifyPullRequest()
        if Status:
            return Status, Message
        # Build dictionary of review comments
        CommentIdDict = {}
        for Comment in self.HubPullRequest.get_review_comments():
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
        if self.event in ['pull_request_review']:
            CommentUser        = self.payload['review']['user']['login'],
            CommentId          = None
            CommentPosition    = None
            CommentPath        = None
            CommentInReplyToId = None
            ReviewId           = self.payload['review']['id']
            try:
                Review = self.HubPullRequest.get_review(ReviewId)
            except:
                Review = None
            ReviewComments = self.GetReviewCommentsFromReview(Review, CommentId, CommentInReplyToId, CommentIdDict)
            if self.action == 'submitted':
                UpdateDeltaTime = 0
                for ReviewComment in ReviewComments:
                    if ReviewComment.pull_request_review_id == ReviewId:
                        if ReviewComment.in_reply_to_id and ReviewComment.in_reply_to_id in CommentIdDict:
                            ParentReviewId = CommentIdDict[ReviewComment.in_reply_to_id].pull_request_review_id
                            if ParentReviewId and ParentReviewId != ReviewId:
                                break
            if self.action == 'edited' and Review:
                UpdatedAt = datetime.strptime(self.payload['pull_request']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
                UpdateDeltaTime = (UpdatedAt - Review.submitted_at).seconds
        if self.event in ['pull_request_review_comment']:
            CommentId          = self.payload['comment']['id']
            CommentUser        = self.payload['comment']['user']['login'],
            CommentPosition    = self.payload['comment']['position']
            CommentPath        = self.payload['comment']['path']
            CommentInReplyToId = None
            ReviewId           = None
            if 'in_reply_to_id' in self.payload['comment']:
                CommentInReplyToId = self.payload['comment']['in_reply_to_id']
            if 'pull_request_review_id' in self.payload['comment']:
                ReviewId = self.payload['comment']['pull_request_review_id']
                try:
                    Review = self.HubPullRequest.get_review(ReviewId)
                except:
                    Review = None
            ReviewComments = self.GetReviewCommentsFromReview(Review, CommentId, CommentInReplyToId, CommentIdDict)
            if self.action == 'deleted':
                UpdateDeltaTime = 0
                DeleteId = self.payload['comment']['id']
            if self.action == 'edited' and Review:
                UpdatedAt = datetime.strptime(self.payload['comment']['updated_at'], "%Y-%m-%dT%H:%M:%SZ")
                UpdateDeltaTime = (UpdatedAt - Review.submitted_at).seconds

        Email = self.FormatPatchSummary(
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
        # Release the local git repository
        self.GitRepo.__del__()
        # Queue sending of generated emails
        GetEmailQueue().put((
            self.eventlog.id,
            self.webhookconfiguration.id,
            self.HubPullRequest.user.login,
            self.HubPullRequest.number,
            [Email]
            ))
        return 200, 'successfully processed %s event with action %s' % (self.event, self.action)

    def ProcessPullRequest(self):
        # Verify the pull request referenced in the payload
        Status, Message = self.VerifyPullRequest()
        if Status:
            return Status, Message
        EmailContents = []
        PatchNumber = 0
        for Commit in self.CommitList:
            PatchNumber = PatchNumber + 1
            if self.action in ['opened', 'synchronize', 'reopened', 'ready_for_review']:
                # Update the list of required reviewers for this commit
                ReviewersUpdated = self.UpdatePullRequestCommitReviewers(Commit)
                # Generate email contents for all commits in a pull request if this is
                # a new pull request or a forced push was done to an existing pull request.
                # Generate email contents for patches that add new reviewers. This
                # occurs when when new commits are added to an existing pull request.
                if self.NewPatchSeries or ReviewersUpdated:
                    Email = self.FormatPatch(Commit, PatchNumber)
                    EmailContents.append(Email)
        if self.action in ['opened', 'synchronize', 'reopened', 'ready_for_review']:
            # Update the list of required reviewers for the pull request
            self.UpdatePullRequestReviewers()
        # If this is a new pull request or a forced push on a pull request or an
        # edit of the pull request title or description, then generate the
        # summary email patch #0 and add to be beginning of the list of emails
        # to send.
        if self.NewPatchSeries or self.action in ['edited', 'closed']:
            UpdateDeltaTime = 0
            if self.action in ['edited', 'closed']:
                UpdateDeltaTime = (self.HubPullRequest.updated_at - self.HubPullRequest.created_at).seconds
            Summary = self.FormatPatchSummary(UpdateDeltaTime = UpdateDeltaTime)
            EmailContents.insert(0, Summary)
        # Release the local git repository
        self.GitRepo.__del__()
        # Queue sending of generated emails
        GetEmailQueue().put((
            self.eventlog.id,
            self.webhookconfiguration.id,
            self.HubPullRequest.user.login,
            self.HubPullRequest.number,
            EmailContents
            ))
        return 200, 'successfully processed %s event with action %s' % (self.event, self.action)

    def DispatchGithubRequest(self):
        try:
            if self.event=='CUSTOM' and self.action=='ResetStatistics':
                self.webhookconfiguration.ResetStatistics()
                return 200, 'successfully processed %s event with action %s' % (self.event, self.action)
            if self.event=='CUSTOM' and self.action=='DeleteRepositoryCache':
                return self.DeleteRepositoryCache()
            if self.event=='CUSTOM' and self.action=='ClearLogs':
                for log in self.webhookconfiguration.children:
                    # Do not delete log entries for ClearLogs request
                    if log == self.eventlog:
                        continue
                    # Do not delete log entries that were created after the
                    # ClearLogs request
                    if log.TimeStamp > self.eventlog.TimeStamp:
                        continue
                    for child in log.children:
                        db.session.delete(child)
                    db.session.delete(log)
                db.session.commit()
                return 200, 'successfully processed %s event with action %s' % (self.event, self.action)
            if self.event == 'issue_comment':
                return self.ProcessIssueComment()
            if self.event == 'commit_comment':
                return self.ProcessCommitComment()
            if self.event == 'pull_request_review':
                return self.ProcessPullRequestReview()
            if self.event == 'pull_request_review_comment':
                return self.ProcessPullRequestReview()
            if self.event == 'pull_request':
                return self.ProcessPullRequest()
        except:
            raise
            return 200, 'exception dispatching event %s with action %s' % (self.event, self.action)
        return 200, 'ignore unsupported event %s with action %s' % (self.event, self.action)

    def QueueGithubRequest(self):
        # Add request to the repository queue
        GetRepositoryQueue(self.webhookconfiguration.GithubRepo).put((
            self.eventlog.id,
            self.event,
            self.action,
            self.payload,
            datetime.now()
            ))
        if self.event != 'CUSTOM':
            self.webhookconfiguration.RequestQueued()
        return 202, 'Event %s with action %s queued for processing' % (self.event, self.action)

    def ProcessGithubRequest(self):
        # Authenticate the request header.
        self.AuthenticateGithubRequestHeader()
        # Parse and verify the GitHub payload is for this webhook
        Status, Message = self.VerifyPayload()
        if Status:
            return Status, Message
        # Process issue_comment events
        # These are comments against the entire pull request
        # Quote Patch #0 Body and add comment below below with commenters GitHubID
        if self.event == 'issue_comment':
            if self.action not in ['created', 'edited', 'deleted']:
                return 200, 'ignore %s event with action %s. Only created, edited, and deleted are supported.' % (self.event, self.action)
            if 'pull_request' not in self.payload['issue']:
                return 200, 'ignore %s event without an associated pull request' % (self.event)
            return self.QueueGithubRequest()
        # Process commit_comment events
        # These are comments against a specific commit
        # Quote Patch #n commit message and add comment below below with commenters GitHubID
        if self.event == 'commit_comment':
            if self.action not in ['created', 'edited']:
                return 200, 'ignore %s event with action %s. Only created and edited are supported.' % (self.event, self.action)
            # Skip REVIEW_REQUEST comments made by the webhook itself. This same
            # information is always present in the patch emails, so filtering these
            # comments prevents double emails when a pull request is opened or
            # synchronized.
            for Line in self.payload['comment']['body'].splitlines():
                if Line.startswith(self.REVIEW_REQUEST):
                    return 200, 'ignore %s event with REVIEW_REQUEST body generated by this webhook' % (self.event)
            return self.QueueGithubRequest()
        # Process pull_request_review events
        # Quote Patch #0 commit message and patch diff of file comment is against
        if self.event == 'pull_request_review':
            if self.action not in ['submitted', 'edited']:
                return 200, 'ignore %s event with action %s. Only submitted and deleted are supported.' % (self.event, self.action)
            if self.action == 'edited' and self.payload['changes'] == {}:
                return 200, 'ignore %s event with action %s that has no changes.' % (self.event, self.action)
            return self.QueueGithubRequest()
        # Process pull_request_review_comment events
        # Quote Patch #0 commit message and patch diff of file comment is against
        if self.event == 'pull_request_review_comment':
            if self.action not in ['edited', 'deleted']:
                return 200, 'ignore %s event with action %s. Only edited and deleted are supported.' % (self.event, self.action)
            # Skip REVIEW_REQUEST comments made by the webhook itself. This same
            # information is always present in the patch emails, so filtering these
            # comments prevents double emails when a pull request is opened or
            # synchronized.
            for Line in self.payload['comment']['body'].splitlines():
                if Line.startswith(self.REVIEW_REQUEST):
                    return 200, 'ignore %s event with REVIEW_REQUEST body generated by this webhook' % (self.event)
            return self.QueueGithubRequest()
        # Process pull_request events
        if self.event == 'pull_request':
            if self.action not in ['opened', 'synchronize', 'edited', 'closed', 'reopened', 'ready_for_review']:
                return 200, 'ignore %s event with action %s. Only opened, synchronize, edited, closed, reopened, and ready_for_review are supported.' % (self.event, self.action)
            return self.QueueGithubRequest()
        return 200, 'ignore unsupported event %s with action %s' % (self.event, self.action)
