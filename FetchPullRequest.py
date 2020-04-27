## @file
# Fetch the git commits required to process a pull request
#
# Copyright (c) 2020, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#

'''
FetchPullRequest
'''
from __future__ import print_function

import os
import sys
import git
import email
import textwrap
import datetime

EMAIL_ARCHIVE_ADDRESS = os.environ['EMAIL_ARCHIVE_ADDRESS']

class Progress(git.remote.RemoteProgress):
    def __init__(self):
        git.remote.RemoteProgress.__init__(self)
        self.PreviousLine = ''
    def update(self, op_code, cur_count, max_count=None, message=''):
        Line = '\r' + self._cur_line
        if len(self.PreviousLine) > len(Line):
            Line = Line + ' ' * (len(self.PreviousLine) - len(Line))
        sys.stdout.write(Line)
        self.PreviousLine = Line

def FetchPullRequest (HubPullRequest, Depth = 200):
    #
    # Fetch the base.ref branch and current PR branch from the base repository
    # of the pull request
    #
    RepositoryPath = os.path.normpath (os.path.join ('Repository', HubPullRequest.base.repo.full_name))
    if os.path.exists (RepositoryPath):
        try:
            print ('pr[%d]' % (HubPullRequest.number), 'mount', RepositoryPath)
            GitRepo = git.Repo(RepositoryPath)
            Origin = GitRepo.remotes['origin']
        except:
            try:
                print ('pr[%d]' % (HubPullRequest.number), 'init', RepositoryPath)
                GitRepo = git.Repo.init (RepositoryPath, bare=True)
                Origin = GitRepo.create_remote ('origin', HubPullRequest.base.repo.html_url)
            except:
                print ('pr[%d]' % (HubPullRequest.number), 'init', RepositoryPath, 'FAILED')
                return None, None
    else:
        try:
            print ('pr[%d]' % (HubPullRequest.number), 'init', RepositoryPath)
            os.makedirs (RepositoryPath)
            GitRepo = git.Repo.init (RepositoryPath, bare=True)
            Origin = GitRepo.create_remote ('origin', HubPullRequest.base.repo.html_url)
        except:
            print ('pr[%d]' % (HubPullRequest.number), 'init', RepositoryPath, 'FAILED')
            return None, None
    #
    # Shallow fetch base.ref branch from origin
    #
    try:
        print ('pr[%d]' % (HubPullRequest.number), 'fetch', HubPullRequest.base.ref, 'from', RepositoryPath)
        Origin.fetch(HubPullRequest.base.ref, progress=Progress(), depth = Depth)
    except:
        print ('pr[%d]' % (HubPullRequest.number), 'fetch', HubPullRequest.base.ref, 'from', RepositoryPath, 'FAILED')
        return None, None
    #
    # Fetch the current pull request branch from origin
    #
    try:
        print ('pr[%d]' % (HubPullRequest.number), 'fetch pull request', HubPullRequest.number, 'from', RepositoryPath)
        Origin.fetch('+refs/pull/%d/*:refs/remotes/origin/pr/%d/*' % (HubPullRequest.number, HubPullRequest.number), progress=Progress())
        print ('pr[%d]' % (HubPullRequest.number), 'fetch', RepositoryPath, 'done')
    except:
        print ('pr[%d]' % (HubPullRequest.number), 'fetch pull request', HubPullRequest.number, 'from', RepositoryPath, 'NOT FOUND')
        return None, None

    #
    # Retrieve the latest version of Maintainers.txt from origin/base.ref
    #
    try:
        Maintainers = GitRepo.git.show('origin/%s:Maintainers.txt' % (HubPullRequest.base.ref))
    except:
        print ('Maintainers.txt does not exist in origin/%s' % (HubPullRequest.base.ref))
        Maintainers = ''

    return GitRepo, Maintainers

def ParseCcLines(Body):
    AddressList = []
    for Line in Body.splitlines():
        if Line.lower().startswith ('cc:'):
            Address = Line[3:].strip()
            if ',' in Address:
                continue
            if '<' not in Address or '>' not in Address:
                continue
            if '@' not in Address.rsplit('<',1)[1].split('>',1)[0]:
                continue
            AddressList.append(Address)
    return AddressList

def GetLineEnding (Line):
    if Line.endswith('\r\n'):
        return '\r\n'
    elif Line.endswith('\r'):
        return '\r'
    else:
        return '\n'

def MetaDataBlockText(HubPullRequest, Commit, AddressList, LineEnding):
    Text = ''
    #
    # Add link to pull request
    #
    Text = Text + '#' * 4 + LineEnding
    Text = Text + '# PR(%s): %s%s' % (HubPullRequest.state, HubPullRequest.html_url, LineEnding)

    #
    # Add base SHA value
    #
    Text = Text + '# Base SHA: ' + HubPullRequest.base.sha + LineEnding

    #
    # Add submitter
    #
    Text = Text + '# Submitter: [' + HubPullRequest.user.login + ']' + LineEnding

    #
    # Add link to commit
    #
    if Commit is not None:
        Text = Text + '# Commit: ' + Commit.html_url + LineEnding

    #
    # Add list of assigned reviewers
    #
    for Address in AddressList:
        Text = Text + '# ' + Address + LineEnding
    Text = Text + '#' * 4 + LineEnding
    Text = Text + LineEnding

    return Text

def QuoteText (Text, Prefix, Depth):
    if Depth <= 0:
        return Text
    Text = Text.splitlines(keepends=True)
    return (Prefix * Depth) + (Prefix * Depth).join(Text)

def WrapParagraph (Paragraph, LineEnding):
    WrappedParagraph = textwrap.wrap(
                           Paragraph,
                           replace_whitespace=False,
                           drop_whitespace=False,
                           break_long_words=False,
                           break_on_hyphens=False
                           )
    Length = len(WrappedParagraph[0]) - len(WrappedParagraph[0].lstrip(' '))
    WrappedParagraph = [X.lstrip(' ') for X in WrappedParagraph]
    if len(WrappedParagraph) > 1 and WrappedParagraph[-1].rstrip() == '':
        WrappedParagraph[-2] = WrappedParagraph[-2] + WrappedParagraph[-1]
        WrappedParagraph = WrappedParagraph[:-1]
    return QuoteText (LineEnding.join(WrappedParagraph), ' ', Length)

def WrapText (Text, LineEnding):
    Result = ''
    for Paragraph in Text.splitlines(keepends=True):
        Result = Result + WrapParagraph (Paragraph, LineEnding)
    return Result

def CommentAsEmailText(Comment, LineEnding, Prefix, Depth):
    #
    # Wrap long lines in comment body, but never split HTML links that may
    # contain hyphens.
    #
    WrappedBody = []
    if Comment.body is not None:
        for Paragraph in Comment.body.splitlines(keepends=True):
            PrefixDepth = 0
            if Prefix:
                while Paragraph.startswith (Prefix):
                    Paragraph = Paragraph[len(Prefix):]
                    PrefixDepth = PrefixDepth + 1
            WrappedParagraph = QuoteText (
                                   WrapParagraph(Paragraph, LineEnding),
                                   Prefix,
                                   PrefixDepth
                                   )
            WrappedBody.append (WrappedParagraph)

    String = 'On %s @%s wrote:%s%s' % (
                 str(Comment.created_at),
                 Comment.user.login,
                 LineEnding,
                 ''.join(WrappedBody)
                 )
    if String[-1] not in ['\n','\r']:
        String = String + LineEnding
    return '-' * 20 + LineEnding + QuoteText (String, Prefix, Depth)

def QuoteCommentList (Comments, Before = '', After = '', LineEnding = '\n', Prefix = '> '):
    #
    # Sort comments from oldest comment to newest comment
    #
    Comments = sorted (Comments, key=lambda Comment: Comment.created_at)
    Body = ''
    if Before:
        if Before[-1] not in ['\n','\r']:
            Before = Before + LineEnding
        Body = Body + QuoteText (Before, Prefix, len(Comments))
    Depth = len(Comments)
    for Comment in Comments:
        Depth = Depth - 1
        Body = Body + CommentAsEmailText(Comment, LineEnding, Prefix, Depth)
    if After:
        if After[-1] not in ['\n','\r']:
            After = After + LineEnding
        Body = Body + '-' * 20 + LineEnding
        Body = Body + QuoteText (After, Prefix, len(Comments))
    else:
        Body = Body + '-' * 20 + LineEnding
    return Body

def FormatPatch (
        event,
        GitRepo,
        HubRepo,
        HubPullRequest,
        Commit,
        AddressList,
        PatchSeriesVersion,
        PatchNumber,
        CommentUser = None,
        CommentType = None,
        CommentId = None,
        CommentPosition = None,
        CommentPath = None,
        Prefix = '',
        CommentInReplyToId = None
        ):
    #
    # Default range is a single commit
    #
    CommitRange = Commit.sha + '~1..' + Commit.sha

    #
    # Format the Subject:
    #   [<repo name>][PATCH v<patch series version> <patch number>/<number of patches>]
    # Format the Messsage-ID:
    #   <webhook-<repo name>-pr<pull>-v<patch series version>-p<patch number>@tianocore.org>
    #
    ToAddress = '<%s>' % (EMAIL_ARCHIVE_ADDRESS)
    if CommentId:
        FromAddress = '%s via TianoCore Webhook <webhook@tianocore.org>' % (CommentUser)
        HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber, CommentId)
        if CommentInReplyToId:
            HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber, CommentInReplyToId)
        else:
            HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber)
    else:
        FromAddress = '%s via TianoCore Webhook <webhook@tianocore.org>' % (HubPullRequest.user.login)
        HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0)
        HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber)
    Email = GitRepo.git.format_patch (
              '--stdout',
              '--cover-letter',
              '--to=' + ToAddress,
              '--from=' + FromAddress,
              '--add-header=' + HeaderInReplyToId,
              '--add-header=' + HeaderMessageId,
              '--subject-prefix=%s][PATCH v%d %*d/%d' % (HubRepo.name, PatchSeriesVersion, len(str(HubPullRequest.commits)), PatchNumber, HubPullRequest.commits),
              CommitRange
              )

    #
    # Remove first line from format-patch that is not part of email and parse
    # the line ending style used by git format-patch
    #
    Email = Email.splitlines(keepends=True)
    LineEnding = GetLineEnding (Email[0])
    Email = ''.join(Email[1:])

    #
    # Parse the email message and parse the message body.  Split the message
    # body at the '\n---\n' marker which seperates the commit message from the
    # patch diffs.
    #
    Message = email.message_from_string(Email)
    Pattern = '\n---\n'
    Body = Message.get_payload().split (Pattern, 1)
    Body[0] = Body[0] + Pattern

    #
    # Parse the Cc: lines from the commit message
    #
    CcAddressList = ParseCcLines (Body[0])

    #
    # Add text with links to pull request and the commit along with the list
    # of maintainers/reviewers for this specific commit after the '\n---\n'
    # marker so this meta data is not part of the commit message or the patch
    # diffs.
    #
    Body[0] = Body[0] + MetaDataBlockText(
                            HubPullRequest,
                            Commit,
                            AddressList,
                            LineEnding
                            )

    if CommentId:
        #
        # Get the comments that apply based on the event type
        #
        AllComments = []
        if event == 'commit_comment':
            AllComments = Commit.get_comments()
        if event == 'pull_request_review_comment':
            AllComments = HubPullRequest.get_review_comments()
        #
        # Only keep the comments that match the CommentPath and CommentPosition
        # from this event
        #
        Comments = []
        for Comment in AllComments:
            if Comment.path == CommentPath and Comment.position == CommentPosition:
                Comments.append(Comment)

        if CommentPath == None:
            #
            # This is a comment against the description of the commit.  Discard
            # the patch diffs and append the review comments quoting the commit
            # message and all previous comments.
            #
            Body = QuoteCommentList (
                       Comments,
                       Before     = Body[0],
                       LineEnding = LineEnding,
                       Prefix     = Prefix
                       )
        else:
            #
            # Find the portion of the patch diffs that contain changes to the
            # file specified by CommentPath
            #
            Start   = '\ndiff --git a/' + CommentPath + ' b/' + CommentPath + '\n'
            End     = '\ndiff --git a/'
            try:
                Body[1] = Start + Body[1].split(Start,1)[1].split(End,1)[0]
                Body[1] = Body[1].lstrip()
            except:
                Body[1] = Body[1] + 'ERROR: %s Comment to file %s position %d not found.\n' % (Commit.sha, CommentPath, CommentPosition)

            #
            # Find the first line of the patch diff for file CommentPath that
            # starts with '@@ '.
            #
            Body[1] = Body[1].splitlines(keepends=True)
            for LineNumber in range(0, len(Body[1])):
                if Body[1][LineNumber].startswith('@@ '):
                    break

            #
            # Insert comments into patch at CommentPosition + 1 lines after '@@ '
            #
            LineNumber = LineNumber + CommentPosition + 1
            Body = QuoteCommentList (
                       Comments,
                       Before     = Body[0] + ''.join(Body[1][:LineNumber]),
                       After      = ''.join(Body[1][LineNumber:]),
                       LineEnding = LineEnding,
                       Prefix     = Prefix
                       )
    else:
        Body = Body[0] + Body[1]

    if CcAddressList:
        Message.add_header('Cc', ','.join(CcAddressList))
    Message.set_payload(Body)

    return Message.as_string()

def FormatPatchSummary (
        event,
        GitRepo,
        HubRepo,
        HubPullRequest,
        AddressList,
        PatchSeriesVersion,
        CommitRange = None,
        CommentUser = None,
        CommentId = None,
        CommentPosition = None,
        CommentPath = None,
        Prefix = '',
        CommentInReplyToId = None,
        UpdateDeltaTime = 0,
        Review = None,
        ReviewComments = [],
        DeleteId = None,
        ParentReviewId = None
        ):

    #
    # Default range is the entire pull request
    #
    if CommitRange is None:
        CommitRange = HubPullRequest.base.sha + '..' + HubPullRequest.head.sha

    #
    # Format the Subject:
    #   [<repo name>][PATCH v<patch series version> <patch number>/<number of patches>]
    # Format the Messsage-ID:
    #   <webhook-<repo name>-pr<pull>-v<patch series version>-p<patch number>@tianocore.org>
    #
    ToAddress = '<%s>' % (EMAIL_ARCHIVE_ADDRESS)
    if Review:
        FromAddress = '%s via TianoCore Webhook <webhook@tianocore.org>' % (CommentUser)
        if DeleteId:
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-r%d-d%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, Review.id, DeleteId)
        elif UpdateDeltaTime != 0:
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-r%d-t%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, Review.id, UpdateDeltaTime)
        else:
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-r%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, Review.id)
        if ParentReviewId:
            HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d-r%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, ParentReviewId)
        elif DeleteId or UpdateDeltaTime != 0:
            HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d-r%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, Review.id)
        else:
            HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0)
    elif CommentId:
        FromAddress = '%s via TianoCore Webhook <webhook@tianocore.org>' % (CommentUser)
        if UpdateDeltaTime != 0:
            HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId)
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d-t%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId, UpdateDeltaTime)
        else:
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId)
            if CommentInReplyToId:
                HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentInReplyToId)
            else:
                HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0)
    else:
        FromAddress = '%s via TianoCore Webhook <webhook@tianocore.org>' % (HubPullRequest.user.login)
        if UpdateDeltaTime != 0:
            HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0)
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-t%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, UpdateDeltaTime)
        else:
            HeaderInReplyToId = None
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0)
    if HeaderInReplyToId:
        Email = GitRepo.git.format_patch (
                  '--stdout',
                  '--cover-letter',
                  '--to=' + ToAddress,
                  '--from=' + FromAddress,
                  '--add-header=' + HeaderInReplyToId,
                  '--add-header=' + HeaderMessageId,
                  '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                  CommitRange
                  )
    else:
        Email = GitRepo.git.format_patch (
                  '--stdout',
                  '--cover-letter',
                  '--to=' + ToAddress,
                  '--from=' + FromAddress,
                  '--add-header=' + HeaderMessageId,
                  '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                  CommitRange
                  )

    #
    # Remove first line from format-patch that is not part of email and parse
    # the line ending style used by git format-patch
    #
    Email = Email.splitlines(keepends=True)
    LineEnding = GetLineEnding (Email[0])
    Email = ''.join(Email[1:])

    #
    # Parse the email message and parse the message body discarding the file
    # diffs leaving only the *** BLURB HERE *** and file change summary.
    # Split the message body at *** BLURB HERE *** so the description of the
    # pull request can inserted and leave the option to discard the file change
    # summary.
    #
    Message = email.message_from_string(Email)
    Pattern = '\n-- \n'
    Body = Message.get_payload().split (Pattern, 1)[0] + Pattern
    Body = Body.split ('*** BLURB HERE ***', 1)

    #
    # Add text with link to pull request and list of maintainers/reviewers
    #
    Body[0] = Body[0] + MetaDataBlockText(
                            HubPullRequest,
                            None,
                            AddressList,
                            LineEnding
                            )

    #
    # Add the body from the pull request
    #
    CcAddressList = []
    if HubPullRequest.body is not None:
        CcAddressList = ParseCcLines (HubPullRequest.body)
        Body[0] = Body[0] + WrapText (HubPullRequest.body, LineEnding)

    #
    # If this is a comment against the description of the pull request
    # then discard the file change summary and append the review comments
    # quoting the decription of the pull request and all previous comments.
    # Otherwise, this is a Patch #0 email that includes the file change summary.
    #
    if CommentId or Review:
        if event in ['pull_request_review_comment', 'pull_request_review']:
            if Review:
                #
                # Add description of review to email
                #
                Body[0] = QuoteText(Body[0], '> ', 1)
                Body[0] = Body[0] + '-' * 20 + LineEnding
                if Review.body:
                    String = 'On %s @%s started a review with state %s:' % (
                                 str(Review.submitted_at),
                                 Review.user.login,
                                 Review.state
                                 )
                    Body[0] = Body[0] + String + LineEnding
                    Body[0] = Body[0] + WrapText (Review.body, LineEnding) + LineEnding
                else:
                    String = 'On %s @%s added a single review comment:' % (
                                 str(Review.submitted_at),
                                 Review.user.login
                                 )
                    Body[0] = Body[0] + String + LineEnding
                Body[0] = Body[0] + '-' * 20 + LineEnding

            else:
                Body[0] = QuoteText(Body[0], '> ', 1)
                Body[0] = Body[0] + '-' * 20 + LineEnding
                if CommentId:
                    Body[0] = Body[0] + 'Review associated with CommentId %s not found' % (CommentId) + LineEnding
                elif Review:
                    Body[0] = Body[0] + 'Review associated with ReviewId %s not found' % (Review.id) + LineEnding
                else:
                    Body[0] = Body[0] + 'Review associated with this pull request was not found' + LineEnding
                Body[0] = Body[0] + '-' * 20 + LineEnding

            #
            # If this is a pull request review comment then discard the file
            # change summary and insert the review comments at the specified
            # position in the pull request diff quoting the decription of the
            # pull request, the diff, and all previous comments.
            #

            #
            # Generate file diff for the commit range
            #
            Diff = '\n-- \n' + GitRepo.git.diff (CommitRange)

            #
            # Get the pull request review comments only keeping the comments
            # that match the CommentPath and CommentPosition from this event
            #
            CommentDict = {}
            for Comment in ReviewComments:
                if Comment.path not in CommentDict:
                    CommentDict[Comment.path] = {}
                if Comment.position not in CommentDict[Comment.path]:
                    CommentDict[Comment.path][Comment.position] = []
                CommentDict[Comment.path][Comment.position].append(Comment)

            DiffBody = ''
            for CommentPath in CommentDict.keys():
                #
                # Find the portion of the patch diffs that contain changes to the
                # file specified by CommentPath
                #
                Start   = '\ndiff --git a/' + CommentPath + ' b/' + CommentPath + '\n'
                End     = '\ndiff --git a/'
                try:
                    PathDiff = Start + Diff.split(Start,1)[1].split(End,1)[0]
                    PathDiff = PathDiff.lstrip()
                except:
                    PathDiff = Diff + 'ERROR: Pull request %d review comment to file %s position %d not found.\n' % (HubPullRequest.number, CommentPath, CommentPosition)

                #
                # Find the first line of the patch diff for file CommentPath that
                # starts with '@@ '.
                #
                PathDiff = PathDiff.splitlines(keepends=True)
                for StartLineNumber in range(0, len(PathDiff)):
                    if PathDiff[StartLineNumber].startswith('@@ '):
                        break
                #
                # Quote the diff for the current path
                #
                PathDiff = QuoteText (''.join(PathDiff), '> ', 1)
                PathDiff = PathDiff.splitlines(keepends=True)

                Positions = list(CommentDict[CommentPath].keys())
                Positions.sort()
                PreviousLineNumber = 0
                for CommentPosition in Positions:
                    #
                    # Insert comments into patch at CommentPosition + 1 lines after '@@ '
                    #
                    LineNumber = StartLineNumber + CommentPosition + 1
                    CommentBody = QuoteCommentList (
                                      CommentDict[CommentPath][CommentPosition],
                                      LineEnding = LineEnding,
                                      Prefix     = ''
                                      )
                    DiffBody = DiffBody + ''.join(PathDiff[PreviousLineNumber:LineNumber]) + CommentBody
                    PreviousLineNumber = LineNumber
                DiffBody = DiffBody + ''.join(PathDiff[LineNumber:])

            Body = Body[0] + '\n-- \n' + DiffBody
        else:
            #
            # If this is a comment against the description of the pull request
            # then discard the file change summary and append the review comments
            # quoting the decription of the pull request and all previous comments.
            #
            Body = QuoteCommentList (
                       HubPullRequest.get_issue_comments(),
                       Before     = Body[0],
                       LineEnding = LineEnding,
                       Prefix     = Prefix
                       )
    else:
        #
        # This is a Patch #0 email that includes the file change summary.
        #
        Body = Body[0] + Body[1]

    #
    # Update incorrect From: line in git format-patch cover letter
    # Replace *** SUBJECT HERE *** with the pull request title
    # Add Re: to Subject if comment is being processed
    #
    Message.replace_header('From', FromAddress)
    if HubPullRequest.title is not None:
        Message.replace_header('Subject', Message['Subject'].replace ('*** SUBJECT HERE ***', HubPullRequest.title))
    if CcAddressList:
        Message.add_header('Cc', ','.join(CcAddressList))
    Message.set_payload(Body)

    return Message.as_string()
