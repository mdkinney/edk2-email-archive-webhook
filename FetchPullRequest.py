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
import git
import email
import textwrap
import threading
import shutil
import stat
from Models import LogTypeEnum

GitRepositoryLock = threading.Lock()

class Progress(git.remote.RemoteProgress):
    def __init__(self):
        git.remote.RemoteProgress.__init__(self)
        self.Log = ''
    def update(self, op_code, cur_count, max_count=None, message=''):
        self.Log += '    ' + self._cur_line + '\n'

def FetchPullRequest (HubPullRequest, eventlog, Depth = 1):
    #
    # Fetch the base.ref branch and current PR branch from the base repository
    # of the pull request
    #
    GitRepositoryLock.acquire()
    Message = ''
    RepositoryPath = os.path.normpath (os.path.join ('Repository', HubPullRequest.base.repo.full_name))
    if os.path.exists (RepositoryPath):
        try:
            Message += 'mount local repository %s\n' % (RepositoryPath)
            GitRepo = git.Repo(RepositoryPath)
            Origin = GitRepo.remotes['origin']
            Message += '  SUCCESS\n'
        except:
            try:
                Message += 'create local repository %s\n' % (RepositoryPath)
                GitRepo = git.Repo.init (RepositoryPath, bare=True)
                Origin = GitRepo.create_remote ('origin', HubPullRequest.base.repo.html_url)
                Message += '  SUCCESS\n'
            except:
                Message += '  FAIL\n'
                eventlog.AddLogEntry (LogTypeEnum.Message, 'Git fetch pr[%d]' % (HubPullRequest.number), Message)
                GitRepositoryLock.release()
                return None, None
    else:
        try:
            Message += 'create local repository %s\n' % (RepositoryPath)
            os.makedirs (RepositoryPath)
            GitRepo = git.Repo.init (RepositoryPath, bare=True)
            Origin = GitRepo.create_remote ('origin', HubPullRequest.base.repo.html_url)
            Message += '  SUCCESS\n'
        except:
            Message += '  FAIL\n'
            eventlog.AddLogEntry (LogTypeEnum.Message, 'Git fetch pr[%d]' % (HubPullRequest.number), Message)
            GitRepositoryLock.release()
            return None, None

    #
    # Shallow fetch base.ref branch from origin
    #
    try:
        Message += 'git fetch origin %s\n' % (HubPullRequest.base.ref)
        P = Progress()
        Origin.fetch(HubPullRequest.base.ref, progress=P, depth = Depth)
        Message = Message + P.Log
        Message += '  SUCCESS\n'
    except:
        Message += '  FAIL\n'
        eventlog.AddLogEntry (LogTypeEnum.Message, 'Git fetch pr[%d]' % (HubPullRequest.number), Message)
        GitRepositoryLock.release()
        return None, None
    #
    # Fetch the current pull request branch from origin
    #
    try:
        Message += 'git fetch origin +refs/pull/%d/*:refs/remotes/origin/pr/%d/*\n' % (HubPullRequest.number, HubPullRequest.number)
        Origin.fetch('+refs/pull/%d/*:refs/remotes/origin/pr/%d/*' % (HubPullRequest.number, HubPullRequest.number), progress=Progress())
        Message += '  SUCCESS\n'
    except:
        Message += '  FAIL\n'
        eventlog.AddLogEntry (LogTypeEnum.Message, 'Git fetch pr[%d]' % (HubPullRequest.number), Message)
        GitRepositoryLock.release()
        return None, None

    #
    # Retrieve the latest version of Maintainers.txt from origin/base.ref
    #
    try:
        Message += 'git show origin/%s:Maintainers.txt\n' % (HubPullRequest.base.ref)
        Maintainers = GitRepo.git.show('origin/%s:Maintainers.txt' % (HubPullRequest.base.ref))
        Message += '  SUCCESS\n'
    except:
        Message += '  FAIL.  Maintainers.txt does not exist in origin/%s\n' % (HubPullRequest.base.ref)
        Maintainers = ''

    eventlog.AddLogEntry (LogTypeEnum.Message, 'Git fetch pr[%d]' % (HubPullRequest.number), Message)

    GitRepositoryLock.release()
    return GitRepo, Maintainers

def DeleteRepositoryCache (webhookconfiguration):
    RepositoryPath = os.path.normpath (os.path.join ('Repository', webhookconfiguration.GithubOrgName, webhookconfiguration.GithubRepoName))
    if not os.path.exists (RepositoryPath):
        return True
    GitRepositoryLock.acquire()
    try:
        # Make sure all dir and files are writable
        for root, dirs, files in os.walk(RepositoryPath):
            for dir in dirs:
                os.chmod(os.path.join(root, dir), stat.S_IWRITE)
            for file in files:
                os.chmod(os.path.join(root, file), stat.S_IWRITE)
        # Remove the entire tree
        shutil.rmtree(RepositoryPath)
        Status = True
    except:
        Status = False
    GitRepositoryLock.release()
    return Status

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

    if hasattr(Comment, 'state'):
        String = 'On %s @%s started a review with state %s:%s%s' % (
                     str(Comment.submitted_at),
                     Comment.user.login,
                     Comment.state,
                     LineEnding,
                     ''.join(WrappedBody)
                     )
    else:
        String = 'On %s @%s wrote:%s%s' % (
                     str(Comment.created_at),
                     Comment.user.login,
                     LineEnding,
                     ''.join(WrappedBody)
                     )
    if String[-1] not in ['\n','\r']:
        String = String + LineEnding
    try:
        for Reaction in Comment.get_reactions():
            String = String + '@%s reacted with %s%s' % (
                                Reaction.user.login,
                                Reaction.content,
                                LineEnding
                                )
    except:
        pass
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
        EmailArchiveAddress,
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
        CommentInReplyToId = None,
        LargePatchLines = 500
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
    ToAddress = '<%s>' % (EmailArchiveAddress)
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
              '--no-numbered',
              '--to=' + ToAddress,
              '--from=' + FromAddress,
              '--add-header=' + HeaderInReplyToId,
              '--add-header=' + HeaderMessageId,
              '--subject-prefix=%s][PATCH v%d %0*d/%d' % (HubRepo.name, PatchSeriesVersion, len(str(HubPullRequest.commits)), PatchNumber, HubPullRequest.commits),
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
    Message = email.message_from_bytes(Email.encode('utf8','surrogateescape'))
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
            PatchLines = len(Body[1].splitlines())
            try:
                BeforeBody = Body[1].split(Start,1)[0] + '\n'
                try:
                    AfterBody = Body[1].split(Start,1)[1].split(End,1)[1]
                    Body[1] = Start.lstrip() + Body[1].split(Start,1)[1].split(End,1)[0]
                except:
                    AfterBody = ''
                    Body[1] = Start.lstrip() + Body[1].split(Start,1)[1]
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
            if PatchLines > LargePatchLines:
                Body = QuoteCommentList (
                           Comments,
                           Before     = Body[0] + BeforeBody + ''.join(Body[1][:LineNumber]),
                           After      = ''.join(Body[1][LineNumber:]) + AfterBody,
                           LineEnding = LineEnding,
                           Prefix     = Prefix
                           )
            else:
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
        EmailArchiveAddress,
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
        ReviewId = None,
        ReviewComments = [],
        DeleteId = None,
        ParentReviewId = None,
        LargePatchLines = 500
        ):

    #
    # Default range is the entire pull request
    #
    if CommitRange is None:
        CommitShaList = [Commit.sha for Commit in HubPullRequest.get_commits()]
        CommitRange = CommitShaList[0] + '..' + CommitShaList[-1]

    #
    # Format the Subject:
    #   [<repo name>][PATCH v<patch series version> <patch number>/<number of patches>]
    # Format the Messsage-ID:
    #   <webhook-<repo name>-pr<pull>-v<patch series version>-p<patch number>@tianocore.org>
    #
    ToAddress = '<%s>' % (EmailArchiveAddress)
    if ReviewId:
        FromAddress = '%s via TianoCore Webhook <webhook@tianocore.org>' % (CommentUser)
        if DeleteId:
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-r%d-d%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, ReviewId, DeleteId)
        elif UpdateDeltaTime != 0:
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-r%d-t%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, ReviewId, UpdateDeltaTime)
        else:
            HeaderMessageId   = 'Message-ID: <webhook-%s-pull%d-v%d-p%d-r%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, ReviewId)
        if ParentReviewId:
            HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d-r%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, ParentReviewId)
        elif DeleteId or UpdateDeltaTime != 0:
            HeaderInReplyToId = 'In-Reply-To: <webhook-%s-pull%d-v%d-p%d-r%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, ReviewId)
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
    Pattern = '\n-- \n'
    Email = Email.split (Pattern, 1)[0] + Pattern
    Message = email.message_from_bytes(Email.encode('utf8','surrogateescape'))
    Body = Message.get_payload()
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
        if event in ['pull_request_review_comment', 'pull_request_review'] and ReviewComments:
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
                if ReviewId and DeleteId:
                    Body[0] = Body[0] + 'Review associated with CommentId %s was deleted' % (CommentId) + LineEnding
                elif CommentId:
                    Body[0] = Body[0] + 'Review associated with CommentId %s not found' % (CommentId) + LineEnding
                elif Review:
                    Body[0] = Body[0] + 'Review associated with ReviewId %s not found' % (Review.id) + LineEnding
                else:
                    Body[0] = Body[0] + 'Review associated with this pull request was not found' + LineEnding
                Body[0] = Body[0] + '-' * 20 + LineEnding

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

            #
            # If this is a pull request review comment then discard the file
            # change summary and insert the review comments at the specified
            # position in the pull request diff quoting the decription of the
            # pull request, the diff, and all previous comments.
            #

            #
            # Generate a quoted file diff for the commit range
            #
            Diff = '\n-- \n' + GitRepo.git.diff (CommitRange)
            Diff = QuoteText (''.join(Diff), '> ', 1)
            Diff = Diff.splitlines(keepends=True)

            #
            # If diff is > LargePatchLines, then only keep diff lines associated
            # with the files mentioned in the comments
            #
            if len(Diff) > LargePatchLines:
                NewDiff = []
                for CommentPath in CommentDict:
                    Start  = '> diff --git a/' + CommentPath + ' b/' + CommentPath + '\n'
                    End    = '> diff --git a/'
                    Match = False
                    for Line in Diff:
                        if Match and Line.startswith (End):
                            Match = False
                        if Line.startswith (Start):
                            Match = True
                        if Match:
                            NewDiff.append(Line)
                Diff = NewDiff

            #
            # Build dictionary of conversations at line nunbers in Diff
            #
            Conversations = {}
            for CommentPath in CommentDict:
                #
                # Find the line in Diff that contains the diffs against file
                # specified by CommentPath
                #
                Start   = '> diff --git a/' + CommentPath + ' b/' + CommentPath + '\n'
                FileFound = False
                DiffFound = False
                for StartLineNumber in range (0, len(Diff)):
                    if Diff[StartLineNumber].startswith(Start):
                        FileFound = True
                    if FileFound:
                        if Diff[StartLineNumber].startswith('> @@ '):
                            DiffFound = True
                            break
                if not DiffFound:
                    Diff.append('ERROR: Pull request %d review comment to file %s not found.\n' % (HubPullRequest.number, CommentPath))
                    continue

                for CommentPosition in CommentDict[CommentPath]:
                    CommentBody = QuoteCommentList (
                                      CommentDict[CommentPath][CommentPosition],
                                      LineEnding = LineEnding,
                                      Prefix     = ''
                                      )
                    Conversations[StartLineNumber + CommentPosition + 1] = CommentBody

            #
            # Insert conversations into the diff patch
            #
            DiffBody = ''
            PreviousLineNumber = 0
            LineNumbers = list(Conversations.keys())
            LineNumbers.sort()
            LineNumber = 0
            for LineNumber in LineNumbers:
                DiffBody = DiffBody + ''.join(Diff[PreviousLineNumber:LineNumber]) + Conversations[LineNumber]
                PreviousLineNumber = LineNumber
            DiffBody = DiffBody + ''.join(Diff[LineNumber:])

            #
            # Append diff patch with coversations to the email body
            #
            Body = Body[0] + '\n-- \n' + DiffBody
        else:
            #
            # If this is a comment against the description of the pull request
            # then discard the file change summary and append the review comments
            # quoting the decription of the pull request and all previous comments.
            #
            IssueComments = []
            for Comment in HubPullRequest.get_issue_comments():
                IssueComments.append(Comment)
            Reviews = HubPullRequest.get_reviews()
            Comments = HubPullRequest.get_review_comments()
            for Review in Reviews:
                Match = False
                for Comment in Comments:
                    if 'pull_request_review_id' in Comment.raw_data:
                        if Comment.raw_data['pull_request_review_id'] == Review.id:
                            Match = True
                            break
                if not Match:
                    Review.created_at = Review.submitted_at
                    IssueComments.append(Review)

            Body = QuoteCommentList (
                       IssueComments,
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
