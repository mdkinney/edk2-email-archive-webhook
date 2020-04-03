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

def FetchAllPullRequests (HubRepo, CommitId = None, Depth = 200):
    #
    # Fetch the base.ref branch and current PR branch from the base repository
    # of the pull request
    #
    RepositoryPath = os.path.normpath (os.path.join ('Repository', HubRepo.full_name))
    if os.path.exists (RepositoryPath):
        print ('mount', RepositoryPath)
        try:
            GitRepo = git.Repo(RepositoryPath)
            Origin = GitRepo.remotes['origin']
        except:
            print ('init', RepositoryPath)
            GitRepo = git.Repo.init (RepositoryPath, bare=True)
            Origin = GitRepo.create_remote ('origin', HubRepo.html_url)
    else:
        print ('init', RepositoryPath)
        os.makedirs (RepositoryPath)
        GitRepo = git.Repo.init (RepositoryPath, bare=True)
        Origin = GitRepo.create_remote ('origin', HubRepo.html_url)
    #
    # Shallow fetch HubRepo.default_branch branch from origin
    #
    print ('fetch', HubRepo.default_branch, 'from', RepositoryPath)
    Origin.fetch(HubRepo.default_branch, progress=Progress(), depth = Depth)
    print ('')
    #
    # Fetch the current pull request branch from origin
    #
    print ('fetch all pull requests from', RepositoryPath)
    Origin.fetch('+refs/pull/*/merge:refs/remotes/origin/pr/*', progress=Progress())
    print ('\nfetch', RepositoryPath, 'done')

    #
    # Retrieve the latest version of Maintainers.txt from origin/base.ref
    #
    try:
        Maintainers = GitRepo.git.show('origin/%s:Maintainers.txt' % (HubRepo.default_branch))
    except:
        print ('Maintainers.txt does not exist in origin/%s' % (HubRepo.default_branch))
        Maintainers = ''

    PullRequestList = []
    if CommitId is not None:
        Branches = GitRepo.git.branch('-a', '--contains', CommitId).splitlines()
        print (Branches)
        PullRequestList = [int(Branch.strip().split('/')[-1]) for Branch in Branches]
        print (PullRequestList)

    return GitRepo, Maintainers, PullRequestList

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

def CommentAsEmailText(Comment, LineEnding, Prefix, Depth):
    #
    # Wrap long lines in comment body, but never split HTML links that may
    # contain hyphens.
    #
    WrappedBody = []
    if Comment.body is not None:
        for Paragraph in Comment.body.splitlines(keepends=True):
            PrefixDepth = 0
            while Paragraph.startswith (Prefix):
                Paragraph = Paragraph[len(Prefix):]
                PrefixDepth = PrefixDepth + 1
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
            WrappedParagraph = QuoteText (LineEnding.join(WrappedParagraph), ' ', Length)
            WrappedParagraph = QuoteText (WrappedParagraph, Prefix, PrefixDepth)
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
        if CommentInReplyToId:
            Email = GitRepo.git.format_patch (
                      '--stdout',
                      '--to=' + ToAddress,
                      '--from=%s via TianoCore Webhook <webhook@tianocore.org>' % (CommentUser),
                      '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber, CommentInReplyToId),
                      '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber, CommentId),
                      '--subject-prefix=%s][PATCH v%d %*d/%d' % (HubRepo.name, PatchSeriesVersion, len(str(HubPullRequest.commits)), PatchNumber, HubPullRequest.commits),
                      CommitRange
                      )
        else:
            Email = GitRepo.git.format_patch (
                      '--stdout',
                      '--to=' + ToAddress,
                      '--from=%s via TianoCore Webhook <webhook@tianocore.org>' % (CommentUser),
                      '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber),
                      '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber, CommentId),
                      '--subject-prefix=%s][PATCH v%d %*d/%d' % (HubRepo.name, PatchSeriesVersion, len(str(HubPullRequest.commits)), PatchNumber, HubPullRequest.commits),
                      CommitRange
                      )
    else:
        Email = GitRepo.git.format_patch (
                  '--stdout',
                  '--to=' + ToAddress,
                  '--from=%s via TianoCore Webhook <webhook@tianocore.org>' % (HubPullRequest.user.login),
                  '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0),
                  '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber),
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
        UpdateDeltaTime = 0
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
    if CommentId:
        FromAddress = '%s via TianoCore Webhook <webhook@tianocore.org>' % (CommentUser)
        if CommentInReplyToId:
            if UpdateDeltaTime != 0:
                Email = GitRepo.git.format_patch (
                          '--stdout',
                          '--cover-letter',
                          '--to=' + ToAddress,
                          '--from=' + FromAddress,
                          '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId),
                          '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d-t%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId, UpdateDeltaTime),
                          '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                          CommitRange
                          )
            else:
                Email = GitRepo.git.format_patch (
                          '--stdout',
                          '--cover-letter',
                          '--to=' + ToAddress,
                          '--from=' + FromAddress,
                          '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentInReplyToId),
                          '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId),
                          '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                          CommitRange
                          )
        else:
            if UpdateDeltaTime != 0:
                Email = GitRepo.git.format_patch (
                          '--stdout',
                          '--cover-letter',
                          '--to=' + ToAddress,
                          '--from=' + FromAddress,
                          '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId),
                          '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d-t%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId, UpdateDeltaTime),
                          '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                          CommitRange
                          )
            else:
                Email = GitRepo.git.format_patch (
                          '--stdout',
                          '--cover-letter',
                          '--to=' + ToAddress,
                          '--from=' + FromAddress,
                          '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0),
                          '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId),
                          '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                          CommitRange
                          )
    else:
        FromAddress = '%s via TianoCore Webhook <webhook@tianocore.org>' % (HubPullRequest.user.login)
        if UpdateDeltaTime != 0:
            Email = GitRepo.git.format_patch (
                      '--stdout',
                      '--cover-letter',
                      '--to=' + ToAddress,
                      '--from=' + FromAddress,
                      '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0),
                      '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d-t%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, UpdateDeltaTime),
                      '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                      CommitRange
                      )
        else:
            Email = GitRepo.git.format_patch (
                      '--stdout',
                      '--cover-letter',
                      '--to=' + ToAddress,
                      '--from=' + FromAddress,
                      '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0),
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
    if HubPullRequest.body is not None:
        for Paragraph in HubPullRequest.body.splitlines(keepends=True):
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
            WrappedParagraph = QuoteText (LineEnding.join(WrappedParagraph), ' ', Length)
            Body[0] = Body[0] + WrappedParagraph

    #
    # If this is a comment against the description of the pull request
    # then discard the file change summary and append the review comments
    # quoting the decription of the pull request and all previous comments.
    # Otherwise, this is a Patch #0 email that includes the file change summary.
    #
    if CommentId:
        if event == 'pull_request_review_comment':
            #
            # If this is a pull request review comment then discard the file
            # change summary and insert the review comments at the specified
            # position in the pull request diff quoting the decription of the
            # pull request, the diff, and all previous comments.
            #

            #
            # Get the pull request review comments only keeping the comments
            # that match the CommentPath and CommentPosition from this event
            #
            Comments = []
            for Comment in HubPullRequest.get_review_comments():
                if Comment.path == CommentPath and Comment.position == CommentPosition:
                    Comments.append(Comment)

            #
            # Generate file diff for the commit range
            #
            Diff = '\n-- \n' + GitRepo.git.diff (CommitRange)

            #
            # Find the portion of the patch diffs that contain changes to the
            # file specified by CommentPath
            #
            Start   = '\ndiff --git a/' + CommentPath + ' b/' + CommentPath + '\n'
            End     = '\ndiff --git a/'
            try:
                Diff = Start + Diff.split(Start,1)[1].split(End,1)[0]
                Diff = Diff.lstrip()
            except:
                Diff = Diff + 'ERROR: Pull request %d review comment to file %s position %d not found.\n' % (HubPullRequest.number, CommentPath, CommentPosition)

            #
            # Find the first line of the patch diff for file CommentPath that
            # starts with '@@ '.
            #
            Diff = Diff.splitlines(keepends=True)
            for LineNumber in range(0, len(Diff)):
                if Diff[LineNumber].startswith('@@ '):
                    break

            #
            # Insert comments into patch at CommentPosition + 1 lines after '@@ '
            #
            LineNumber = LineNumber + CommentPosition + 1
            Body = QuoteCommentList (
                       Comments,
                       Before     = Body[0] + '\n-- \n' + ''.join(Diff[:LineNumber]),
                       After      = ''.join(Diff[LineNumber:]),
                       LineEnding = LineEnding,
                       Prefix     = Prefix
                       )
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
    Message.set_payload(Body)

    return Message.as_string()
