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
        print ('pr[%d]' % (HubPullRequest.number), 'mount', RepositoryPath)
        try:
            GitRepo = git.Repo(RepositoryPath)
            Origin = GitRepo.remotes['origin']
        except:
            print ('pr[%d]' % (HubPullRequest.number), 'init', RepositoryPath)
            GitRepo = git.Repo.init (RepositoryPath, bare=True)
            Origin = GitRepo.create_remote ('origin', HubPullRequest.base.repo.html_url)
    else:
        print ('pr[%d]' % (HubPullRequest.number), 'init', RepositoryPath)
        os.makedirs (RepositoryPath)
        GitRepo = git.Repo.init (RepositoryPath, bare=True)
        Origin = GitRepo.create_remote ('origin', HubPullRequest.base.repo.html_url)
    #
    # Shallow fetch base.ref branch from origin
    #
    print ('pr[%d]' % (HubPullRequest.number), 'fetch', HubPullRequest.base.ref, 'from', RepositoryPath)
    Origin.fetch(HubPullRequest.base.ref, progress=Progress(), depth = Depth)
    #
    # Fetch the current pull request branch from origin
    #
    print ('pr[%d]' % (HubPullRequest.number), 'fetch pull request', HubPullRequest.number, 'from', RepositoryPath)
    Origin.fetch('+refs/pull/%d/merge:refs/remotes/origin/pr/%d' % (HubPullRequest.number, HubPullRequest.number), progress=Progress())
    print ('pr[%d]' % (HubPullRequest.number), 'fetch', RepositoryPath, 'done')

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

def FormatPatch (GitRepo, HubRepo, HubPullRequest, Commit, AddressList, PatchSeriesVersion, PatchNumber, CommentId = None, CommentPosition = None, CommentLine = None, CommentPath = None, Prefix = ''):
    #
    # Format the Subject:
    #   [<repo name>][PATCH v<patch series version> <patch number>/<number of patches>]
    # Format the Messsage-ID:
    #   <webhook-<repo name>-pr<pull>-v<patch series version>-p<patch number>@tianocore.org>
    #
    if CommentId:
        Email = GitRepo.git.format_patch (
                  '--stdout',
                  '--from=TianoCore <webhook@tianocore.org>',
                  '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber),
                  '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber, CommentId),
                  '--subject-prefix=%s][PATCH v%d %*d/%d' % (HubRepo.name, PatchSeriesVersion, len(str(HubPullRequest.commits)), PatchNumber, HubPullRequest.commits),
                  Commit.sha + '~1..' + Commit.sha
                  )
    else:
        Email = GitRepo.git.format_patch (
                  '--stdout',
                  '--from=TianoCore <webhook@tianocore.org>',
                  '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0),
                  '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber),
                  '--subject-prefix=%s][PATCH v%d %*d/%d' % (HubRepo.name, PatchSeriesVersion, len(str(HubPullRequest.commits)), PatchNumber, HubPullRequest.commits),
                  Commit.sha + '~1..' + Commit.sha
                  )
    #
    # Remove first line from format-patch that is not part of email
    #
    Email = Email.splitlines(keepends=True)[1:]

    LineEnding = GetLineEnding (Email[0])

    ModifiedEmail = []
    Found = False
    for Line in Email:
        ModifiedEmail.append(Line)
        if Found or Line.rstrip() != '---':
            continue
        Found = True
        ModifiedEmail.append('#' * 4 + LineEnding)
        #
        # Add link to pull request
        #
        ModifiedEmail.append('# PR: ' + HubPullRequest.html_url + LineEnding)
        #
        # Add link to commit
        #
        ModifiedEmail.append('# Commit: ' + Commit.html_url + LineEnding)
        #
        # Add list of assigned reviewers
        #
        for Address in AddressList:
            ModifiedEmail.append('# ' + Address + LineEnding)
        ModifiedEmail.append('#' * 4 + LineEnding)
        if CommentId:
            break
    ModifiedEmail = ''.join(ModifiedEmail)

    #
    # If Prefix is provided, then add to beginning of each line
    #
    if Prefix:
        BodyFound = False
        ModifiedEmail = ModifiedEmail.splitlines(keepends=True)
        for LineNumber in range(0, len(ModifiedEmail)):
            if BodyFound:
                ModifiedEmail[LineNumber] = Prefix + ModifiedEmail[LineNumber]
            if ModifiedEmail[LineNumber].strip() == '':
                BodyFound = True
        ModifiedEmail = ''.join(ModifiedEmail)

    if CommentId:
        CommentText = ''
        for Comment in Commit.get_comments():
            AddComment = False
            if None in [CommentPosition, CommentLine, CommentPath]:
                if None in [Comment.position, Comment.line, Comment.path]:
                    AddComment = True
            if None not in [CommentPosition, CommentLine, CommentPath]:
                if None not in [Comment.position, Comment.line, Comment.path]:
                    AddComment = True
            if not AddComment:
                continue
            Text = 'On ' + str(Comment.created_at) + ' @' + Comment.user.login + ' wrote:' + LineEnding + Comment.body  + LineEnding
            if Comment.id != CommentId:
                Text = Prefix + Prefix.join(Text.splitlines(keepends=True))
            CommentText = CommentText + Text
        if None in [CommentPosition, CommentLine, CommentPath]:
            #
            # Append comments after commit message
            #
            ModifiedEmail = ModifiedEmail + CommentText
        else:
            #
            # Insert comments into patch
            #
            Email = ''.join(Email)
            Pattern = '\ndiff --git a/' + CommentPath + ' b/' + CommentPath + '\n'
            Email = Email.split (Pattern, 1)[1]
            Email = Pattern + Email.split ('\ndiff --git a/')[0]
            Email = Email.splitlines (keepends=True)
            QuotedEmail = []
            for Index in range(0, len(Email)):
                if Email[Index].startswith('@@ '):
                    ModifiedEmail = ModifiedEmail + Prefix + Prefix.join(Email[:Index+CommentLine+1]) + CommentText + Prefix + Prefix.join(Email[Index+CommentLine+1:])
                    break

    #
    # Add Re: to Subject if a comment is being processed
    #
    Message = email.message_from_string(ModifiedEmail)
#    if CommentId:
#        Message.replace_header('Subject', 'Re: [edk2codereview] ' + Message['Subject'])

    return Message.as_string()

def FormatPatchSummary (GitRepo, HubRepo, HubPullRequest, AddressList, PatchSeriesVersion, CommentId = None, Prefix = ''):
    #
    # Format the Subject:
    #   [<repo name>][PATCH v<patch series version> <patch number>/<number of patches>]
    # Format the Messsage-ID:
    #   <webhook-<repo name>-pr<pull>-v<patch series version>-p<patch number>@tianocore.org>
    #
    if CommentId:
        Summary = GitRepo.git.format_patch (
                    '--stdout',
                    '--cover-letter', 
                    '--from=TianoCore <webhook@tianocore.org>',
                    '--add-header=In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0),
                    '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, CommentId),
                    '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                    HubPullRequest.base.sha + '..' + HubPullRequest.head.sha
                    )
    else:
        Summary = GitRepo.git.format_patch (
                    '--stdout',
                    '--cover-letter', 
                    '--from=TianoCore <webhook@tianocore.org>',
                    '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0),
                    '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                    HubPullRequest.base.sha + '..' + HubPullRequest.head.sha
                    )
    #
    # Remove first line from format-patch that is not part of email
    #
    Summary = ''.join(Summary.splitlines(keepends=True)[1:])

    LineEnding = GetLineEnding (Summary[0])

    #
    # Parse the cover letter summary from git format-patch
    #
    Summary = Summary.split ('\n-- \n', 1)[0] + '\n-- \n'

    #
    # Add link to pull request
    #
    Blurb = []
    Blurb.append('#' * 4 + LineEnding)
    Blurb.append('# PR: ' + HubPullRequest.html_url + LineEnding)

    #
    # Add list of assigned reviewers
    #
    for Address in AddressList:
        Blurb.append('# ' + Address + LineEnding)
    Blurb.append('#' * 4 + LineEnding)
    Blurb.append(LineEnding)

    #
    # Replace *** BLURB HERE *** with the pull request body
    #
    Summary = Summary.split ('*** BLURB HERE ***', 1)
    Summary[0] = Summary[0] + ''.join(Blurb) + HubPullRequest.body
    if CommentId:
        Summary = Summary[0]
    else:
        Summary = Summary[0] + Summary[1]

    #
    # If Prefix is provided, then add to beginning of each line
    #
    if Prefix:
        BodyFound = False
        Summary = Summary.splitlines(keepends=True)
        for LineNumber in range(0, len(Summary)):
            if BodyFound:
                Summary[LineNumber] = Prefix + Summary[LineNumber]
                if CommentId:
                    Summary[LineNumber] = Prefix + Summary[LineNumber]
            if Summary[LineNumber].strip() == '':
                BodyFound = True
        Summary = ''.join(Summary)

    if CommentId:
        CommentText = ''
        for Comment in HubPullRequest.get_issue_comments():
            Text = 'On ' + str(Comment.created_at) + ' @' + Comment.user.login + ' wrote:' + LineEnding + Comment.body  + LineEnding
            if Comment.id != CommentId:
                Text = Prefix + Prefix.join(Text.splitlines(keepends=True))
            CommentText = CommentText + Text
        Summary = Summary + CommentText

    #
    # Update incorrect From: line in git format-patch cover letter
    # Replace *** SUBJECT HERE *** with the pull request title
    # Add Re: to Subject if comment is being processed
    #
    Message = email.message_from_string(Summary)
    Message.replace_header('From', 'TianoCore <webhook@tianocore.org>')
    Message.replace_header('Subject', Message['Subject'].replace ('*** SUBJECT HERE ***', HubPullRequest.title))
#    if CommentId:
#        Message.replace_header('Subject', 'Re: [edk2codereview] ' + Message['Subject'])

    return Message.as_string()
