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

class Progress(git.remote.RemoteProgress):
    def __init__(self):
        git.remote.RemoteProgress.__init__(self)
        self.PreviousLine = ''
    def update(self, op_code, cur_count, max_count=None, message=''):
        Line = '\r' + self._cur_line
        if len(self.PreviousLine) > len(Line):
            Line = Line + '%*s' % (len(self.PreviousLine) - len(Line), ' ')
        sys.stdout.write(Line)
        self.PreviousLine = Line

def FetchPullRequest (HubPullRequest):
    #
    # Fetch the base.ref branch and current PR branch from the base repository
    # of the pull request
    #
    if os.path.exists (HubPullRequest.base.repo.name):
        print ('mount', HubPullRequest.base.repo.full_name)
        try:
            GitRepo = git.Repo(HubPullRequest.base.repo.name)
            Origin = GitRepo.remotes['origin']
        except:
            print ('init', HubPullRequest.base.repo.full_name)
            GitRepo = git.Repo.init (HubPullRequest.base.repo.name, bare=True)
            Origin = GitRepo.create_remote ('origin', HubPullRequest.base.repo.html_url)
    else:
        print ('init', HubPullRequest.base.repo.full_name)
        os.mkdir (HubPullRequest.base.repo.name)
        GitRepo = git.Repo.init (HubPullRequest.base.repo.name, bare=True)
        Origin = GitRepo.create_remote ('origin', HubPullRequest.base.repo.html_url)
    print ('fetch', HubPullRequest.base.repo.full_name)
    #
    # Shallow fetch base.ref branch from origin
    #
    Origin.fetch(HubPullRequest.base.ref, progress=Progress(), depth = 1)
    #
    # Fetch the current pull request branch from origin
    #
    Origin.fetch('+refs/pull/%d/merge:refs/remotes/origin/pr/%d' % (HubPullRequest.number, HubPullRequest.number), progress=Progress())
    print ('fetch', HubPullRequest.base.repo.full_name, 'done')

    #
    # Retrieve the latest version of Maintainers.txt from origin/base.ref
    #
    try:
        Maintainers = GitRepo.git.show('origin/%s:Maintainers.txt' % (HubPullRequest.base.ref))
    except:
        print ('Maintainers.txt does not exist in origin/%s' % (HubPullRequest.base.ref))
        Maintainers = ''

    return GitRepo, Maintainers
