## @file
# TianoCore Code Review Archive Service Global Variables
#
# Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##
'''
TianoCore Code Review Archive Service Global Variables
'''
import os
import threading
import persistqueue

def Initialize():
    global GitRepositoryLockDict
    global RepoQueueDict
    global EmailQueue

    GitRepositoryLockDict = {}
    RepoQueueDict         = {}
    EmailQueue            = None

def AcquireRepositoryLock(GithubRepo):
    global GitRepositoryLockDict

    if GithubRepo not in GitRepositoryLockDict:
        print ('Create repo git lock', GithubRepo)
        GitRepositoryLockDict[GithubRepo] = threading.Lock()
    GitRepositoryLockDict[GithubRepo].acquire()

def ReleaseRepositoryLock(GithubRepo):
    global GitRepositoryLockDict

    if GithubRepo not in GitRepositoryLockDict:
        print ('Create repo git lock', GithubRepo)
        GitRepositoryLockDict[GithubRepo] = threading.Lock()
        return
    GitRepositoryLockDict[GithubRepo].release()

def GetRepositoryQueue(GithubRepo):
    global RepoQueueDict

    if GithubRepo not in RepoQueueDict:
        print ('Open repo queue file', GithubRepo)
        RepoQueueDict[GithubRepo] = persistqueue.UniqueAckQ(
            os.path.normpath(os.path.join('Queue', GithubRepo)),
            multithreading=True
            )
    return RepoQueueDict[GithubRepo]

def GetEmailQueue():
    global EmailQueue

    if EmailQueue is None:
        print ('Open email queue file')
        EmailQueue = persistqueue.UniqueAckQ(
            os.path.normpath(os.path.join('Queue', 'Email')),
            multithreading=True
            )
    return EmailQueue
