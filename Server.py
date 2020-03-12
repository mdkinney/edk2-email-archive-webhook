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

import os
import sys
import argparse
import hmac
from json import dumps
from flask import Flask, request, abort
from github import Github
from GetMaintainers import GetMaintainers
from SendEmails import SendEmails
from FetchPullRequest import FetchPullRequest

#
# Globals for help information
#
__prog__        = 'TianoCoreGitHubWebHookServer'
__copyright__   = 'Copyright (c) 2020, Intel Corporation. All rights reserved.'
__description__ = 'Assign reviewers to commits in a GitHub pull request based on assignments documented in Maintainers.txt and generate email archive of all review activities.\n'

GITHUB_TOKEN               = os.environ['GITHUB_TOKEN']
GITHUB_WEBHOOK_SECRET      = os.environ['GITHUB_WEBHOOK_SECRET']
GITHUB_WEBHOOK_ROUTE       = os.environ['GITHUB_WEBHOOK_ROUTE']
GITHUB_WEBHOOK_PORT_NUMBER = int(os.environ['GITHUB_WEBHOOK_PORT_NUMBER'])
GITHUB_REPO_WHITE_LIST     = os.environ['GITHUB_REPO_WHITE_LIST']

application = Flask(__name__)

@application.route(GITHUB_WEBHOOK_ROUTE, methods=['GET', 'POST'])
def index():
    """
    Main WSGI application entry.
    """
    print (request.headers)
    
    # Only POST is implemented
    if request.method != 'POST':
        print (501, "only POST is supported")
        abort(501, "only POST is supported")

    # Enforce secret, so not just anybody can trigger these hooks
    secret = GITHUB_WEBHOOK_SECRET
    if secret:
        # Only SHA1 is supported
        header_signature = request.headers.get('X-Hub-Signature')
        if header_signature is None:
            print (403, "No header signature found")
            abort(403, "No header signature found")

        sha_name, signature = header_signature.split('=')
        if sha_name != 'sha1':
            print(501, "Only SHA1 is supported")
            abort(501, "Only SHA1 is supported")

        # HMAC requires the key to be bytes, but data is string
        mac = hmac.new(bytes(secret, 'utf-8'), msg=request.data, digestmod='sha1')

        # Python does not have hmac.compare_digest prior to 2.7.7
        if sys.hexversion >= 0x020707F0:
            if not hmac.compare_digest(str(mac.hexdigest()), str(signature)):
                print(403, "hmac compare digest failed")
                abort(403)
        else:
            # What compare_digest provides is protection against timing
            # attacks; we can live without this protection for a web-based
            # application
            if not str(mac.hexdigest()) == str(signature):
                print(403, "hmac compare digest failed")
                abort(403)

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

    # Determining the branch can be tricky, as it only appears for certain event
    # types, and at different levels
    branch = None
    try:
        # Case 1: a ref_type indicates the type of ref.
        # This true for create and delete events.
        if 'ref_type' in payload:
            if payload['ref_type'] == 'branch':
                branch = payload['ref']

        # Case 2: a pull_request object is involved. This is pull_request and
        # pull_request_review_comment events.
        elif 'pull_request' in payload:
            # This is the TARGET branch for the pull-request, not the source
            # branch
            branch = payload['pull_request']['base']['ref']

        elif event in ['push']:
            # Push events provide a full Git ref in 'ref' and not a 'ref_type'.
            branch = payload['ref'].split('/', 2)[2]

    except KeyError:
        # If the payload structure isn't what we expect, we'll live without
        # the branch name
        pass

    #
    # Skip push and create events
    #
    if event in ['push', 'create']:
        print ('skip event', event)
        return dumps({'status': 'skipped'})

    #
    # Skip payload that does not provide a repository
    #
    if 'repository' not in payload:
        print ('skip payload that does not provide a repository', event)
        return dumps({'status': 'skipped'})

    #
    # Skip payload that does not provide a repository full name
    #
    if 'full_name' not in payload['repository']:
        print ('skip payload that does not provide a repository full name', event)
        return dumps({'status': 'skipped'})

    #
    # Skip requests that are not in GITHUB_REPO_WHITE_LIST
    #
    if payload['repository']['full_name'] not in GITHUB_REPO_WHITE_LIST:
        print ('skip event for different repo')
        return dumps({'status': 'skipped'})

    #
    # Process issue comment events
    # These are comments against the entire pull request
    # Quote Patch #0 Body and add comment below below with commenters GitHubID
    #
    if event == 'issue_comment':
      action = payload['action']
      if action not in ['created', 'edited']:
          print ('skip issue_comment event with action other than created or edited')
          return dumps({'status': 'skipped'})
      if 'pull_request' not in payload['issue']:
          print ('skip issue_comment event without an associated pull request')
          return dumps({'status': 'skipped'})

      # 
      # Use GitHub API to get Pull Request
      #
      try:
          HubRepo = Hub.get_repo (payload['repository']['full_name'])
          HubPullRequest = HubRepo.get_pull(payload['issue']['number'])
      except:
          #
          # Skip requests if the PyGitHub objects can not be retrieved
          #
          print ('skip issue_comment event for which the PyGitHub objects can not be retrieved')
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
      # Count head_ref_force_pushed events to determine the version of 
      # the patch series.
      #
      PatchSeriesVersion = 1;
      Events = HubPullRequest.get_issue_events()
      for Event in Events:
          if Event.event == 'head_ref_force_pushed':
              PatchSeriesVersion = PatchSeriesVersion + 1;


      print ('From: TianoCore <webhook@tianocore.org>')
      print ('Subject: Re [edk2codereview][%s][PATCH v%d %*d/%d] %s' % (HubRepo.name, PatchSeriesVersion, len(str(HubPullRequest.commits)), 0, HubPullRequest.commits, HubPullRequest.title))
      print ('In-Reply-To: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0))
      print ('Message-ID: <webhook-%s-pull%d-v%d-p%d-c%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0, payload['comment']['id']))
      
      print ('')
      print ('> ' + '> '.join(HubPullRequest.body.splitlines(keepends=True)))
      print ('')
      print ('@' + payload['comment']['user']['login'] + ' commented:')
      print (payload['comment']['body'])

      #
      # Send any generated emails
      #
#      SendEmails (EmailContents, args.EmailServer)

      print ('issue_comment created or edited done')
      return dumps({'msg': 'issue_comment created or edited'})

    #
    # Process pull request events
    #
    if event == 'pull_request':
      action = payload['action']
      if action not in ['opened', 'synchronize']:
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

      NewPatchSeries = False
      PatchSeriesVersion = 1;
      if action == 'opened':
          #
          # New pull request was created
          #
          NewPatchSeries = True
      if action == 'synchronize':
          #
          # Existing pull request was updated.
          # Commits were added to an existing pull request or an existing pull
          # request was forced push.  Get events to determine what happened
          #
          Events = HubPullRequest.get_issue_events()
          for Event in Events:
              #
              # Count head_ref_force_pushed events to determine the version of 
              # the patch series.
              #
              if Event.event == 'head_ref_force_pushed':
                  PatchSeriesVersion = PatchSeriesVersion + 1;
                  #
                  # If the head_ref_force_pushed event occurred at the exact
                  # same date/time (or within 2 seconds) that the pull request
                  # was updated, then this was a forced push and the entire
                  # patch series should be emailed again.
                  #
                  if abs(Event.created_at - HubPullRequest.updated_at).seconds <= 2:
                      NewPatchSeries = True

      GitHubIdList = []
      EmailList = []
      PullRequestEmailAddressList = []
      EmailContents = []
      PatchNumber = 0
      for Commit in HubPullRequest.get_commits():
        PatchNumber = PatchNumber + 1
        #
        # Get commit from GIT repository
        #
        CommitFiles = GitRepo.commit(Commit.sha).stats.files

        #
        # Get maintainers and reviewers for all files in this commit
        #
        Addresses = GetMaintainers (Maintainers, CommitFiles)

        #
        # Determine GitHub IDs of required reviewers
        #
        SingleCommitGitHubIdList = []
        SingleCommitEmailAddressList = []
        for Line in Addresses:
            Line = Line.strip()
            if Line.split(':')[0] not in ['R', 'M']:
                continue
            if Line.split(':')[0] == 'R':
                SingleCommitEmailAddressList.append('Reviewer  : ' + Line.split(':')[1].strip())
                PullRequestEmailAddressList.append('Reviewer  : ' + Line.split(':')[1].strip())
            if Line.split(':')[0] == 'M':
                SingleCommitEmailAddressList.append('Maintainer: ' + Line.split(':')[1].strip())
                PullRequestEmailAddressList.append('Maintainer: ' + Line.split(':')[1].strip())
            if '[' in Line and ']' in Line:
                print (__prog__ + ': Parse GitHub ID from: ', Line)
                GitHubId = Line.split('[')[1].split(']')[0].strip()
                if GitHubId:
                    SingleCommitGitHubIdList.append(GitHubId)
                    GitHubIdList.append(GitHubId)
                else:
                    print (__prog__ + ': error: Missing GitHub ID: ' + Line)
                    continue
            else:
                print (__prog__ + ': error: Missing GitHub ID: ' + Line)
                continue
            if '<' in Line and '>' in Line:
                print (__prog__ + ': Parse email from: ', Line)
                Email = Line.split('<')[1].split('>')[0].strip()
                if '@' in Email:
                    EmailList.append(Email)
                else:
                    print (__prog__ + ': error: Invalid email address: ' + Line)
                    continue
            else:
                print (__prog__ + ': error: Missing email address: ' + Line)
                continue
        SingleCommitGitHubIdList = list(set(SingleCommitGitHubIdList))

        #
        # Retrieve all review comments for this commit
        #
        Body = ''
        Comments = Commit.get_comments()
        for Comment in Comments:
            Body = Body + Comment.body
        Body = Body.splitlines()
        print (Body)
        
        AddReviewers = []
        for Reviewer in SingleCommitGitHubIdList:
            if 'Review Request: @' + Reviewer not in Body:
                AddReviewers.append(Reviewer)
        if AddReviewers != []:
            print ('Assign Reviewers to commit', Commit.sha, AddReviewers)
            Commit.create_comment ('Review Request: @' + '\nReview Request: @'.join(AddReviewers))

        #
        # Generate email contents for all commits in a pull request if this is
        # a new pull request or a forced push was done to an existing pull request.
        # Generate email contents for patches that add new reviewers.  This 
        # occurs when when new commits are added to an existing pull request.
        #
        if NewPatchSeries or AddReviewers != []:
            #
            # Format the Subject:
            #   [<repo name>][PATCH v<patch series version> <patch number>/<number of patches>]
            # Format the Messsage-ID:
            #   <webhook-<repo name>-pr<pull>-v<patch series version>-p<patch number>@tianocore.org>
            #
            Email = GitRepo.git.format_patch (
                      '--stdout',
                      '--from=TianoCore <webhook@tianocore.org>',
                      '--subject-prefix=%s][PATCH v%d %*d/%d' % (HubRepo.name, PatchSeriesVersion, len(str(HubPullRequest.commits)), PatchNumber, HubPullRequest.commits),
                      '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, PatchNumber),
                      Commit.sha + '~1..' + Commit.sha
                      )
            Email = Email.splitlines (keepends=True)
            EmailLineEnding = '\n'
            if Email[0].endswith('\r\n'):
                EmailLineEnding = '\r\n'
            elif Email[0].endswith('\r'):
                EmailLineEnding = '\r'

            ModifiedEmail = []
            Found = False
            for Line in Email:
                ModifiedEmail.append(Line)
                if Found or Line.rstrip() != '---':
                    continue
                Found = True
                ModifiedEmail.append('#' * 4 + EmailLineEnding)
                #
                # Add link to pull request
                #
                ModifiedEmail.append('# PR: ' + HubPullRequest.html_url + EmailLineEnding)
                #
                # Add link to commit
                #
                ModifiedEmail.append('# Commit: ' + Commit.html_url + EmailLineEnding)
                #
                # Add list of assigned reviewers
                #
                for Address in SingleCommitEmailAddressList:
                    ModifiedEmail.append('# ' + Address + EmailLineEnding)
                ModifiedEmail.append('#' * 4 + EmailLineEnding)
            EmailContents.append (''.join(ModifiedEmail))

      GitHubIdList = list(set(GitHubIdList))
      EmailList    = list(set(EmailList))
      PullRequestEmailAddressList = list(set(PullRequestEmailAddressList))

      #
      # Determine list of reviewers to add and remove to the entire pull request
      #
      RequestedReviewers = HubPullRequest.get_review_requests()[0]

      RemoveReviewerList = []
      for Reviewer in RequestedReviewers:
          if Reviewer.login not in GitHubIdList:
              print ('Remove Reviewer  :', Reviewer.login)
              RemoveReviewerList.append(Reviewer.login)

      AddReviewerList = []
      for Login in GitHubIdList:
          Reviewer = Hub.get_user(Login)
          if Reviewer == HubPullRequest.user:
              print ('Reviewer is Author :', Reviewer.login)
          elif Reviewer not in RequestedReviewers:
              print ('Add Reviewer     :', Reviewer.login)
              AddReviewerList.append (Reviewer.login)
          else:
              print ('Already Assigned :', Reviewer.login)

      #
      # Update review requests
      #
      if RemoveReviewerList != []:
          HubPullRequest.delete_review_request (RemoveReviewerList)
      if AddReviewerList != []:
          HubPullRequest.create_review_request (AddReviewerList)

      if NewPatchSeries:
          #
          # Format the Subject:
          #   [<repo name>][PATCH v<patch series version> <patch number>/<number of patches>]
          # Format the Messsage-ID:
          #   <webhook-<repo name>-pr<pull>-v<patch series version>-p<patch number>@tianocore.org>
          #
          Patches = GitRepo.git.format_patch (
                    '--stdout',
                    '--from=TianoCore <webhook@tianocore.org>',
                    '--cover-letter', 
                    '--subject-prefix=%s][PATCH v%d' % (HubRepo.name, PatchSeriesVersion),
                    '--add-header=Message-ID: <webhook-%s-pull%d-v%d-p%d@tianocore.org>' % (HubRepo.name, HubPullRequest.number, PatchSeriesVersion, 0),
                    HubPullRequest.base.sha + '..' + HubPullRequest.head.sha
                    )
          Summary = Patches.split ('\n-- \n', 1)[0] + '\n-- \n'
          Summary = Summary.replace ('*** SUBJECT HERE ***', HubPullRequest.title, 1)

          Email = Summary.splitlines (keepends=True)[1:]
          EmailLineEnding = '\n'
          if Email[0].endswith('\r\n'):
              EmailLineEnding = '\r\n'
          elif Email[0].endswith('\r'):
              EmailLineEnding = '\r'

          for LineNumber in range(0, len(Email)):
              if Email[LineNumber].startswith('From: '):
                  Email[LineNumber] = 'From: TianoCore <webhook@tianocore.org>' + EmailLineEnding
                  break
          Summary = ''.join(Email)

          Blurb = []
          Blurb.append('#' * 4 + EmailLineEnding)
          #
          # Add link to pull request
          #
          Blurb.append('# PR: ' + HubPullRequest.html_url + EmailLineEnding)
          #
          # Add list of assigned reviewers
          #
          for Address in PullRequestEmailAddressList:
              Blurb.append('# ' + Address + EmailLineEnding)
          Blurb.append('#' * 4 + EmailLineEnding)
          Blurb.append(EmailLineEnding)
          Summary = Summary.replace ('*** BLURB HERE ***', ''.join(Blurb) + HubPullRequest.body, 1)
          EmailContents = [Summary] + EmailContents

      #
      # Send any generated emails
      #
      SendEmails (EmailContents, args.EmailServer)

      print ('pull_request opened or synchronize done')
      return dumps({'msg': 'pull_request opened or synchronize'})

    print ('skip unsupported event')
    return dumps({'status': 'skipped'})

if __name__ == '__main__':
    #
    # Create command line argument parser object
    #
    parser = argparse.ArgumentParser (prog = __prog__,
                                      description = __description__ + __copyright__,
                                      conflict_handler = 'resolve')
    parser.add_argument ("-e", "--email-server", dest = 'EmailServer', choices = ['SMTP', 'SendGrid'], required = True,
                         help = "Email server type used to send emails.")
    parser.add_argument ("-v", "--verbose", dest = 'Verbose', action = "store_true",
                         help = "Increase output messages")
    parser.add_argument ("-q", "--quiet", dest = 'Quiet', action = "store_true",
                         help = "Reduce output messages")
    parser.add_argument ("--debug", dest = 'Debug', type = int, metavar = '[0-9]', choices = range (0, 10), default = 0,
                         help = "Set debug level")

    #
    # Parse command line arguments
    #
    args = parser.parse_args ()

    #
    # Create GitHub object authenticated using GitHub Token for the webhook
    #
    try:
        Hub = Github (GITHUB_TOKEN)
    except:
        print ('can not access GitHub APIs')
        sys.exit(1)

    try:
        application.run(debug=False, host='localhost', port=GITHUB_WEBHOOK_PORT_NUMBER)
    except:
        print ('can not create listener for GitHub HTTP requests')
        sys.exit(1)
