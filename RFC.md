[edk2-rfc] GitHub Pull Request based Code Review Process

Hello,

This is a proposal to change from the current email-based code review process to
a GitHub pull request-based code review process for all repositories maintained
in TianoCore.  The current email-based code review process and commit message
requirements are documented in Readme.md or Readme.rst at the root of
repositories along with a few Wiki pages:

* https://github.com/tianocore/edk2/blob/master/ReadMe.rst
* https://github.com/tianocore/tianocore.github.io/wiki/EDK-II-Development-Process
* https://github.com/tianocore/tianocore.github.io/wiki/Laszlo's-unkempt-git-guide-for-edk2-contributors-and-maintainers
* https://github.com/tianocore/tianocore.github.io/wiki/Commit-Message-Format
* https://github.com/tianocore/tianocore.github.io/wiki/Commit-Signature-Format

The goal is to post changes by opening a GitHub pull request and perform all
code review activity using the GitHub web interface.  This proposal does not
change any licenses or commit message requirements.  It does require all
developers, maintainers, and reviewers to have GitHub accounts.

One requirement that was collected from previous discussions on this topic is
the need for an email archive of all patches and code review activities.  The
existing GitHub features to produce an email archive were deemed insufficient.
A proof of concept of a GitHub webhook has been implemented to provide the email
archive service.  This email archive is read-only.  You will not be able to send
emails to this archive or reply to emails in the archive.

The sections below provide more details on the proposed GitHub pull request
based code review process, details on the email archive service, and a set of
remaining tasks make the email archive service production quality.  It does not
make sense to support both the existing email-based code review and the GitHub
pull request-based code review at the same time.  Instead, this proposal is to
switch to the GitHub pull request-based code review and retire the email based
code review process on the same date.

The edk2 repository is using GitHub pull requests today to run automated
CI checks on the code changes and allows a maintainer to set the `push` label to
request the changes to be merged if all CI checks pass.  With this proposal,
once the code review is complete and the commit messages have been updated, the
same pull request can be used to perform a final set of CI checks and merge the
changes into the master branch.

I would like to collect feedback on this proposal and the email archive service
over the next two weeks with close of comments on Friday May 22, 2020.  If all
issues and concerns can be addressed, then I would like to see the community
agree to make this change as soon as all remaining tasks are completed.

# TianoCore Repositories to enable

* [edk2](https://github.com/tianocore/edk2)
* [edk2-platforms](https://github.com/tianocore/edk2-platforms)
* [edk2-non-osi](https://github.com/tianocore/edk2-non-osi)
* [edk2-test](https://github.com/tianocore/edk2-test)
* [edk2-libc](https://github.com/tianocore/edk2-libc)
* [edk2-staging](https://github.com/tianocore/edk2-staging)

# GitHub Pull Request Code Review Process

**NOTE**: All steps below use [edk2](https://github.com/tianocore/edk2) as an
example.  Several repositories are supported.

## Author/Developer Steps
  * Create a personal fork of [edk2](https://github.com/tianocore/edk2)

    https://help.github.com/en/github/getting-started-with-github/fork-a-repo

  * Create a new branch from edk2/master in personal fork of edk2 repository.

  * Add set of commits for new feature or bug fix to new branch.  Make sure to
    follow the commit message format requirements.  The only change with this
    RFC is that the Cc: lines to maintainers/reviewers should **not** be added.
    The Cc: lines are still supported, but they should only be used to add
    reviewers that do not have GitHub IDs or are not members of TianoCore.

  * Push branch with new commits to personal fork
  * Create a pull request against TianoCore edk2/master

    https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/creating-a-pull-request

  * If pull request has more than 1 commit, then fill in the pull request title
    and decryption information for Patch #0.  Do not leave defaults.

  * Do not assign reviewers.  The webhook assigns maintainers and reviewers to
    the pull request and each commit in the pull request.

  * If maintainers/reviewers provide feedback that requires changes, then make
    add commits to the current branch with the requested changes.  Once all
    changes are accepted on the current branch, reformulate the patch series and
    commit comments as needed for perform a forced push to the branch in the
    personal fork of the edk2 repository.  This step may be repeated if multiple
    versions of the patch series are required to address all code review
    feedback.

  **OPEN**: How should minimum review period be set?  Labels?

## TianoCore GitHub Email Archive Webhook Service Steps
  * Receive an event that a new pull request was opened
  * Evaluate the files modified by the entire pull request and each commit in
    the pull request and cross references against `Maintainters.txt` in the root
    of the repository to assign maintainers/reviewers to the pull request and
    each commit in the pull request. Individual commit assignments are performed
    by adding a commit comment of the following form:

    [CodeReview] Review-request @mdkinney

  * Generate and sends git patch review emails to the email archive.  Emails
    are also sent to any Cc: tags in the commit messages.

  * If the author/developer performs a forced push to the branch in their
    personal fork of the edk2 repository, then a new set of patch review emails
    with patch series Vx is sent to the email archive and any Cc: tags in commit
    messages.

  * Receive events associated with all code review activities and generate
    and send emails to the email archive that shows all review comments and
    all responses closely matching the email contents seen in the current email
    based code review process.

  * Generate and send email when pull request is merged or closed.

## Maintainer/Reviewer Steps

  * Make sure GitHub configuration is setup to 'Watch' the repositories that
    you have maintainer ship or review responsibilities and that email
    notifications from GitHub are enabled.  This enables email notifications
    when a maintainer/reviewer is assigned to a pull request and individual
    commits.

    https://help.github.com/en/github/managing-subscriptions-and-notifications-on-github/configuring-notifications

  * Subscribe to the email archive associated with the TianoCore GitHub Email
    Archive Webhook Service.

    https://www.redhat.com/mailman/listinfo/tianocore-code-review-poc

  * Review pull requests and commits assigned by the TianoCore GitHub Email
    Archive Webhook Service and use the GitHub web UI to provide all review
    feedback.

    https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/reviewing-changes-in-pull-requests

  * Wait for Author/Developer to respond to all feedback and add commits with
    code changes as needed to resolve all feedback.  This step may be repeated
    if the developer/author need to produce multiple versions of the patch
    series to address all feedback.

  * Once all feedback is addressed, add Reviewed-by, Acked-by, and Tested-by
    responses on individual commits.  Or add Series-reviewed-by, Series-acked-by,
    or Series-Tested-by responses to the entire pull request.

  * Wait for Developer/Author to add tags to commit messages in the pull request.

  * Perform final review of patches and commit message tags.  If there are not
    issues, set the `push` label to run final set of CI checks and auto merge
    the pull request into master.

# Maintainers.txt Format Changes

Add GitHub IDs of all maintainers and reviewers at the end of M: and R: lines
in [].  For example:

    M: Michael D Kinney <michael.d.kinney@intel.com> [mdkinney]

# TianoCore GitHub Email Archive Webhook Service

Assign reviewers to commits in a GitHub pull request based on assignments
documented in Maintainers.txt and generates an email archive of all pull request
and code review activities.

https://github.com/mdkinney/edk2-email-archive-webhook

# Email Archive Subscription Service

The emails are being delivered to the following RedHat email subscription
service.  Please subscribe to receive the emails and to be able to view the
email archives.

https://www.redhat.com/mailman/listinfo/tianocore-code-review-poc

The email archives are at this link:

https://www.redhat.com/mailman/private/tianocore-code-review-poc/index.html

The following sections show some example pull requests and code reviews to
help review the generated emails, their contents, and threading.

## Email Achieve Thread View

https://www.redhat.com/mailman/private/tianocore-code-review-poc/2020-May/thread.html#00289

## Example patch series with 1 patch

https://www.redhat.com/mailman/private/tianocore-code-review-poc/2020-May/thread.html#00340

## Example patch series with < 10 patches

* https://www.redhat.com/mailman/private/tianocore-code-review-poc/2020-May/msg00289.html
* https://www.redhat.com/mailman/private/tianocore-code-review-poc/2020-May/msg00030.html
* https://www.redhat.com/mailman/private/tianocore-code-review-poc/2020-May/msg00018.html
* https://www.redhat.com/mailman/private/tianocore-code-review-poc/2020-May/msg00008.html

## Example patch series with > 80 patches

* https://www.redhat.com/mailman/private/tianocore-code-review-poc/2020-May/msg00198.html
* https://www.redhat.com/mailman/private/tianocore-code-review-poc/2020-May/msg00116.html
* https://www.redhat.com/mailman/private/tianocore-code-review-poc/2020-May/msg00035.html

# Tasks to Complete

* Create edk2-codereview repository for evaluation of new code review process.
* Add GitHub IDs to Maintainers.txt in edk2-codereview repository
* Update BaseTools/Scripts/GetMaintainer.py to be compatible with GitHub IDs at
  the end of M: and R: statements
* Update webhook to use Rabbit MQ to manage requests and emails
* Determine if webhook requests must be serialized?  Current POC is serialized.
* Make sure webhook has error handling for all unexpected events/states.
* Add logging of all events and emails to webhook
* Add admin interface to webhook
* Deploy webhook on a production server with 24/7 support

# Ideas for Future Enhancements

* Run PatchCheck.py before assigning maintainers/reviewers.
* Add a simple check that fails if a single patch spans more than one package.
* Monitor comments for Reviewed-by, Acked-by, Tested-by, Series-Reviewed-by,
  Series-Acked-by, Series-Tested-by made by assigned maintainers/reviewers.
  Once all commits have required tags, auto update commit messages in the
  branch and wait for maintainer to set the `Push` label to run CI and auto
  merge if all CI checks pass.
