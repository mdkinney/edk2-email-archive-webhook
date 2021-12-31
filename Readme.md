# TianoCore GitHub Email Archive Webhook Service

Assign reviewers to commits in a GitHub pull request based on assignments
documented in Maintainers.txt and generates an email archive of all pull request
and code review activities.

## Installation Instructions

1) Clone GIT repo with TianoCore Code Review Archive Service

2) Install Python 3.8 or newer

3) PIP install from requirements.txt

4) Create 32 character SECRET_KEY for Flask (example creation and format)

```
    py
    >>> import secrets
    >>> print(secrets.token_urlsafe(32))
    NHf3_djweYDyGwXPGXjQfwCK4L2tcLDPsRhMRbZ1D9Q
```

```
    py -c "import secrets; print(secrets.token_urlsafe(32))"
    NHf3_djweYDyGwXPGXjQfwCK4L2tcLDPsRhMRbZ1D9Q
```

5) Copy config.py.template to config.py and fill in required settings.

6) Create first administrator account using adduser.py

7) Launch Server by running app.py

8) Login using account created in (6)

10) Invite other administrators

11) Add repo
   * GitHubToken

     Create PAT in GitHub user dev settings

   * GitHubWebHookSecret (example creation and format)

```
     py -c "import secrets; print(secrets.token_hex(32))"
     ee6e0fa4f9e4fc255b1c1200f2444843d88c614393a5fdcd31b329626fe86643
```

## Development Mode

* If behind a firewall, then use smee.io to redirect to local version of app
* If using smee.io, then must disable VPN and http proxies
* If disable VPN, then need to disable HTTP_PROXY in config.py
* If running with multiple repos, then a smee client is required for each
  repo redirected to the correct webhook link /webhook/<org>/<repo>

## Production Mode

## Interesting Notes

* GitHub PR commit ranges is not PR sha base to PR sha head.  If PR is out of
  sync, this can return an very long list of commits.  Instead, commit range
  of sha values can be determined with get_commits()

## Todo List

* Implement unit tests

* Add WebhookContext object class with context for processing request.
  + app
  + webhookconfiguration
  + eventlog
  + event
  + action
  + payload
  + Hub
  + GitRepo
  + HubRepo
  + HubPullRequest
  + Maintainers
  + Status (default 200)
  + Message (json message to return in response)

* Logs - Show list of events. Hyperlink to list of logs for that event
  Event should provide date/time/event/action.

* Update lock around git operations to support a different lock for each repo.
  And use of lock around all git operations.  Consider returning list of files
  modified and set of formatted patches from the Fetch() method.

* Update database to auto update if fields or models are added/removed/renamed.

* Add test case with the same commits in more than one open PR.  Commit_comments
  should generate emails against all PRs with that same commit.

* Clean up SQLAlchemy database so deleted logs reduce file size.

* Use message queue for received requests

* Use message queue to send emails

* fetch repo base.ref.  Default depth is 200.  Since the only file needed for
  processing is Maintainers.txt, can likely use Depth = 1.

  Changed default to Depth=1.  Need to do more testing.

* Review what happens when the PR is an update to Maintainers.txt. Need old
  and new maintainer/reviewer to review the change unless the old maintainer
  is not longer active.  Must have new maintainer review to accept new role

* If Maintainers.txt is updated to add/remove maintainers/reviewers, then the
  GitHub repository maintainers/reviewers also needs to be updated.

* Combination of GitHub org and GitHub repo must be unique.

* Auto clear log entries older than 30 days.

* Git patches with Unicode or invalid UTF8 characters have to be stripped to
  process through python email module.  Example workaround:

  Message = email.message_from_bytes(Email.encode('utf8','surrogateescape'))

  Need a better solution that guarantees that patch emails sent with
  complete patches (no comments) can be extracted and applied and get the
  same result.

## Completed Tasks

* DONE 12-30-2121 - Ignore draft PRs and add case for read_for_review and
  treat the same as reopened.

* DONE 12-30-2021 - Update checks to only generate emails of code review if
  the target branch is protected or it is the default branch

  The current behavior only supports 1 target branch:
    #
    # Skip pull requests with a base branch that is not the default branch
    #
  Need to extend to support multiple target branches so code reviews against
  release branches can be supported too.

* DONE 12-29-2021 - Add all requests, responses, git commands, and emails to logs.

* DONE 12-29-2021 - Add option to delete the repository cache

* DONE 12-29-2021 - Add lock around all methods to perform GIT operations or file operations in Repository

* DONE 12-23-2021 - Add support for SH256 auth of request header from GitHub
  Should we upgrade from SHA1 to SHA256 for GitHub Request HMAC auth? YES
  Read GitHub pages.
  https://docs.github.com/en/developers/webhooks-and-events/webhooks/securing-your-webhooks

* DONE 12-23-2021 - Add TianoCore Favicon logo

* DONE 12-22-2021 - Add select repo list with hyperlinks for each repo that when selected takes
  you to log view page.  Buttons at top for HOME, ADD REPO

  When in log view for one repo, buttons at top for BACK, HOME, UPDATE, DELETE, CLEAR LOG

* DONE 12-22-2021 - Add clear logs button in scope of repo

* DONE 12-22-2021: Add form to list users, delete users, and invite new users

* DONE 12-22-2021 Replace MyCorp Copyright 2019 with TianoCore Copyright 2021.

* DONE 12-22-2021 - User strong passwords requirements.

  class CustomUserManager(UserManager):

      # Override the default password validator
      def password_validator(self, form, field):
          # Regular expression used to validate a strong password.
          #   * The password length must be greater than or equal to 8
          #   * The password must contain one or more uppercase characters
          #   * The password must contain one or more lowercase characters
          #   * The password must contain one or more numeric values
          #   * The password must contain one or more special characters
          #
          # https://www.computerworld.com/article/2833081/how-to-validate-password-strength-using-a-regular-expression.html
          #
          StrongPasswordRegex = '(?=^.{8,}$)(?=.*\d)(?=.*[!@#$%^&*]+)(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$'
          if not re.match(StrongPasswordRegex, field.data):
              raise ValidationError(('Password must be >=8 chars with one or more Upper, Lower, Number, and Special'))

# Configuration Settings (Outdated)

The following environment variables must be set before starting the webhook
service.

* `GITHUB_TOKEN` - 40 character hex string that is a Personal Access Token
  created in GitHub in User->Settings->Developer Settings->Personal access tokens.
  The personal access token must be generated from a user account that has
  permissions to the GitHub repositories for which an email archive is required.
  This token is used by the webhook service when making GitHub API calls.  If
  this environment variable is not set correctly then GitHub API calls fail.

  [Creating webHooks](https://developer.github.com/webhooks/creating/)

* `GITHUB_WEBHOOK_SECRET` - 64 character hex string that is secret used to
  validate payloads received from GitHub.  If this environment variable is not
  set correctly, then all payloads from GitHub are rejected.  This value
  must match the GitHub repository setting  in Settings->WebHooks->Edit->Secret.

  [Setting your secret token](https://developer.github.com/webhooks/securing/#setting-your-secret-token)

* `GITHUB_WEBHOOK_ROUTE` - The route the webhook server listens for payloads
  sent by GitHub (e.g. `/webhook`).  This value must match the GitHub repository
  setting Settings->WebHooks->Edit->Payload URL.

* `GITHUB_WEBHOOK_PORT_NUMBER` - The port the webhook server listens for
  payloads sent by GitHub (e.g. `8888`).  This value must match the GitHub
  repository setting Settings->WebHooks->Edit->Payload URL.

* `GITHUB_REPO_WHITE_LIST` - A list of repositories from a single GitHub account
  that the webhook service supports.  The format of this setting is a Python
  list of strings with each string containing the GitHub account name '/' then
  the GitHub repository name (e.g. `['mdkinney/repo1', 'mdkinney/repo1']`).

* `EMAIL_ARCHIVE_ADDRESS` - The TO address for emails address generated by this
  webhook service.  This is typically the address of an email subscription
  service that allows a community of developers to receive the emails generated
  by this webhook service and for the emails to be archived.

* `SMTP_ADDRESS` - The address of the SMTP server used to send emails.

* `SMTP_PORT_NUMBER` - The port number of the SMTP server used to send emails.

* `SMTP_USER_NAME` - The use name of the account on the SMTP server used to send
  emails.

* `SMTP_PASSWORD` - The password of the account on the SMTP server used to send
  emails.

* `SENDGRID_API_KEY` - The API key used to send emails using [SendGrid](https://sendgrid.com/).
  The webook service can use either use an SMTP server or SendGrid to send
  emails using a command line flag to select one of these options.

# Maintainers.txt File Format

The file `Maintainers.txt` must be present in the root of a repository.

The following describe the syntax of a section statement.  If a line
does not start with one of the tags listed below, then the line is
considered a section separator.  Blank lines and end of file are also
section separators.

* `L:` Mailing list that is relevant to this area (default is `edk2-devel`)
  Patches and questions should be sent to the email list.
* `M:` Package Maintainer: Cc address for patches and questions. Responsible
  for reviewing and pushing package changes to source control.  The end
  of this line must contain the GitHub ID of the maintainer in [].
* `R:` Package Reviewer: Cc address for patches and questions. Reviewers help
  maintainers review code, but don't have push access. A designated Package
  Reviewer is reasonably familiar with the Package (or some modules
  thereof), and/or provides testing or regression testing for the Package
  (or some modules thereof), in certain platforms and environments.  The
  end of this line must contain the GitHub ID of the maintainer in [].
* `W:` Web-page with status/info
* `T:` SCM tree type and location.  Type is one of: `git`, `svn`.
* `S:` Status, one of the following:
  * `Supported`: Someone is actually paid to look after this.
  * `Maintained`: Someone actually looks after it.
  * `Odd Fixes`: It has a maintainer but they don't have time to do
    much other than throw the odd patch in. See below.
  * `Orphan`: No current maintainer [but maybe you could take the
    role as you write your new code].
  * `Obsolete`: Old code. Something tagged obsolete generally means
    it has been replaced by a better system and you should be using that.
* `F:` Files and directories with wildcard patterns. A trailing slash
  includes all files and subdirectory files.  One pattern per line.
  Multiple F: lines per section acceptable.
  * `F: MdeModulePkg/`   all files in and below `MdeModulePkg`
  * `F: MdeModulePkg/*`  all files in `MdeModulePkg`, but not below
  * `F: */Pci/*`         all files in a directory called `Pci`, at any depth in the hierarchy, but not below
* `X:` Files and directories that are NOT maintained, same rules as F:
  Files exclusions are tested after file matches. Can be useful for excluding
  a specific subdirectory.  The example below matches all files in and below
  `NetworkPkg` excluding `NetworkPkg/Ip6Dxe/`.
```
F: NetworkPkg/
X: NetworkPkg/Ip6Dxe/
```

Filenames not caught by any F: rule get matched as being located in the top-
level directory. (Internally, the script looks for a match called `<default>`,
so please don't add a file called that in the top-level directory.)

# Webhook Event Processing

# Unit Tests

# Build Status

# License Details

The majority of the content in the EDK II open source project uses a
[BSD-2-Clause Plus Patent License](License.txt).

The EDK II Project is composed of packages.  The maintainers for each package
are listed in [Maintainers.txt](Maintainers.txt).

# Resources
* [TianoCore](http://www.tianocore.org)
* [EDK II](https://github.com/tianocore/tianocore.github.io/wiki/EDK-II)
* [Getting Started with EDK II](https://github.com/tianocore/tianocore.github.io/wiki/Getting-Started-with-EDK-II)
* [Mailing Lists](https://github.com/tianocore/tianocore.github.io/wiki/Mailing-Lists)
* [TianoCore Bugzilla](https://bugzilla.tianocore.org)
* [How To Contribute](https://github.com/tianocore/tianocore.github.io/wiki/How-To-Contribute)
* [Release Planning](https://github.com/tianocore/tianocore.github.io/wiki/EDK-II-Release-Planning)

# Code Contributions
To make a contribution to a TianoCore project, follow these steps.
1. Create a change description in the format specified below to
   use in the source control commit log.
2. Your commit message must include your `Signed-off-by` signature
3. Submit your code to the TianoCore project using the process
   that the project documents on its web page.  If the process is
   not documented, then submit the code on development email list
   for the project.
4. It is preferred that contributions are submitted using the same
   copyright license as the base project. When that is not possible,
   then contributions using the following licenses can be accepted:
   * BSD (2-clause): http://opensource.org/licenses/BSD-2-Clause
   * BSD (3-clause): http://opensource.org/licenses/BSD-3-Clause
   * MIT: http://opensource.org/licenses/MIT
   * Python-2.0: http://opensource.org/licenses/Python-2.0
   * Zlib: http://opensource.org/licenses/Zlib

   For documentation:
   * FreeBSD Documentation License
     https://www.freebsd.org/copyright/freebsd-doc-license.html

   Contributions of code put into the public domain can also be
   accepted.

   Contributions using other licenses might be accepted, but further
   review will be required.

# Developer Certificate of Origin

Your change description should use the standard format for a
commit message, and must include your `Signed-off-by` signature.

In order to keep track of who did what, all patches contributed must
include a statement that to the best of the contributor's knowledge
they have the right to contribute it under the specified license.

The test for this is as specified in the [Developer's Certificate of
Origin (DCO) 1.1](https://developercertificate.org/). The contributor
certifies compliance by adding a line saying

  Signed-off-by: Developer Name <developer@example.org>

where `Developer Name` is the contributor's real name, and the email
address is one the developer is reachable through at the time of
contributing.

```
Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
    have the right to submit it under the open source license
    indicated in the file; or

(b) The contribution is based upon previous work that, to the best
    of my knowledge, is covered under an appropriate open source
    license and I have the right under that license to submit that
    work with modifications, whether created in whole or in part
    by me, under the same open source license (unless I am
    permitted to submit under a different license), as indicated
    in the file; or

(c) The contribution was provided directly to me by some other
    person who certified (a), (b) or (c) and I have not modified
    it.

(d) I understand and agree that this project and the contribution
    are public and that a record of the contribution (including all
    personal information I submit with it, including my sign-off) is
    maintained indefinitely and may be redistributed consistent with
    this project or the open source license(s) involved.
```

# Sample Change Description / Commit Message

```
From: Contributor Name <contributor@example.com>
Subject: [Repository/Branch PATCH] Pkg-Module: Brief-single-line-summary

Full-commit-message

Signed-off-by: Contributor Name <contributor@example.com>
```

## Notes for sample patch email

* The first line of commit message is taken from the email's subject
  line following `[Repository/Branch PATCH]`. The remaining portion of the
  commit message is the email's content.
* `git format-patch` is one way to create this format

## Definitions for sample patch email

* `Repository` is the identifier of the repository the patch applies.
  This identifier should only be provided for repositories other than
  `edk2`. For example `edk2-BuildSpecification` or `staging`.
* `Branch` is the identifier of the branch the patch applies. This
  identifier should only be provided for branches other than `edk2/master`.
  For example `edk2/UDK2015`, `edk2-BuildSpecification/release/1.27`, or
  `staging/edk2-test`.
* `Module` is a short identifier for the affected code or documentation. For
  example `MdePkg`, `MdeModulePkg/UsbBusDxe`, `Introduction`, or
  `EDK II INF File Format`.
* `Brief-single-line-summary` is a short summary of the change.
* The entire first line should be less than ~70 characters.
* `Full-commit-message` a verbose multiple line comment describing
  the change.  Each line should be less than ~70 characters.
* `Signed-off-by` is the contributor's signature identifying them
  by their real/legal name and their email address.
