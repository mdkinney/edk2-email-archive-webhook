## @file
#  Retrieves the people to request review from on submission of a commit.
#
#  Copyright (c) 2019, Linaro Ltd. All rights reserved.<BR>
#
#  SPDX-License-Identifier: BSD-2-Clause-Patent
#

from __future__ import print_function
from collections import defaultdict
import re

EXPRESSIONS = {
    'exclude':    re.compile(r'^X:\s*(?P<exclude>.*?)\r*$'),
    'file':       re.compile(r'^F:\s*(?P<file>.*?)\r*$'),
    'list':       re.compile(r'^L:\s*(?P<list>.*?)\r*$'),
    'maintainer': re.compile(r'^M:\s*(?P<maintainer>.*?)\r*$'),
    'reviewer':   re.compile(r'^R:\s*(?P<reviewer>.*?)\r*$'),
    'status':     re.compile(r'^S:\s*(?P<status>.*?)\r*$'),
    'tree':       re.compile(r'^T:\s*(?P<tree>.*?)\r*$'),
    'webpage':    re.compile(r'^W:\s*(?P<webpage>.*?)\r*$')
}

def pattern_to_regex(pattern):
    """Takes a string containing regular UNIX path wildcards
       and returns a string suitable for matching with regex."""

    pattern = pattern.replace('.', r'\.')
    pattern = pattern.replace('?', r'.')
    pattern = pattern.replace('*', r'.*')

    if pattern.endswith('/'):
        pattern += r'.*'
    elif pattern.endswith('.*'):
        pattern = pattern[:-2]
        pattern += r'(?!.*?/.*?)'

    return pattern

def path_in_section(path, section):
    """Returns True of False indicating whether the path is covered by
       the current section."""
    if not 'file' in section:
        return False

    for pattern in section['file']:
        regex = pattern_to_regex(pattern)

        match = re.match(regex, path)
        if match:
            # Check if there is an exclude pattern that applies
            for pattern in section['exclude']:
                regex = pattern_to_regex(pattern)

                match = re.match(regex, path)
                if match:
                    return False

            return True

    return False

def get_section_maintainers(path, section):
    """Returns a list with email addresses to any M: and R: entries
       matching the provided path in the provided section."""
    maintainers = []
    lists = []

    if path_in_section(path, section):
        for address in section['maintainer'], section['reviewer']:
            # Convert to list if necessary
            if isinstance(address, list):
                maintainers += address
            else:
                lists += [address]
        for address in section['list']:
            # Convert to list if necessary
            if isinstance(address, list):
                lists += address
            else:
                lists += [address]

    return maintainers, lists

def get_maintainers(path, sections, level=0):
    """For 'path', iterates over all sections, returning maintainers
       for matching ones."""
    maintainers = []
    lists = []
    for section in sections:
        tmp_maint, tmp_lists = get_section_maintainers(path, section)
        if tmp_maint:
            maintainers += tmp_maint
        if tmp_lists:
            lists += tmp_lists

    if not maintainers:
        # If no match found, look for match for (nonexistent) file
        # REPO.working_dir/<default>
        print('"%s": no maintainers found, looking for default' % path)
        if level == 0:
            maintainers = get_maintainers('<default>', sections, level=level + 1)
        else:
            print("No <default> maintainers set for project.")
        if not maintainers:
            return None

    return maintainers + lists

def parse_maintainers_line(line):
    """Parse one line of Maintainers.txt, returning any match group and its key."""
    for key, expression in EXPRESSIONS.items():
        match = expression.match(line)
        if match:
            if key not in ['file', 'exclude']:
                return key, line.strip()
            else:
                return key, match.group(key)
    return None, None

def parse_maintainers_file(Maintainers):
    """Parse the contents of Maintainers.txt from top-level of repo and
       return a list containing dictionaries of all sections."""
    sectionlist = []
    section = defaultdict(list)
    key = None
    value = None
    for line in Maintainers.splitlines():
        # If end of section (end of file, or non-tag line encountered)...
        if not key or not value or not line:
            # ...if non-empty, append section to list.
            if section:
                sectionlist.append(section.copy())
                section.clear()

        key, value = parse_maintainers_line(line)
        if key and value:
            section[key].append(value)

    return sectionlist

def GetMaintainers (Maintainers, Files):
    Addresses = []
    Sections = parse_maintainers_file(Maintainers)
    for file in Files:
        addresslist = get_maintainers(file, Sections)
        if addresslist:
            Addresses += addresslist
    return Addresses

def ParseMaintainerAddresses (Addresses):
    EmailList = []
    GitHubIdList = []
    AddressList = []
    for Line in Addresses:
        Line = Line.strip()
        AddressType = Line.split(':')[0].strip()
        if AddressType == 'R':
            AddressList.append('Reviewer  : ' + Line.split(':')[1].strip())
        elif AddressType == 'M':
            AddressList.append('Maintainer: ' + Line.split(':')[1].strip())
        else:
            continue
        if '[' not in Line or ']' not in Line:
            print ('ERROR: Missing GitHub ID: ' + Line)
            continue
        GitHubId = Line.split('[')[1].split(']')[0].strip()
        if GitHubId == '':
            print ('ERROR: Missing GitHub ID: ' + Line)
            continue
        GitHubIdList.append(GitHubId)
        if '<' not in Line or '>' not in Line:
            print ('ERROR: Missing email address: ' + Line)
            continue
        Email = Line.split('<')[1].split('>')[0].strip()
        if '@' not in Email:
            print ('ERROR: Invalid email address: ' + Line)
            continue
        EmailList.append(Email)
    EmailList    = list(set(EmailList))
    GitHubIdList = list(set(GitHubIdList))
    AddressList  = list(set(AddressList))
    return AddressList, GitHubIdList, EmailList
