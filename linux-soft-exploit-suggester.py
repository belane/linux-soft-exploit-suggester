#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Linux Soft Exploit Suggester
# Version: 0.7
# Author: Belane
# Contributors: davidtavarez, 72Zn
# https://github.com/belane/linux-soft-exploit-suggester

import re, os, argparse, csv, platform
from distutils.version import LooseVersion

valid_platforms = ['linux','linux_crisv32','linux_mips','linux_ppc','linux_sparc','lin_x86','lin_x86-64','multiple']
badpackages = ('centos','debian','ubuntu','redhat','addon','agent','apps','base','bin','bsd','cache','check','client','command',
            'common','configuration','control','core','cron','data','database','dev','editor','events','extras','family','file',
            'files','form','ftp','generic','gnu','headers','http','info','installation','kernel','legacy','linux','load','manager',
            'message','module','monitor','net','network','one','open','patch','path','plugin','plugins','release','router','secure',
            'security','server','ssl','software','standard','support','system','team','text','the','theme','time','toolkit','tools',
            'unix','update','user','utility','viewer','web','wifi','windows','wireless')    

exploits_db_url = 'https://raw.githubusercontent.com/offensive-security/exploit-database/master/files_exploits.csv'

class field: pass

def getFields(header):
    """ Get fields from CSV header and fill Field class """
    fields = {x:i for i,x in enumerate(header)}
    for title,id in fields.items():
        setattr(field,title,id)

def loadExploitsList(exploits_file):
    """ Load exploits from csv file to exploit_list """
    file_exploits = open(exploits_file, 'rb')
    reader = csv.reader(file_exploits)
    exploit_list = list(reader)
    file_exploits.close()
    getFields(exploit_list[0])
    return exploit_list[1:]

def getPackageList():
    """ Generate installed package list """
    package_list = []
    if(os.path.isfile("/usr/bin/dpkg")):
        packages = os.popen("/usr/bin/dpkg -l")
        package_list = parseDebian(packages)
    elif(os.path.isfile("/usr/bin/rpm")):
        packages = os.popen("/usr/bin/rpm -qa")
        package_list = parseRedhat(packages)
    else:
        print 'Error: Unable to generate package list.'

    return package_list

def parseDebian(packages_file):
    """ Parse debian package list to dict (name:version) """
    result = {}
    if args.clean==True: first_field = 0
    else: first_field = 1
    for line in packages_file:
        if args.clean==True or line[:2] == 'ii':
            fields = line.split()
            if len(fields) < 2 + first_field: continue
            # Software name
            search = fields[first_field].find(':')
            if search != -1:
                soft_name = cleanName(fields[first_field][:search])
            else:
                soft_name = cleanName(fields[first_field])
            # Version
            search = re.search(r"-|\+|~", fields[first_field + 1])
            if search:
                soft_version = fields[first_field + 1][:search.span()[0]]
            else:
                soft_version = fields[first_field + 1]
            search = soft_version.find(':')
            if search != -1:
                soft_version = soft_version[search + 1:]
            soft_version = purgeVersionString(soft_version)
            # Format check
            if not soft_name or not soft_version: continue
            # Intense package name split
            if args.intense and '-' in soft_name:
                for sub_package in soft_name.split('-'):
                    if len(sub_package)>2 and '.' not in sub_package and sub_package not in badpackages: result[sub_package] = soft_version
            else:
                if soft_name not in badpackages: result[soft_name] = soft_version
    return result

def parseRedhat(packages_file):
    """ Parse redhat package list to dict (name:version) """
    result = {}
    for line in packages_file:
        fields = '.'.join(line.split('.')[:-2]).split('-')
        if len(fields) < 2: continue
        # Software name
        soft_name = cleanName('-'.join(fields[:-2]))
        # Version
        soft_version = purgeVersionString(fields[-2])
        # Format check
        if not soft_name or not soft_version: continue
        # Intense package name split
        if args.intense and '-' in soft_name:
            for sub_package in soft_name.split('-'):
                if len(sub_package)>2 and '.' not in sub_package and sub_package not in badpackages: result[sub_package.lower()] = soft_version
        else:
            if soft_name not in badpackages: result[soft_name.lower()] = soft_version
    return result

def cleanName(soft_name):
    """ Clean package name from common strings """
    for badword in badpackages:
        soft_name = re.sub(r'-' + badword, '', soft_name)
    return soft_name

def versionVariations(soft_version, level):
    """ Return Version variations for selected level """
    if level == 1:      # Same version
        result = soft_version
    elif level == 2:    # Micro and Patch version
        result = '.'.join(soft_version.split('.')[:3])
    elif level == 3:    # Minor version
        result = '.'.join(soft_version.split('.')[:2])
        if '.' not in result and len(result) > 3: result = result[:3]
    elif level == 4:    # Major version
        result = soft_version.split('.')[0]
        if '.' not in result and len(result) > 4: result = result[:4]
    elif level == 5:    # Whitout version
        result = ''
    return result

def purgeVersionString(version_string):
    """ Eliminate invalid characters and last dot from version string """
    search = re.search(r'[^0-9.]', version_string)
    if search: result = version_string[:search.span()[0]]
    else: result = version_string
    if len(result) > 0 and result[-1] == '.': result = result[:-1]
    return result

def searchExploit(exploit_list, soft_name, soft_version):
    """ Search affected packages in exploit_list """
    result = []
    version_search = versionVariations(soft_version, args.level)
    for exploit in exploit_list:
        if exploit[field.platform] in valid_platforms and (args.dos or exploit[field.type]!='dos' or args.type == 'dos'): # Platform and DoS
            if args.filter == None or args.filter.lower() in exploit[field.description].lower():                    # Filter
                if args.type == None or args.type == exploit[field.type]:                                    # Type
                    query = "(^(\w*\s){0,%s}|/\s?)%s(\s|\s.*\s|\/).* -" % (args.level, soft_name.replace('+', '\+'))
                    if re.search(query, exploit[field.description],re.IGNORECASE):
                        affected_versions = extractVersions(exploit[field.description])
                        for affected_version in affected_versions:
                            if args.level == 5 or LooseVersion(version_search) <= LooseVersion(affected_version):
                                if args.duplicates == False: exploit_list.remove(exploit)          # Duplicates
                                printOutput(exploit, soft_name, soft_version)
                                result.append([exploit, soft_name, soft_version])
                                break

    return result

def extractVersions(title_string):
    """ Extract all version numbers from a string """
    search = re.search(r'\s-|\(|\&', title_string)
    if search:
        title_string = title_string[:search.span()[0]]
    result = []
    for possible_version in title_string.split():
        if possible_version[0].isdigit():
            if '/' in possible_version:
                for multiversion in possible_version.split('/'):
                    if '-' in multiversion:
                        multiversion = '.'.join(multiversion.split('-')[0].split('.')[:-1]) + '.' + multiversion.split('-')[-1]
                    if purgeVersionString(multiversion):
                        result.append(purgeVersionString(multiversion))
            elif '-' in possible_version:
                result.append(purgeVersionString('.'.join(possible_version.split('-')[0].split('.')[:-1]) + '.' + possible_version.split('-')[-1]))
            else:
                result.append(purgeVersionString(possible_version))
    return result

def printOutput(exploit_details, soft_name, soft_version):
    """ Print formated output """
    print "\033[1;31m[!]\033[0m \033[1m%s\033[0m\033[0;90m - %s\033[0m" % (exploit_details[field.description], exploit_details[field.platform])
    print "\tFrom: %s %s" % (soft_name, soft_version)
    print "\tFile: /usr/share/exploitdb/%s" % exploit_details[field.file]
    print "\tUrl: https://www.exploit-db.com/exploits/%s\n" % exploit_details[field.id]

def updateDB():
    """ Download latest exploits DB """
    try:
        print 'Retrieving ' + exploits_db_url,
        from sys import stdout
        stdout.flush()
        import urllib
        urllib.urlretrieve(exploits_db_url, 'files_exploits.csv')
        print 'DONE.\n'
    except:
        print 'Error: Unable to download.'


if __name__ == "__main__":
    # Banner
    print('\033[95m\033[1m' + """
  |  _         __ _  _ |    _    _ | _  |    __    __  __  _  __ |   _  _
  |·| || |\/  (_ | ||_ |-  /_)\/| \|| |·|-  (_ | ||  )|  )/_)(_  |- /_)|
  ||| ||_|/\  __)|_||  |_  \_ /\|_/||_|||_  __)|_||_/ |_/ \_ __) |_ \_ |
                                |                 _/  _/
    """ + '\033[0m')
    # Help & Args
    usage_examples = 'usage examples: \
    \n  Get Package List:\n\tdebian/ubuntu: dpkg -l > package_list\n\tredhat/centos: rpm -qa > package_list\n \
    \n  Update exploit database:\n\tpython linux-soft-exploit-suggester.py --update \n \
    \n  Basic usage:\n\tpython linux-soft-exploit-suggester.py --file package_list \n \
    \n  Specify exploit db:\n\tpython linux-soft-exploit-suggester.py --file package_list --db files_exploits.csv \n \
    \n  Use Redhat/Centos format file:\n\tpython linux-soft-exploit-suggester.py --file package_list --distro redhat \n \
    \n  Search exploit for major version:\n\tpython linux-soft-exploit-suggester.py --file package_list --level 4 \n \
    \n  Filter by remote exploits:\n\tpython linux-soft-exploit-suggester.py --file package_list --type remote \n \
    \n  Search specific words in exploit title:\n\tpython linux-soft-exploit-suggester.py --file package_list --filter Overflow \n \
    \n  Advanced usage:\n\tpython linux-soft-exploit-suggester.py --file package_list --level 3 --type local --filter escalation \n '
    parser = argparse.ArgumentParser(description='linux-soft-exploit-suggester:\n  Search for Exploitable Software from package list.',
                                    formatter_class=argparse.RawTextHelpFormatter,
                                    add_help=False, epilog=usage_examples)
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit')
    parser.add_argument('-f', '--file', type=str, help='Package list file')
    parser.add_argument('--clean',  action='store_true', help='Use clean package list, if used \'dpkg-query -W\'')
    parser.add_argument('--duplicates', action='store_true', help='Show duplicate exploits')
    parser.add_argument('--db', type=str,  help='Exploits csv file [default: files_exploits.csv]')
    parser.add_argument('--update', action='store_true',  help='Download latest version of exploits db')
    parser.add_argument('-d', '--distro', metavar='debian|redhat', type=str, choices=set(('debian','redhat')), default='debian', help='Linux flavor, debian or redhat [default: debian]')
    parser.add_argument('--dos', action='store_true', help='Include DoS exploits')
    parser.add_argument('--intense', action='store_true', help='Include intense package name search,\nwhen software name doesn\'t match package name (experimental)')
    parser.add_argument('-l', '--level', metavar='1-5', type=int, choices=set((1,2,3,4,5)), default=1, help='Software version search variation [default: 1]\
                        \n  level 1: Same version\
                        \n  level 2: Micro and Patch version\
                        \n  level 3: Minor version\
                        \n  level 4: Major version\
                        \n  level 5: All versions')
    parser.add_argument('--type', type=str, metavar="TYPE", choices=set(('local', 'remote', 'webapps', 'dos', 'shellcode')), help='Exploit type; local, remote, webapps, dos.\n  e.g.\t--type local\n\t--type remote')
    parser.add_argument('--filter', type=str,  help='Filter exploits by string\n  e.g.\t--filter "escalation"')
    args = parser.parse_args()

    # Update DB
    if args.update:
        updateDB()
        exit()
    # Default: DB from running path, on Kali linux from system DB
    exploits_db = 'files_exploits.csv'
    if platform.dist()[0] == 'Kali': exploits_db='/usr/share/exploitdb/' + exploits_db
    if args.db: exploits_db = args.db
    if not os.path.isfile(exploits_db):
        print 'Exploit DB not found! Updating'
        updateDB()
        exploits_db = 'files_exploits.csv'
    
    # Linux flavor package list load
    soft_list = []
    if args.file:
        try:
            packages_file = open(args.file,'r')
            if args.distro == 'redhat':
                soft_list = parseRedhat(packages_file)
            else:
                soft_list = parseDebian(packages_file)
            packages_file.close()
        except IOError:
            print "Error: File %s not found. Ignoring." % (args.file)
    if not soft_list:
        print 'Wrong package list format or no package file found. Generating ...\n'
        soft_list = getPackageList()
    # Exploits list load
    exploit_list = loadExploitsList(exploits_db)
    # Search Exploits
    for soft_name, soft_version in soft_list.items():
        searchExploit(exploit_list, soft_name, soft_version)
