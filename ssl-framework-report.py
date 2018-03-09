################################################################################
# This is SSL Framework version 2.0
# SSL Framework is an application for integration of testssl.sh
# functionality with SIEM systems.
#
# SSL Framework automates and enables continuous digital certificates
# analysis and simplifies their maintenance process.
#
# SSL Framework works on *NIX.
#
# Copyright (C) 2018  SOC Prime, Inc.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR APARTICULAR PURPOSE.
#
# See the GNU General Public License for more details. You should have received
# a copy of the GNU General Public License along with this program.  If not,
# see <http://www.gnu.org/licenses/>.
#
# To get a copy of the software, please send an e-mail to
# sales@socprime.com <mailto:sales@socprime.com>
# or write to 1201 Orange street, Suite 600, Wilmington, 19899, Delaware, USA
################################################################################

__author__ = 'Alexander Geruk'
__version__ = '2.0'
__license__ = 'GPLv3'

import csv
import argparse
import time
import platform
import subprocess
import logging
from logging import handlers
from logging.handlers import SysLogHandler
import os
import sys
import ConfigParser
import re
import socket
from datetime import datetime
import json
import urllib2
import multiprocessing

currentdir = os.path.dirname(os.path.abspath(sys.argv[0]))

# create logger
LOG_FILENAME = os.path.normpath(currentdir +'/ssl-framework-report.log')
logger = logging.getLogger('ssl-framework-logger')
logger.setLevel(logging.INFO)
handler = logging.handlers.RotatingFileHandler(LOG_FILENAME, maxBytes=5242880, backupCount=4)
handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
logger.addHandler(handler)

if platform.system() == 'Windows':
    msg = 'SSL Framework Report currently supports *nix only.'
    print msg
    logger.error(msg)
    exit(0)

# global vars
exportFormat = ''
rowsList = []

errorPatternsDict = {
    'cef':'CEF:0|SOC Prime|SSL Framework|'+ __version__ +'|slf:{eventId}|{eventName}|{severity}| msg={msg}\n',
    'leef':'LEEF:1.0|SOC Prime|SSL Framework|'+ __version__ +'|slf:{eventId}|\tmsg={msg}\n',
    'log':'vendor="SOC Prime", product="SSL Framework", version="'+ __version__ +'", eventId="slf:{eventId}", eventName="{eventName}", severity={severity}, msg="{msg}"\n'
    }

errorNamesDict = {
    201:{'name':'cmd line error', 'sev': 7},
    202:{'name':'secondary/other cmd line error', 'sev': 7},
    203:{'name':'other user error', 'sev': 5},
    204:{'name':'network problem', 'sev': 5},
    205:{'name':'s.th. fatal is not supported in the client', 'sev': 5},
    206:{'name':'s.th. is not supported yet', 'sev': 5},
    207:{'name':'openssl problem', 'sev': 7},
    208:{'name':'host list is empty', 'sev': 5},
    209:{'name': 'could not read file', 'sev': 7},
}

errorsMappingDict = {
    1:201,
    2:202,
    255:203,
    254:204,
    253:205,
    252:206,
    251:207
    }


def get_blacklist():
    url = 'https://sslbl.abuse.ch/downloads/ssl_extended.csv'
    response = urllib2.urlopen(url)
    cr = csv.reader(response)

    hash_list = []
    for row in cr:
        if not row[0].startswith('#'):
            hash_list += [row[4]] if row[4] not in hash_list else []
    del response, cr
    return hash_list


def add_event_to_flow(eventDict):
    global rowsList
    evId = eventDict['eventId']
    eventDict['eventName'] = errorNamesDict[evId]['name']
    eventDict['severity'] = errorNamesDict[evId]['sev']
    event = errorPatternsDict[exportFormat].format(**eventDict)
    rowsList.append(event)


def exec_shell_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if out:
        print out
    if err:
        print err
    return_code = p.returncode
    while return_code is None:
        time.sleep(0.5)
    return return_code, err


def raiseException(msg):
    logger.error(msg)
    raise Exception(msg)


def search(host, data):
    return [element for element in data if element['ip'] == host]


def start_scan(domain):
    logger.info('Start testssl.sh for domain [{0}]'.format(domain))
    output_file = currentdir + '/testssl/' + domain + '.json'
    output_log = currentdir + '/testssl/' + domain + '.log'
    print (time.asctime() + '|Start testssl.sh for host [{0}]'.format(domain))
    try:
        os.remove(output_file)
        os.remove(output_log)
    except OSError:
        pass
    command = bash + ' ' + currentdir + '/testssl/testssl.sh -h -S -U --fast --jsonfile {0} --logfile {1} {2}'.format(output_file, output_log, domain)
    exit_code, std_err = exec_shell_command(command)
    if exit_code in errorsMappingDict:
        errorcode = errorsMappingDict[exit_code]
        msg = 'testssl.sh returned an error: {0}'.format(std_err.strip())
        add_event_to_flow({'eventId': errorcode, 'msg': msg})
        logger.error(msg)
    else:
        logger.info('Finished scan for [{0}]'.format(domain))
        host_list = []
        scan_result_list = []
        data = json.load(open(output_file))
        for host in data:
            if host['id'] == 'service':
                host_list.append(host['ip'])
        for host in host_list:
            value = search(host, data)
            scan_result_list.append(value)
        return scan_result_list


def get_list_from_file():
    lines = []
    try:
        with open(domainsListFile, 'r') as f:
            for line in f:
                domain = line.strip()
                if line[0] != '#':
                    lines.append(domain)

    except Exception as e:
        msg = 'Could not read file: '+str(e)
        add_event_to_flow({'eventId':'209', 'msg':msg})
        raiseException(msg)

    return lines[0:200]


def get_vulns(host_data):
    vulnsList = []
    for record in host_data:
            if 'VULNERABLE' in record['finding'] or 'potentially vulnerable' in record['finding']:
                value = record['id'].upper()
                vulnsList.append(value)
    if vulnsList:
        return ', '.join(vulnsList)
    else:
        return 'Not found'


def datetime_from_utc_to_local(utc_datetime):
    utc_datetime = datetime.utcfromtimestamp(utc_datetime/1000)
    now_timestamp = time.time()
    offset = datetime.fromtimestamp(now_timestamp) - datetime.utcfromtimestamp(now_timestamp)
    return (utc_datetime + offset).strftime('%b %d %Y %H:%M:%S').upper()


def calc_valid_until_days(date_to):
    now = datetime.now().date()
    date_to = date_to.date()
    diff = (date_to - now).days
    if diff < 0:
        diff = 0
    return diff


def get_report_data(host_data):
    rowsList = []
    rowDict = {}
    algorithm = next((item['finding'] for item in host_data if item['id'] == 'algorithm'), None)
    key_size = next((item['finding'] for item in host_data if item['id'] == 'key_size'), None)
    expiration = next((item['finding'] for item in host_data if item['id'] == 'expiration'), None)
    if not algorithm:
        key_sign = key_size
    elif not key_size:
        key_sign = algorithm
    else:
        key_sign = algorithm + ', ' + key_size
    match = re.findall(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}', expiration)
    date_from = datetime.strptime(match[0], '%Y-%m-%d %H:%M')
    date_from_f = date_from.strftime('%b %d %Y %H:%M') + ':00'
    date_to = datetime.strptime(match[1], '%Y-%m-%d %H:%M')
    date_to_f = date_to.strftime('%b %d %Y %H:%M') + ':00'
    ts = time.time()
    st = datetime.fromtimestamp(ts).strftime('%b %d %Y %H:%M:%S')
    domain_ip = next((item['ip'] for item in host_data if item['id'] == 'service'), None)
    domain, ip = domain_ip.split('/')
    altnames = next((item['finding'] for item in host_data if item['id'] == 'san'), None).split(' ')
    altnames_count = altnames[3:].__len__()

    rowDict['domain'] = domain
    rowDict['ip'] = ip
    rowDict['commonNames'] = next((item['finding'] for item in host_data if item['id'] == 'cn'), None)
    rowDict['altNames'] = altnames_count
    rowDict['notBefore'] = date_from_f
    rowDict['notAfter'] = date_to_f
    rowDict['validUntilD'] = calc_valid_until_days(date_to)
    rowDict['key'] = key_sign
    rowDict['issuerLabel'] = next((item['finding'] for item in host_data if item['id'] == 'issuer'), None)
    rowDict['revocationStatus'] = next((item['finding'] for item in host_data if item['id'] == 'crl'), None)
    rowDict['trusted'] = next((item['finding'] for item in host_data if item['id'] == 'trust'), None)
    rowDict['testTime'] = st
    rowDict['httpStatusCode'] = next((item['finding'] for item in host_data if item['id'] == 'HTTP_STATUS_CODE'), None)
    rowDict['sigAlg'] = algorithm
    rowDict['vulnsList'] = get_vulns(host_data)

    rowsList.append(rowDict)

    return rowsList

delimitersDict = {'cef': ' ', 'leef': '\t', 'log': ', '}

patternsDict = {
    'cef': 'CEF:0|SOC Prime|SSL Framework|' + __version__ + '|slf:102|SSL Check|3|{0}\n',
    'leef': 'LEEF:1.0|SOC Prime|SSL Framework|' + __version__ + '|slf:102|{0}\n',
    'log': 'vendor="SOC Prime", product="SSL Framework", version="' + __version__ + '", eventId="slf:102", eventName="SSL Check", severity=3{0}\n'
}

mapDict = {
    'cef': {
        'domain':'fname={0}',
        'ip':'src={0}',
        'commonNames':'cs1={0} cs1Label=Common names',
        'altNames':'cs2={0} cs2Label=Alternative names count',
        'notBefore':'deviceCustomDate1={0} deviceCustomDate1Label=Valid from',
        'notAfter':'deviceCustomDate2={0} deviceCustomDate2Label=Valid until',
        'validUntilD':'',
        'key':'filePermission={0}',
        'issuerLabel':'filePath={0}',
        'revocationStatus':'cs5={0} cs5Label=Revocation status',
        'trusted':'cs6={0} cs6Label=Trusted',
        'testTime':'end={0}',
        'httpStatusCode':'sourceUserId={0}',
        'serverName':'shost={0}',
        'sigAlg':'cs4={0} cs4Label=Signature algorithm',
        'vulnsList':'cs3={0} cs3Label=Vulnerabilities'
        },

    'leef': {
        'domain':'DomainName={0}',
        'ip':'src={0}',
        'commonNames':'commonNames={0}',
        'altNames':'altNames={0}',
        'notBefore':'validFrom={0}',
        'notAfter':'validUntil={0}',
        'validUntilD':'validUntilD={0}',
        'key':'keySign={0}',
        'issuerLabel':'certIssuer={0}',
        'revocationStatus':'revocStatus={0}',
        'trusted':'trustStatus={0}',
        'testTime':'devTime={0}\tdevTimeFormat=MMM dd yyyy HH:mm:ss',
        'httpStatusCode':'httpStatus={0}',
        'serverName':'serverHost={0}',
        'sigAlg':'signAlgorithm={0}',
        'vulnsList':'vulnerabilitiesDomain={0}'
        },

    'log': {
        'domain':'domainName="{0}"',
        'ip':'src="{0}"',
        'commonNames':'commonNames="{0}"',
        'altNames':'altNames="{0}"',
        'notBefore':'validFrom="{0}"',
        'notAfter':'validUntil="{0}"',
        'validUntilD':'validUntilD={0}',
        'key':'keySign="{0}"',
        'issuerLabel':'certIssuer="{0}"',
        'revocationStatus':'revocStatus="{0}"',
        'trusted':'trustStatus="{0}"',
        'testTime':'devTime="{0}"',
        'httpStatusCode':'httpStatus={0}',
        'serverName':'serverHost="{0}"',
        'sigAlg':'signAlgorithm="{0}"',
        'vulnsList':'vulnerabilitiesDomain="{0}"'
        }
}


def dict_to_str(values):
        cefstr = ''
        delimiter = delimitersDict[exportFormat]
        for key in reversed(values.keys()):
            if values[key]:
                cefstr = cefstr + delimiter + mapDict[exportFormat][key].format(values[key])
        return cefstr


def export_report(rowsList):
    pattern = patternsDict[exportFormat]
    rowsPerFile = 5000
    filescount = (len(rowsList) // rowsPerFile) + 1
    for filenum in range(1, filescount + 1):
        try:
            timestamp = datetime.now().strftime('%Y-%m-%d-%H-%M-%S')
            filename = os.path.normpath(
                '{0}/ssl-framework-report-{1}.{2}.{3}'.format(reportsPath, timestamp, filenum, 'tmp'))
            with open(filename, 'w') as f:
                logger.debug('File ' + filename + ' created')
                for row in rowsList[(filenum - 1) * rowsPerFile: filenum * rowsPerFile]:
                    if isinstance(row, dict):
                        try:
                            f.write(pattern.format(dict_to_str(row)))
                        except Exception as e:
                            logger.debug('Can not format message: ' + str(row))
                            raise
                    else:
                        try:
                            f.write(row)
                        except Exception as e:
                            logger.debug('Can not write message: ' + str(row))
                            raise

            logger.debug('File was exported')
            newfname = filename[:-3] + exportFormat
            os.rename(filename, newfname)
            logger.debug('File was renamed')
            filename = newfname
            logger.info('Ssl-framework-report was successfully created, file: {0}'.format(filename))
        except Exception as e:
            msg = 'Could not write file: ' + str(e)
            logger.error(msg)
            raise Exception(msg)  # terminate script


def send_report_via_syslog(rowsList):
    try:
        syslogger = logging.getLogger('syslog')
        syslogger.setLevel(logging.INFO)

        if syslogProtocol == 'udp':
            syslogger.addHandler(SysLogHandler(address=(syslogHost, syslogPort)))
        else:  # TCP only for Python 2.7+
            syslogger.addHandler(SysLogHandler(address=(syslogHost, syslogPort), socktype=socket.SOCK_STREAM))

        pattern = patternsDict[exportFormat]
        for row in rowsList:
            if isinstance(row, dict):
                syslogger.info(pattern.format(dict_to_str(row)))
            else:
                syslogger.info(row)
        logger.info(
            'Ssl-framework-report was successfully created and sent to [{0}:{1}]'.format(syslogHost, syslogPort))
    except Exception as e:
        msg = 'Could not send syslog: ' + str(e)
        logger.error(msg)
        raise Exception(msg)  # terminate script


def get_config(filename):
    _default_config = {
        'main': {
            'maxassessmentstimeout': 60,  # sec
            'waitresulttimeout': 60,  # sec
            'maxcacheage': 1,  # hours
            'reportspath': os.path.normpath(currentdir + '/reports/'),
            'localdomainslistfile': os.path.normpath(currentdir + '/domainslistfile.txt'),
            'exportformat': 'cef',  # CEF, LEEF, SPLUNK
            'connectmaxretries': 10,
            'connectretrytimeout': 60,  # sec
            'use_splunk': 0,
            'proxy_used': 0,
            'proxy_auth_used': 0
        }
    }
    config = ConfigParser.RawConfigParser()
    if os.path.exists(filename):
        config.read(filename)
    else:
        # create default config
        for section in _default_config:
            config.add_section(section)
            for option in _default_config[section]:
                config.set(section, option, _default_config[section][option])
        try:
            logger.info('Create default config: ' + filename)
            with open(filename, 'wb') as configfile:
                config.write(configfile)
        except Exception as e:
            errmsg = 'Could not create config file: ' + str(filename)
            logger.error(errmsg)
            raise Exception(errmsg)

    return config



if __name__ == '__main__':
    try:
        argparser = argparse.ArgumentParser()
        argparser.add_argument("-d", "--domain", help="Scan specified domain", action="store")
        argparser.add_argument("-c", "--config", help="Full path to application folder", action="store")
        argparser.add_argument("-b", "--bash", help="Full path to bash interpreter", action="store")
        args = argparser.parse_args()

        _cfgfilename_default = os.path.normpath(currentdir + '/ssl-framework.cfg')

        # read config ###########################################
        logger.info('Start. Initialization...')
        config_default = get_config(_cfgfilename_default)
        reportsPath = os.path.normpath(os.path.abspath(config_default.get('main', 'reportspath')))
        # blacklist = get_blacklist()

        if not os.path.exists(reportsPath):
            reportsPath = os.path.normpath(currentdir + '/' + config_default.get('main', 'reportsPath'))

        domainsListFile = os.path.normpath(os.path.abspath(config_default.get('main', 'domainslistfile')))

        if not os.path.exists(domainsListFile):
            domainsListFile = os.path.normpath(currentdir + '/' + config_default.get('main', 'domainslistfile'))

        exportFormat = config_default.get('main', 'exportformat').lower()

        if exportFormat == 'splunk':
            exportFormat = 'log'

        sendReportViaSyslog = False
        if config_default.has_section('syslog'):
            sendReportViaSyslog = True
            syslogProtocol = config_default.get('syslog', 'protocol').lower()

            if (sys.version_info < (2, 7)) and (syslogProtocol == 'tcp'):
                logger.warning('Sending syslog over TCP protocol is available only for Python 2.7+')

            syslogHost = config_default.get('syslog', 'host')
            syslogPort = config_default.getint('syslog', 'port')
        # ########################
        if args.domain:
            domainList = [args.domain]
        else:
            domainList = get_list_from_file()
        # ########################
        if args.bash:
            bash = args.bash
        else:
            if os.path.isfile('/bin/bash'):
                bash = '/bin/bash'
            else:
                msg = 'Can\'t find bash interpreter in /bin/. Please specify path using key -b.'
                print msg
                logger.error(msg)
                exit(0)
    except Exception as e:
        logger.error('Error occurred: ' + str(e) + '. Terminate script.')
        raise
    #####################################################################
    try:
        if not domainList:
            msg = 'Domain names list is empty'
            add_event_to_flow({'eventId': '208', 'msg': msg})
            logger.warning(msg)
        else:
            pool = multiprocessing.Pool(processes=15)
            results = pool.map(start_scan, domainList)
            for result in results:
                if result:
                    for row in result:
                        rList = get_report_data(row)
                        logger.info(rList)
                        rowsList.extend(rList)
                else:
                    continue
    except Exception as e:
        logger.warning('Error occurred: ' + str(e) + '. Exporting the collected data.')
        raise
    finally:
        if rowsList:
            if sendReportViaSyslog:
                send_report_via_syslog(rowsList)
            else:
                export_report(rowsList)
        else:
            logger.warning('Cannot create report, result is empty')
            exit(0)
