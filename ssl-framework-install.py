#!/usr/bin/env python

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

__author__ = 'Nikolay Trofimyuk'
__version__ = '1.1.0'
__license__ = 'GPLv3'

import sys
import subprocess
import re
import os
import atexit
import curses
import curses.textpad as textpad
from datetime import datetime
import time
import logging
import ConfigParser



configurator_title = 'SOC Prime SSL Framework configuration wizard v' + __version__

currentdir = os.path.dirname(os.path.abspath(__file__))


def exec_shell_command(command):
    p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p.wait()
    if p.returncode == 2:
        msg  = 'System returned an error while running the command: {0}, error: {1}'.format(command, p.stderr.read().strip())
        logging.error(msg)
        raise Exception(msg)
    elif p.returncode == 1:
        msg  = 'System returned a warning while running the command: {0}, warning: {1}'.format(command, p.stderr.read().strip())
        logging.warning(msg)

    return p.stdout.read()

def create_reports_folder(GUI):
    GUI.print_log('Create reports folder...')
    logging.info('Create reports folder')

    path = os.path.normpath(GUI.masterRezValues['EXPORTPATH'])
    command = 'mkdir -p {0}'.format(path)
    exec_shell_command(command)

    GUI.print_log('Folder was created successfully: ')
    GUI.print_log('  '+str(path))
    logging.info('Folder was created successfully')


def create_config(GUI):

    exportformat = 'CEF'
    d = GUI.masterRezValues['FORMATSDICT']
    for row in d:
        if d[row]['selected']:
            exportformat = d[row]['title']
            break

    _cfgfilename = os.path.normpath(currentdir +'/ssl-framework.cfg')
    _default_config = {
        'main':{
            'maxassessmentstimeout': 60,    #sec
            'waitresulttimeout': 60,        #sec
            'maxcacheage': 1,               #hours
            'reportspath': GUI.masterRezValues['EXPORTPATH'],
            'domainslistfile': os.path.normpath(currentdir +'/domainlist.txt'),
            'exportformat':exportformat,         #CEF, LEEF, SPLUNK
            'connectmaxretries': 10,
            'connectretrytimeout': 60,
            'proxy_used': 0,
            'proxy_auth_used': 0
            }
        }
    
    if GUI.masterRezValues['METHODSDICT'][1]['selected']:   #syslog
        d = GUI.masterRezValues['SYSLOGPROTOCOLSDICT']
        if d[1]['selected']:    #tcp
            syslogProtocol = 'tcp'
        else:
            syslogProtocol = 'udp'
            
        (syslogHost, syslogPort) = GUI.masterRezValues['SYSLOGSETTINGS']
        
        _default_config['syslog'] = {
            'protocol': syslogProtocol, 
            'host': syslogHost,
            'port': syslogPort
            }
        
    (proxyHost, proxyPort, proxyLogin, proxyPass) = GUI.masterRezValues['PROXYSETTINGS']
    if proxyHost:
        _default_config['main']['proxy_used'] = 1
        _default_config['proxy'] = {
            'proxy_host': proxyHost,
            'proxy_port': proxyPort,
            'proxy_login': proxyLogin,
            'proxy_password': proxyPass
            }
    if proxyLogin:
        _default_config['main']['proxy_auth_used'] = 1

    config = ConfigParser.RawConfigParser()
    # create config
    for section in _default_config:
        config.add_section(section)
        for option in _default_config[section]:
            config.set(section, option, _default_config[section][option])

    GUI.print_log('Create config file...')
    logging.info('Create config: '+_cfgfilename)

    try:
        with open(_cfgfilename, 'wb') as configfile:
            config.write(configfile)
    except Exception as e:
        errmsg = 'Could not create config file: '+str(_cfgfilename)
        logging.error(errmsg)
        raise Exception(errmsg)

    GUI.print_log('Config file was created successfully: ')
    GUI.print_log('  '+str(_cfgfilename))
    logging.info('Config file was created successfully')



def create_domainlist(GUI):
    if GUI.masterRezValues['DOMAINLIST']:
        domainlist = GUI.masterRezValues['DOMAINLIST'].split(',')
        domainlist = '\n'.join(domainlist)

        filename = os.path.normpath(currentdir +'/domainlist.txt')
        GUI.print_log('Create domain list file...')
        logging.info('Create domain list file: '+filename)

        try:
            with open(filename, 'w') as f:
                f.write(domainlist)
        except Exception as e:
            errmsg = 'Could not create domain list file: '+str(filename)
            logging.error(errmsg)
            raise Exception(errmsg)

        GUI.print_log('Domain list file was created successfully: ')
        GUI.print_log('  '+str(filename))
        logging.info('Domain list file was created successfully')
    else:
        GUI.print_log('List of domains is empty, domainlist file was not created.')
        logging.warning('List of domains is empty, domainlist file was not created.')




def edit_crontab(GUI):
    GUI.print_log('Edit crontab...')
    logging.info('Edit crontab')

    crontab = exec_shell_command('crontab -l').strip().split('\n')

    if 'no crontab for' in crontab[0]:
        crontab = []
    else:
        i = 0
        for row in crontab:
            if '#ssl-framework-external-web-servers' in row:
                crontab.pop(i)
            i += 1

    (ndays,hour,minute) = GUI.masterRezValues['SCHEDULE']

    if int(ndays) == 1:
        ndays = '*'
    else:
        ndays = '*/' + str(int(ndays))

    filename = os.path.normpath(currentdir +'/ssl-framework-report.py')

    crontab.append('{0} {1} {2} * * /usr/bin/python {3} #ssl-framework-external-web-servers'.format(minute, hour, ndays, filename))
    crontab.append('')
    crontab = '\n'.join(crontab)
    command = 'echo "{0}" | crontab -'.format(crontab)
    exec_shell_command(command)

    GUI.print_log('crontab for external domains was edited successfully')
    logging.info('crontab for external domains was edited successfully.')

logo = \
'''    SSSSSSSSSSSSSSSS               OOOOOOOO                   CCCCCCCCCCCCC
  SSSSSSSSSSSSSSSSSSSS         OOOOOOOOOOOOOOOO            CCCCCCCCCCCCCCCCCCC
 SSSS              SSSS     OOOOOO          OOOOOO       CCCCCCC           CCCC
SSSS                       OOOO                OOOO     CCCC
SSSS                      OOOO                  OOOO   CCCC
 SSSSSSSSSSSS            OOOO                    OOOO CCCC
   SSSSSSSSSSSSSSSSSS    OOOO                    OOOO CCCC
             SSSSSSSSSS  OOOO         II         OOOO CCCC
                    SSSS OOOO        IIII        OOOO CCCC
                    SSSS  OOOO       IIII       OOOO   CCCC
SSSS               SSSS    OOOO      IIII      OOOO     CCCCCCCC           CCCC
 SSSSSSSSSSSSSSSSSSSSS       OOOO    IIII    OOOO         CCCCCCCCCCCCCCCCCCCC
    SSSSSSSSSSSSSSSS           OO    IIII    OO               CCCCCCCCCCCCCC
                                     IIII
PPPPPPPPPPPPPP     RRRRRRRRRRRRRR    IIII    MMM         MMM     EEEEEEEEEEEEEE
PPP         PP     RRR          R    IIII    MMMMMM   MMMMMM     EEE
PPPPPPPPPPPPPP     RRRRRRRRRRR RR    IIII    MM   MMMMM   MM     EEEEEEEEEEEE
PPP                RRR      RRR       II     MM     M     MM     EEE
PPP                RRR        RR             MM           MM     EEEEEEEEEEEEEE

Welcome to SOC Prime SSL Framework configuration wizard.
Press Enter to start setup'''

#########################################################################################################################

def cleanup():
   curses.nocbreak()
   #self.stdscr.keypad(0)
   curses.echo()
   curses.curs_set(1)
   curses.endwin()

#atexit.register(cleanup)

class GUI:
    # General variables
    stdscr = None
    window = None
    textbox = None
    lastkey = 0
    masterRezValues = {}
    logList = []

    # General constants
    tby = 5
    tbx = 1
    tbh = 1
    tbw = 0

    helpMsg1 = 'Use ENTER to confirm, ESC - go back to previous step.'

    validDomainSymbolsList =  sorted(range(ord('a'), ord('z')+1) + \
                                     range(ord('A'), ord('Z')+1) + \
                                     range(ord('0'), ord('9')+1) + \
                                     [ord(' '), ord('-'),ord('.'),ord(','),ord(':')])


    # Constants for connlist
    DOWN = 1
    UP = -1
    SPACE_KEY = 32
    ESC_KEY = 27
    ENTER_KEY = 10

    markCheck = '[X] '
    markUnCheck = '[ ] '

    flagUnSelect = 2
    flagSelect = 1

    colorpairText = 5
    colorpairField = 6

    WX = 1
    WY = 6
    WW = 0
    WH = 0

    logWX = 1
    logWY = 3
    logWW = 0
    logWH = 0

    dlWX = 1
    dlWY = 5
    dlWW = 0
    dlWH = 0


    def cleanup(self):
        curses.nocbreak()
        self.stdscr.keypad(0)
        curses.echo()
        curses.curs_set(1)
        curses.endwin()


    def __init__(self):
        self.stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        #curses.curs_set(0)
        self.stdscr.keypad(1)
        curses.start_color()
        atexit.register(cleanup)


        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)    # 1 unselected,
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)    # 2 selected,
        curses.init_pair(self.colorpairText, curses.COLOR_BLACK, curses.COLOR_WHITE)                    # text
        curses.init_pair(self.colorpairField, curses.COLOR_WHITE, curses.COLOR_BLACK)                    # field
        self.stdscr.bkgd(curses.color_pair(self.colorpairText))

        (LINES, COLS) = self.stdscr.getmaxyx()

        self.tbw = COLS - self.tbx - 1

        self.WW = COLS - self.WX - 2
        self.WH = LINES - self.WY - 1

        self.logWW = COLS - self.logWX - 2
        self.logWH = LINES - self.logWY - 1

        self.dlWW = COLS - self.dlWX - 2
        self.dlWH = LINES - self.dlWY - 1

# General functions #############################################################################
    def printmainwindow(self, header):
        self.stdscr.clear()
        self.stdscr.addstr(0,1, configurator_title, curses.A_BOLD)
        row = 0
        for text in header:
            row += 1
            self.stdscr.addstr(row,1, text, curses.A_BOLD)

    def rectangle(self, win, u, l, b, r):
        hl = '-' * (r-l+1)
        win.addstr(u, l, hl)
        win.addstr(b, l, hl)


    def maketextbox(self, h,w,y,x,value=""):
        self.window = curses.newwin(h,w,y,x)
        self.window.bkgd(curses.color_pair(self.colorpairText))
        txtbox = curses.textpad.Textbox(self.window)
        self.rectangle(self.stdscr,y-1,x-1,y+h,x+w)
        self.window.addstr(0,0,value)
        self.stdscr.refresh()
        return txtbox




    def textboxvalidator(self, key):
        if key == 27 or key == 10 or key == 9:
            self.lastkey = key
            return 7
        else:
            return key

    def textboxvalidator_int(self, key):
        if key == 27 or key == 10 or key == 9:
            self.lastkey = key
            return 7
        elif (key>=48 and key<=57) or key == curses.KEY_BACKSPACE: # [0-9]
            return key
        else:
            return

    def textboxvalidator_host(self, key):
        if key == 27 or key == 10 or key == 9:
            self.lastkey = key
            return 7
        elif (key in [45,46,92,95] 
             or (key>=48 and key<=57) 
             or (key>=65 and key<=90) 
             or (key>=97 and key<=122) 
             or key == curses.KEY_BACKSPACE): #-.\_[0-9][A-Z][a-z]
            return key
        else:
            return

    def textboxvalidator_domainlist(self, key):
        if key == 27 or key == 10:
            self.lastkey = key
            return 7
        elif key in self.validDomainSymbolsList or key in [curses.KEY_BACKSPACE,curses.KEY_LEFT,curses.KEY_RIGHT,curses.KEY_UP,curses.KEY_DOWN]:
            return key
        else:
            return

# Functions for list ##########################################################################
    def print_list(self, rowsDict, cursorPosition, topLineNum, bottomLineNum):
        self.window.clear()
        row = 0
        for conn in sorted(rowsDict)[topLineNum:bottomLineNum+1]:
            if rowsDict[conn]['selected']:
                mark = self.markCheck
            else:
                mark = self.markUnCheck

            if cursorPosition == conn:
                colorpair = self.flagSelect
            else:
                colorpair = self.flagUnSelect

            text = mark + rowsDict[conn]['title']
            text = text + (self.WW - len(text) - 1)*' '
            self.window.addstr(row, 0, text, curses.color_pair(colorpair))
            row += 1

        self.window.refresh()


    def updown(self, increment, cursorPosition, topLineNum, bottomLineNum, maxBottomLineNum):
        # paging
        if increment == self.UP and cursorPosition == topLineNum and topLineNum > 0:
            topLineNum += self.UP
            bottomLineNum += self.UP

        elif increment == self.DOWN and cursorPosition == bottomLineNum and bottomLineNum < maxBottomLineNum:
            topLineNum += self.DOWN
            bottomLineNum += self.DOWN
        # move cursor
        if increment == self.UP and cursorPosition > 0:
            cursorPosition += self.UP
        elif increment == self.DOWN and cursorPosition < bottomLineNum:
            cursorPosition += self.DOWN

        return (cursorPosition, topLineNum, bottomLineNum)

# Master steps ###################################################################################
    def step_print_logo(self):
        curses.curs_set(0)
        self.stdscr.clear()
        row = 0
        for text in logo.split('\n'):
            row += 1
            self.stdscr.addstr(row,1, text)

        self.stdscr.refresh()

        while True:
            key = self.stdscr.getch()
            if key == 10:
                self.lastkey = key
                break


    def step_enter_exportpath(self, text):
        curses.curs_set(1)
        errormsg = ''
        rePtrn_path = re.compile('^/{1,2}((/{1}\.{1})?[a-zA-Z0-9_ \.\-]+/?)+$')
        while True:
            self.printmainwindow(["Step 3. Enter ABSOLUTE PATH to export results.", 'Use ENTER to confirm',errormsg])
            self.textbox = self.maketextbox(self.tbh, self.tbw, self.tby, self.tbx, text)
            self.stdscr.refresh()
            text = self.textbox.edit(self.textboxvalidator).strip()

            if self.lastkey == 10 and re.match(rePtrn_path, text):
                errormsg = ''
                break
            if self.lastkey == 27: 
                break
            else:
                errormsg = 'Invalid path!'


        del self.textbox
        del self.window
        return text



    def step_select_option(self, rowsDict, windowTitle):
        curses.curs_set(0)

        self.printmainwindow([windowTitle,
                              "Use UP/DOWN arrows to list and SPACE to select/unselect",
                              self.helpMsg1])

        self.window = curses.newwin(self.WH, self.WW, self.WY, self.WX)
        self.window.bkgd(curses.color_pair(self.colorpairText))

        self.rectangle(self.stdscr, self.WY-1, self.WX-1, self.WY+self.WH, self.WX+self.WW)

        self.stdscr.refresh()
        ####################################

        cursorPosition = 0
        topLineNum = 0
        bottomLineNum = topLineNum + self.WH -1
        maxBottomLineNum = len(rowsDict) - 1
        if bottomLineNum > maxBottomLineNum:
            bottomLineNum = maxBottomLineNum

        key = ''
        while True:
            self.print_list(rowsDict, cursorPosition, topLineNum, bottomLineNum)
            key = self.stdscr.getch()
            if key == 27 or key == 10:
                for row in rowsDict:
                    if rowsDict[row]['selected']:
                        self.lastkey = key
                        return rowsDict

            elif key == curses.KEY_UP:
                (cursorPosition, topLineNum, bottomLineNum) = self.updown(self.UP, cursorPosition, topLineNum, bottomLineNum, maxBottomLineNum)
            elif key == curses.KEY_DOWN:
                (cursorPosition, topLineNum, bottomLineNum) = self.updown(self.DOWN, cursorPosition, topLineNum, bottomLineNum, maxBottomLineNum)
            elif key == ord(' '):
                for row in rowsDict:
                    rowsDict[row]['selected'] = False
                rowsDict[cursorPosition]['selected'] = True

        del self.window
        return rowsDict



##############################################################################
    def makefield(self, h,w,y,x, indent=0, title='', value=""):
        window = curses.newwin(h,w-indent,y,x+indent)
        window.bkgd(curses.color_pair(self.colorpairText))
        txtbox = curses.textpad.Textbox(window)
        window.addstr(0, 0, value)

        self.stdscr.addstr(y, x, title)
        self.stdscr.addch(y, x+indent-1, '[')
        self.stdscr.addch(y, x+w, ']')

        self.stdscr.refresh()
        window.refresh()

        return txtbox

    def validateNDays(self, val):
        if val:
            val = int(val)
            if val > 0:
                return True

        return False

    def validateHour(self, val):
        if val:
            val = int(val)
            if val >= 0 and val <= 23:
                return True

        return False

    def validateMinute(self, val):
        if val:
            val = int(val)
            if val >= 0 and val <= 59:
                return True

        return False

    def validateField(self, value, validator, y, x):
        if validator(value):
            errormsg = '              '
            rez = True
        else:
            errormsg = 'Invalid value!'
            rez = False

        self.stdscr.addstr(y, x, errormsg)
        self.stdscr.refresh()
        return rez


    def step_schedule(self, (ndays,hour,minute)):

        indent = 15
        fieldW = 18

        curses.curs_set(1)

        self.printmainwindow(["Step 6. Setup schedule task.", self.helpMsg1, 'Use TAB for select field.'])
        self.stdscr.refresh()

        self.stdscr.addstr(4, 1, 'Program will run...')
        fieldDays = self.makefield(1, fieldW, 5, 1, indent, 'Every N days:', ndays)
        fieldHour = self.makefield(1, fieldW, 6, 1, indent, 'In hour:', hour)
        fieldMinute = self.makefield(1, fieldW, 7, 1, indent, 'In minute:', minute)


        fieldsList = [fieldDays, fieldHour, fieldMinute]
        validatorsList = [self.validateNDays, self.validateHour, self.validateMinute]
        rez = ['','','']

        currentField = 0
        maxFieldNum = len(fieldsList)

        while True:
            fieldsList[currentField].win.refresh()
            rez[currentField] = fieldsList[currentField].edit(self.textboxvalidator_int).strip()

            if self.lastkey == 9:
                if self.validateField(rez[currentField], validatorsList[currentField], 5 + currentField, fieldW + 3):
                    currentField += 1
                    if currentField == maxFieldNum:
                        currentField = 0
                #else stay in field

            elif self.lastkey == 10 :
                allOk = True


                for i in range(0, maxFieldNum):
                    rez[i] = fieldsList[i].gather().strip()
                    if not self.validateField(rez[i], validatorsList[i], 5 + i, fieldW + 3):
                        allOk = False
                if allOk:
                    break

            elif self.lastkey == 27:
                break

        return tuple(rez)
        
    def validateNothing(self, val):
        return True
        
    def validateHost(self, val):
        return bool(val)

        
    def validatePort(self, val):
        if val:
            val = int(val)
            if val > 0 and val <= 65535:
                return True
        return False
    
    
    def step_syslog_settings(self, (syslogHost, syslogPort)):

        indent = 8
        fieldW = 60

        curses.curs_set(1)

        self.printmainwindow(["Step 3.2. Syslog settings.", self.helpMsg1, 'Use TAB for select field.'])
        self.stdscr.refresh()

        #self.stdscr.addstr(4, 1, 'Program will run...')
        field1 = self.makefield(1, fieldW, 5, 1, indent, 'Server:', syslogHost)
        field2 = self.makefield(1, fieldW, 6, 1, indent, 'Port:', syslogPort)



        fieldsList = [field1, field2]
        keyValidatorsList = [self.textboxvalidator_host, self.textboxvalidator_int]
        validatorsList = [self.validateHost, self.validatePort]
        
        rez = ['','']

        currentField = 0
        maxFieldNum = len(fieldsList)

        while True:
            fieldsList[currentField].win.refresh()
            rez[currentField] = fieldsList[currentField].edit(keyValidatorsList[currentField]).strip()

            if self.lastkey == 9:
                if self.validateField(rez[currentField], validatorsList[currentField], 5 + currentField, fieldW + 3):
                    currentField += 1
                    if currentField == maxFieldNum:
                        currentField = 0
                #else stay in field

            elif self.lastkey == 10 :
                allOk = True


                for i in range(0, maxFieldNum):
                    rez[i] = fieldsList[i].gather().strip()
                    if not self.validateField(rez[i], validatorsList[i], 5 + i, fieldW + 3):
                        allOk = False
                if allOk:
                    break

            elif self.lastkey == 27:
                break

        return tuple(rez)
        
        
    #####    
    def step_proxy_settings(self, (proxyHost, proxyPort, proxyLogin, proxyPass)):

        indent = 10
        fieldW = 60

        curses.curs_set(1)

        self.printmainwindow(["Step 4. Proxy settings.", self.helpMsg1, 'Use TAB for select field.'])
        self.stdscr.refresh()

        self.stdscr.addstr(4, 1, 'If you do not need to use a proxy, leave the fields blank and press Enter.')
        self.stdscr.addstr(5, 1, 'Login and Password can be empty.')

        field1 = self.makefield(1, fieldW, 6, 1, indent, 'Server:', proxyHost)
        field2 = self.makefield(1, fieldW, 7, 1, indent, 'Port:', proxyPort)
        field3 = self.makefield(1, fieldW, 8, 1, indent, 'Login:', proxyLogin)
        field4 = self.makefield(1, fieldW, 9, 1, indent, 'Password:', proxyPass)


        fieldsList = [field1, field2, field3, field4]
        keyValidatorsList = [self.textboxvalidator_host, self.textboxvalidator_int, self.textboxvalidator, self.textboxvalidator]
        validatorsList = [self.validateNothing, self.validateNothing, self.validateNothing, self.validateNothing]
        
        rez = ['','','','']

        currentField = 0
        maxFieldNum = len(fieldsList)

        while True:
            fieldsList[currentField].win.refresh()
            rez[currentField] = fieldsList[currentField].edit(keyValidatorsList[currentField]).strip()

            if self.lastkey == 9:
                if self.validateField(rez[currentField], validatorsList[currentField], 6 + currentField, fieldW + 3):
                    currentField += 1
                    if currentField == maxFieldNum:
                        currentField = 0
                #else stay in field

            elif self.lastkey == 10 :
                allOk = True


                for i in range(0, maxFieldNum):
                    rez[i] = fieldsList[i].gather().strip()
                    if not self.validateField(rez[i], validatorsList[i], 6 + i, fieldW + 3):
                        allOk = False
                if allOk:
                    break

            elif self.lastkey == 27:
                break

        return tuple(rez)
########################################

    def step_enter_domain_list(self, text):
        curses.curs_set(1)
        errormsg = ''
        while True:
            self.printmainwindow(["Step 5. Fill domains list (comma separated).",
                                "Allowed characters: a-z,A-Z,'-',comma,dot. Other symbols will be ignored.", self.helpMsg1])
            self.textbox = self.maketextbox(self.dlWH, self.dlWW, self.dlWY, self.dlWX, text)

            text = self.textbox.edit(self.textboxvalidator_domainlist).strip()
            self.stdscr.refresh()
            break

        del self.textbox
        del self.window
        rePtrn_escapeSpecChars = re.compile('([a-zA-Z0-9\-,\.])')
        return  (''.join(rePtrn_escapeSpecChars.findall(text))).lower()


######################################

    def print_log(self, text):

        self.logList.append(text[0:self.logWW-1] + (self.logWW - len(text) - 1)*' ')
        self.logList = self.logList[-self.logWH:]
        i = 0
        for row in self.logList:
            self.window.addstr(i,0,row)
            i += 1

        time.sleep(0.5)
        self.window.refresh()



    def step_last(self):
        curses.curs_set(0)
        self.printmainwindow(["Step 7. Configuration.", 'Press ENTER for start process or ESC for go back to previous step.'])

        while True:
            key = self.stdscr.getch()
            if key == 27:
                self.lastkey = key
                return
            elif key == 10:

                self.window = curses.newwin(self.logWH, self.logWW, self.logWY, self.logWX)
                self.window.bkgd(curses.color_pair(self.colorpairText))
                self.rectangle(self.stdscr, self.logWY-1, self.logWX-1, self.logWY+self.logWH, self.logWX+self.logWW)
                self.stdscr.refresh()

                try:
                    create_config(self)
                    create_domainlist(self)
                    create_reports_folder(self)
                    # edit_crontab(self)
                    # edit_local_crontab(self)
                except Exception as e:
                    logging.error(str(type(e))+ ': ' + str(e))
                    self.print_log(str(e))
                    self.print_log('During work an error occurred. Please see install.log for details.')

                self.print_log('Process done. Press ENTER to exit.')

                while True:
                    key = self.stdscr.getch()
                    if key == 10:
                        self.lastkey = key
                        return

    def get_list_dict(self, rows):
        rowsDict = {}
        i = 0
        for row in rows:
            rowsDict[i] = {'title':row, 'selected':False}
            i += 1
        return rowsDict

    def skip_step(self, stepNum):
        
        if stepNum in [4,5] and self.masterRezValues['METHODSDICT'][0]['selected']: #file
            return True
        elif stepNum == 3 and self.masterRezValues['METHODSDICT'][1]['selected']: #syslog
            return True
        
        return False
    
    
    
    def runMaster(self):
        exportFormatsList = ['cef','leef','splunk']
        exportMethodsList = ['file','syslog']
        syslogProtocolsList = ['UDP','TCP (only for Python 2.7+)']


        self.masterRezValues['FORMATSDICT'] = self.get_list_dict(exportFormatsList)
        self.masterRezValues['METHODSDICT'] = self.get_list_dict(exportMethodsList)
        self.masterRezValues['SYSLOGPROTOCOLSDICT'] = self.get_list_dict(syslogProtocolsList)
        self.masterRezValues['SYSLOGSETTINGS'] = ('','')
        self.masterRezValues['EXPORTPATH'] = os.path.normpath(currentdir +'/reports/')
        self.masterRezValues['PROXYSETTINGS'] = ('','','','')
        self.masterRezValues['SCHEDULE'] = ('1','03','30')
        self.masterRezValues['DOMAINLIST'] = ''

        step = 0
        maxsteps = 9


        stepsDict = {
            0:{'func':'step_print_logo'},
            1:{'func':'step_select_option',           'rezval':'FORMATSDICT', 'params':['Step 1. Select export format.']},
            2:{'func':'step_select_option',           'rezval':'METHODSDICT', 'params':['Step 2. Select export method.']},
            3:{'func':'step_enter_exportpath',        'rezval':'EXPORTPATH'},
            4:{'func':'step_select_option',           'rezval':'SYSLOGPROTOCOLSDICT', 'params':['Step 3.1. Select syslog protocol.']},
            5:{'func':'step_syslog_settings',         'rezval':'SYSLOGSETTINGS'},
            6:{'func':'step_proxy_settings',          'rezval':'PROXYSETTINGS'},
            7:{'func':'step_enter_domain_list',       'rezval':'DOMAINLIST'},
            8:{'func':'step_schedule',                'rezval':'SCHEDULE'},
            9:{'func':'step_last'}
            }

        while True:
            if not self.skip_step(step):
                item = stepsDict[step]
                if 'params' in item.keys(): 
                    params = item['params']
                else:
                    params = []
                
                if 'rezval' in item.keys():
                    rezkey = item['rezval']
                    self.masterRezValues[rezkey] = getattr(self, item['func'])(self.masterRezValues[rezkey], *params)
                else:
                    getattr(self, item['func'])(*params)

            if self.lastkey == 27:
                if step > 1:
                    step -= 1
            elif self.lastkey == 10:
                step += 1
                if step > maxsteps:
                    break



#########################################################################################################################

if __name__ == '__main__':
    logging.basicConfig(filename='install.log', filemode='w', level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s',)

    if sys.platform != 'linux2':
        msg = configurator_title +'. Only for Linux! Exit....'
        print msg
        logging.warning(msg)
        exit(0)

    try:
        logging.info('Initialize GUI')
        gui = GUI()

        gui.runMaster()

        gui.cleanup()

        logging.info('Exit....')
    except Exception as e:
        gui.cleanup()
        print 'During work an error occurred. Please see install.log for details.'
        print str(type(e))+ ': ' + str(e)
        logging.error(str(type(e))+ ': ' + str(e))
