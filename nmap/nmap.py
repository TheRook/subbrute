#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
nmap.py - version and date, see below

Source code : https://bitbucket.org/xael/python-nmap

Author :

* Alexandre Norman - norman at xael.org

Contributors:

* Steve 'Ashcrow' Milner - steve at gnulinux.net
* Brian Bustin - brian at bustin.us
* old.schepperhand
* Johan Lundberg
* Thomas D. maaaaz
* Robert Bost
 
Licence : GPL v3 or any later version


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


"""


__author__ = 'Alexandre Norman (norman@xael.org)'
__version__ = '0.4.3'
__last_modification__ = '2015.09.11'


import collections
import csv
import io
import os
import re
import shlex
import string
import subprocess
import sys
import types
from xml.etree import ElementTree as ET


try:
    from multiprocessing import Process
except ImportError:
    # For pre 2.6 releases
    from threading import Thread as Process

############################################################################

class PortScanner(object):
    """
    PortScanner class allows to use nmap from python

    """
    
    def __init__(self, nmap_search_path=('nmap','/usr/bin/nmap','/usr/local/bin/nmap','/sw/bin/nmap','/opt/local/bin/nmap') ):
        """
        Initialize PortScanner module

        * detects nmap on the system and nmap version
        * may raise PortScannerError exception if nmap is not found in the path

        :param nmap_search_path: tupple of string where to search for nmap executable. Change this if you want to use a specific version of nmap.
        :returns: nothing

        """
        self._nmap_path = ''                # nmap path
        self._scan_result = {}
        self._nmap_version_number = 0       # nmap version number
        self._nmap_subversion_number = 0    # nmap subversion number
        self._nmap_last_output = ''  # last full ascii nmap output
        is_nmap_found = False       # true if we have found nmap

        self.__process = None

        # regex used to detect nmap (http or https)
        regex = re.compile('Nmap version [0-9]*\.[0-9]*[^ ]* \( http(|s)://.* \)')
        # launch 'nmap -V', we wait after 'Nmap version 5.0 ( http://nmap.org )'
        # This is for Mac OSX. When idle3 is launched from the finder, PATH is not set so nmap was not found
        for nmap_path in nmap_search_path:
            try:
                if sys.platform.startswith('freebsd') or sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                    p = subprocess.Popen([nmap_path, '-V'], bufsize=10000, stdout=subprocess.PIPE, close_fds=True)
                else:
                    p = subprocess.Popen([nmap_path, '-V'], bufsize=10000, stdout=subprocess.PIPE)
                    
            except OSError:
                pass
            else:
                self._nmap_path = nmap_path # save path 
                break
        else:
            raise PortScannerError('nmap program was not found in path. PATH is : {0}'.format(os.getenv('PATH')))            


            
        self._nmap_last_output = bytes.decode(p.communicate()[0]) # store stdout
        for line in self._nmap_last_output.split(os.linesep):
            if regex.match(line) is not None:
                is_nmap_found = True
                # Search for version number
                regex_version = re.compile('[0-9]+')
                regex_subversion = re.compile('\.[0-9]+')

                rv = regex_version.search(line)
                rsv = regex_subversion.search(line)

                if rv is not None and rsv is not None:
                    # extract version/subversion
                    self._nmap_version_number = int(line[rv.start():rv.end()])
                    self._nmap_subversion_number = int(line[rsv.start()+1:rsv.end()])
                break

        if is_nmap_found == False:
            raise PortScannerError('nmap program was not found in path')

        return


    def get_nmap_last_output(self):
        """
        Returns the last text output of nmap in raw text
        this may be used for debugging purpose

        :returns: string containing the last text output of nmap in raw text
        """
        return self._nmap_last_output



    def nmap_version(self):
        """
        returns nmap version if detected (int version, int subversion)
        or (0, 0) if unknown
        :returns: (nmap_version_number, nmap_subversion_number)
        """
        return (self._nmap_version_number, self._nmap_subversion_number)



    def listscan(self, hosts='127.0.0.1'):
        """
        do not scan but interpret target hosts and return a list a hosts
        """
        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        
        self.scan(hosts, arguments='-sL')
        return self.all_hosts()



    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False):
        """
        Scan given hosts

        May raise PortScannerError exception if nmap output was not xml

        Test existance of the following key to know if something went wrong : ['nmap']['scaninfo']['error']
        If not present, everything was ok.

        :param hosts: string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as nmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for nmap '-sU -sX -sC'
        :param sudo: launch nmap with sudo if True

        :returns: scan_result as dictionnary 
        """
        if sys.version_info[0]==2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

        for redirecting_output in ['-oX', '-oA']:
            assert not redirecting_output in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'

        h_args = shlex.split(hosts)
        f_args = shlex.split(arguments)
        
        # Launch scan
        args = [self._nmap_path, '-oX', '-'] + h_args + ['-p', ports]*(ports!=None) + f_args
        if sudo:
            args = ['sudo'] + args

        p = subprocess.Popen(args, bufsize=100000,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)

        # wait until finished
        # get output
        (self._nmap_last_output, nmap_err) = p.communicate()
        self._nmap_last_output = bytes.decode(self._nmap_last_output)
        nmap_err = bytes.decode(nmap_err)

        # If there was something on stderr, there was a problem so abort...  in
        # fact not always. As stated by AlenLPeacock :
        # This actually makes python-nmap mostly unusable on most real-life
        # networks -- a particular subnet might have dozens of scannable hosts,
        # but if a single one is unreachable or unroutable during the scan,
        # nmap.scan() returns nothing. This behavior also diverges significantly
        # from commandline nmap, which simply stderrs individual problems but
        # keeps on trucking.

        nmap_err_keep_trace = []
        if len(nmap_err) > 0:
            regex_warning = re.compile('^Warning: .*')
            for line in nmap_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warning.search(line)
                    if rgw is not None:
                        sys.stderr.write(line+os.linesep)
                        pass
                    else:
                        #raise PortScannerError(nmap_err)
                        nmap_err_keep_trace.append(nmap_err)

        return self.analyse_nmap_xml_scan(nmap_xml_output = self._nmap_last_output,
                                          nmap_err = nmap_err,
                                          nmap_err_keep_trace = nmap_err_keep_trace)


    def analyse_nmap_xml_scan(self, nmap_xml_output=None, nmap_err='', nmap_err_keep_trace=''):
        """
        Analyses NMAP xml scan ouput

        May raise PortScannerError exception if nmap output was not xml

        Test existance of the following key to know if something went wrong : ['nmap']['scaninfo']['error']
        If not present, everything was ok.

        :param nmap_xml_output: xml string to analyse
        :returns: scan_result as dictionnary 
        """

        # nmap xml output looks like :
        # <host starttime="1267974521" endtime="1267974522">
        #   <status state="up" reason="user-set"/>
        #   <address addr="192.168.1.1" addrtype="ipv4" />
        #   <hostnames><hostname name="neufbox" type="PTR" /></hostnames>
        #   <ports>
        #     <port protocol="tcp" portid="22">
        #       <state state="filtered" reason="no-response" reason_ttl="0"/>
        #       <service name="ssh" method="table" conf="3" />
        #     </port>
        #     <port protocol="tcp" portid="25">
        #       <state state="filtered" reason="no-response" reason_ttl="0"/>
        #       <service name="smtp" method="table" conf="3" />
        #     </port>
        #   </ports>
        #   <hostscript>
        #    <script id="nbstat" output="NetBIOS name: GROSTRUC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: &lt;unknown&gt;&#xa;" />
        #    <script id="smb-os-discovery" output=" &#xa;  OS: Unix (Samba 3.6.3)&#xa;  Name: WORKGROUP\Unknown&#xa;  System time: 2013-06-23 15:37:40 UTC+2&#xa;" />
        #    <script id="smbv2-enabled" output="Server doesn&apos;t support SMBv2 protocol" />
        #   </hostscript>
        #   <times srtt="-1" rttvar="-1" to="1000000" />
        # </host>

        # <port protocol="tcp" portid="25">
        #  <state state="open" reason="syn-ack" reason_ttl="0"/>
        #   <service name="smtp" product="Exim smtpd" version="4.76" hostname="grostruc" method="probed" conf="10">
        #     <cpe>cpe:/a:exim:exim:4.76</cpe>
        #   </service>
        #   <script id="smtp-commands" output="grostruc Hello localhost [127.0.0.1], SIZE 52428800, PIPELINING, HELP, &#xa; Commands supported: AUTH HELO EHLO MAIL RCPT DATA NOOP QUIT RSET HELP "/>
        # </port>


        if nmap_xml_output is not None:
            self._nmap_last_output = nmap_xml_output
            
        scan_result = {}


        try:
            dom = ET.fromstring(self._nmap_last_output)
        except Exception:
            if len(nmap_err)>0:
                raise PortScannerError(nmap_err)
            else:
                raise PortScannerError(self._nmap_last_output)

        # nmap command line
        scan_result['nmap'] = {
            'command_line': dom.get('args'),
            'scaninfo': {},
            'scanstats':{'timestr':dom.find("runstats/finished").get('timestr'),
                         'elapsed':dom.find("runstats/finished").get('elapsed'),
                         'uphosts':dom.find("runstats/hosts").get('up'),
                         'downhosts':dom.find("runstats/hosts").get('down'),
                         'totalhosts':dom.find("runstats/hosts").get('total')}
            }

        # if there was an error
        if len(nmap_err_keep_trace)>0:
            scan_result['nmap']['scaninfo']['error'] = nmap_err_keep_trace

        # info about scan
        for dsci in dom.findall('scaninfo'):
            scan_result['nmap']['scaninfo'][dsci.get('protocol')] = {                
                'method': dsci.get('type'),
                'services': dsci.get('services')
                }


        scan_result['scan'] = {}
        
        for dhost in  dom.findall('host'):
            # host ip, mac and other addresses
            host = None
            address_block = {}
            vendor_block = {}
            for address in dhost.findall('address'):
                addtype = address.get('addrtype')
                address_block[addtype] = address.get('addr')
                if addtype == 'ipv4':
                    host = address_block[addtype]
                elif addtype == 'mac' and address.get('vendor') != None:
                    vendor_block[address_block[addtype]] = address.get('vendor')

            if host is None:
                host = dhost.find('address').get('addr')
                
            hostnames = []
            for dhostname in dhost.findall('hostnames/hostname'):
                hostnames.append({
                    'name':dhostname.get('name'),
                    'type':dhostname.get('type'),
                    })
            scan_result['scan'][host] = PortScannerHostDict({'hostnames': hostnames})

            scan_result['scan'][host]['addresses'] = address_block
            scan_result['scan'][host]['vendor'] = vendor_block

            for dstatus in dhost.findall('status'):
                # status : up...
                scan_result['scan'][host]['status'] = {'state': dstatus.get('state'),
                                               'reason': dstatus.get('reason')}
            for dstatus in dhost.findall('uptime'):
                # uptime : seconds, lastboot
                scan_result['scan'][host]['uptime'] = {'seconds': dstatus.get('seconds'),
                                                'lastboot': dstatus.get('lastboot')}
            for dport in dhost.findall('ports/port'):
                # protocol
                proto = dport.get('protocol')
                # port number converted as integer
                port =  int(dport.get('portid'))
                # state of the port
                state = dport.find('state').get('state')
                # reason
                reason = dport.find('state').get('reason')
                # name, product, version, extra info and conf if any
                name,product,version,extrainfo,conf,cpe = '','','','','',''
                for dname in dport.findall('service'):
                    name = dname.get('name')
                    if dname.get('product'):
                        product = dname.get('product')
                    if dname.get('version'):
                        version = dname.get('version')
                    if dname.get('extrainfo'):
                        extrainfo = dname.get('extrainfo')
                    if dname.get('conf'):
                        conf = dname.get('conf')

                    for dcpe in dname.findall('cpe'):
                        cpe = dcpe.text
                # store everything
                if not proto in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host][proto] = {}
                    
                scan_result['scan'][host][proto][port] = {'state': state,
                                                  'reason': reason,
                                                  'name': name,
                                                  'product': product,
                                                  'version': version,
                                                  'extrainfo': extrainfo,
                                                  'conf': conf,
                                                  'cpe': cpe}
                script_id = ''
                script_out = ''
                # get script output if any
                for dscript in dport.findall('script'):
                    script_id = dscript.get('id')
                    script_out = dscript.get('output')
                    if not 'script' in list(scan_result['scan'][host][proto][port].keys()):
                        scan_result['scan'][host][proto][port]['script'] = {}

                    scan_result['scan'][host][proto][port]['script'][script_id] = script_out


            # <hostscript>
            #  <script id="nbstat" output="NetBIOS name: GROSTRUC, NetBIOS user: &lt;unknown&gt;, NetBIOS MAC: &lt;unknown&gt;&#xa;" />
            #  <script id="smb-os-discovery" output=" &#xa;  OS: Unix (Samba 3.6.3)&#xa;  Name: WORKGROUP\Unknown&#xa;  System time: 2013-06-23 15:37:40 UTC+2&#xa;" />
            #  <script id="smbv2-enabled" output="Server doesn&apos;t support SMBv2 protocol" />
            # </hostscript>
            for dhostscript in dhost.findall('hostscript'):
                for dname in dhostscript.findall('script'):
                    hsid = dname.get('id')
                    hsoutput = dname.get('output')

                    if not 'hostscript' in list(scan_result['scan'][host].keys()):
                        scan_result['scan'][host]['hostscript'] = []

                    scan_result['scan'][host]['hostscript'].append(
                        {
                            'id': hsid,
                            'output': hsoutput
                            }
                        )

            for dos in dhost.findall('os'):
                for dosmatch in dos.findall('osmatch'):
                    for dosclass in dosmatch.findall('osclass'):
                        # <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="98"/>
                       ostype = ''
                       vendor = ''
                       osfamily = ''
                       osgen = ''
                       accuracy = ''
                       try:
                           ostype = dosclass.get('type')
                           vendor = dosclass.get('vendor')
                           osfamily = dosclass.get('osfamily')
                           osgen = dosclass.get('osgen')
                           accuracy = dosclass.get('accuracy')
                       except AttributeError:
                           pass
       
                       scan_result['scan'][host]['osclass'] = {
                           'type': ostype,
                           'vendor': vendor,
                           'osfamily': osfamily,
                           'osgen': osgen,
                           'accuracy': accuracy
                       }
       


            for dport in dhost.findall('osclass'):
                # <osclass name="Linux 2.6.31" accuracy="98" line="30043"/>
                name = ''
                accuracy = ''
                line = ''
                try:
                    name = dport.get('name')
                    accuracy = dport.get('accuracy')
                    line = dport.get('line')
                except AttributeError:
                    pass
                if not 'osclass' in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host]['osclass'] = []

                scan_result['scan'][host]['osclass'].append(
                    {
                        'name': name,
                        'accuracy': accuracy,
                        'line': line,
                        }
                    )


            for dport in dhost.findall('osfingerprint'):
                # <osfingerprint fingerprint="OS:SCAN(V=5.50%D=11/[...]S)&#xa;"/>
                fingerprint = ''
                try:
                    fingerprint = dport.get('fingerprint')
                except AttributeError:
                    pass

                scan_result['scan'][host]['fingerprint'] = fingerprint



        self._scan_result = scan_result # store for later use
        return scan_result


    
    def __getitem__(self, host):
        """
        returns a host detail
        """
        if sys.version_info[0]==2:
            assert type(host) in (str, unicode), 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        else:
            assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        return self._scan_result['scan'][host]


    def all_hosts(self):
        """
        returns a sorted list of all hosts
        """
        if not 'scan' in list(self._scan_result.keys()):
            return []
        listh = list(self._scan_result['scan'].keys())
        listh.sort()
        return listh
        

    def command_line(self):
        """
        returns command line used for the scan

        may raise AssertionError exception if called before scanning
        """
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'command_line' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['command_line']


    def scaninfo(self):
        """
        returns scaninfo structure
        {'tcp': {'services': '22', 'method': 'connect'}}

        may raise AssertionError exception if called before scanning
        """
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scaninfo' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['scaninfo']
            
        
    def scanstats(self):
        """
        returns scanstats structure
        {'uphosts': '3', 'timestr': 'Thu Jun  3 21:45:07 2010', 'downhosts': '253', 'totalhosts': '256', 'elapsed': '5.79'}

        may raise AssertionError exception if called before scanning
        """
        assert 'nmap' in self._scan_result, 'Do a scan before trying to get result !'
        assert 'scanstats' in self._scan_result['nmap'], 'Do a scan before trying to get result !'

        return self._scan_result['nmap']['scanstats']        


    def has_host(self, host):
        """
        returns True if host has result, False otherwise
        """
        assert type(host) is str, 'Wrong type for [host], should be a string [was {0}]'.format(type(host))
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if host in list(self._scan_result['scan'].keys()):
            return True

        return False


    def csv(self):
        """
        returns CSV output as text

        Example :
        host;protocol;port;name;state;product;extrainfo;reason;version;conf;cpe
        127.0.0.1;tcp;22;ssh;open;OpenSSH;protocol 2.0;syn-ack;5.9p1 Debian 5ubuntu1;10;cpe
        127.0.0.1;tcp;23;telnet;closed;;;conn-refused;;3;
        127.0.0.1;tcp;24;priv-mail;closed;;;conn-refused;;3;
        """
        assert 'scan' in self._scan_result, 'Do a scan before trying to get result !'

        if sys.version_info < (3,0):
            fd = io.BytesIO()
        else:
            fd = io.StringIO()
            
        csv_ouput = csv.writer(fd, delimiter=';')
        csv_header = [
            'host',
            'protocol',
            'port',
            'name',
            'state',
            'product',
            'extrainfo',
            'reason',
            'version',
            'conf',
            'cpe'
            ]

        csv_ouput.writerow(csv_header)

        for host in self.all_hosts():
            for proto in self[host].all_protocols():
                if proto not in ['tcp', 'udp']:
                    continue
                lport = list(self[host][proto].keys())
                lport.sort()
                for port in lport:
                    csv_row = [
                        host, proto, port, 
                        self[host][proto][port]['name'],
                        self[host][proto][port]['state'],
                        self[host][proto][port]['product'],
                        self[host][proto][port]['extrainfo'],
                        self[host][proto][port]['reason'],
                        self[host][proto][port]['version'],
                        self[host][proto][port]['conf'],
                        self[host][proto][port]['cpe']
                        ]
                    csv_ouput.writerow(csv_row)

        return fd.getvalue()

############################################################################

def __scan_progressive__(self, hosts, ports, arguments, callback, sudo):
    """
    Used by PortScannerAsync for callback
    """
    for host in self._nm.listscan(hosts):
        try:
            scan_data = self._nm.scan(host, ports, arguments, sudo)
        except PortScannerError:
            pass
        if callback is not None:
            callback(host, scan_data)
    return

############################################################################

class PortScannerAsync(object):
    """
    PortScannerAsync allows to use nmap from python asynchronously
    for each host scanned, callback is called with scan result for the host

    """

    def __init__(self):
        """
        Initialize the module

        * detects nmap on the system and nmap version
        * may raise PortScannerError exception if nmap is not found in the path

        """
        self._process = None
        self._nm = PortScanner()
        return


    def __del__(self):
        """
        Cleanup when deleted

        """
        if self._process is not None and self._process.is_alive():
            self._process.terminate()
        return


    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', callback=None, sudo=False):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard nmap is catched and you won't know about it

        :param hosts: string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as nmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for nmap '-sU -sX -sC'
        :param callback: callback function which takes (host, scan_data) as arguments
        :param sudo: launch nmap with sudo if true
        """

        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))
        assert callable(callback) or callback is None, 'The [callback] {0} should be callable or None.'.format(str(callback))

        for redirecting_output in ['-oX', '-oA']:
            assert not redirecting_output in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'


        self._process = Process(
            target = __scan_progressive__,
            args = (self, hosts, ports, arguments, callback, sudo)
            )
        self._process.daemon = True
        self._process.start()
        return


    def stop(self):
        """
        Stop the current scan process

        """
        if self._process is not None:
            self._process.terminate()
        return


    def wait(self, timeout=None):
        """
        Wait for the current scan process to finish, or timeout

        :param timeout: default = None, wait timeout seconds 

        """

        assert type(timeout) in (int, type(None)), 'Wrong type for [timeout], should be an int or None [was {0}]'.format(type(timeout))

        self._process.join(timeout)
        return

    

    def still_scanning(self):
        """
        :returns: True if a scan is currently running, False otherwise

        """
        try:
            return self._process.is_alive()
        except:
            return False

    

############################################################################


class PortScannerYield(PortScannerAsync):
    """
    PortScannerYield allows to use nmap from python with a generator
    for each host scanned, yield is called with scan result for the host

    """

    def __init__(self):
        """
        Initialize the module

        * detects nmap on the system and nmap version
        * may raise PortScannerError exception if nmap is not found in the path

        """
        PortScannerAsync.__init__(self)
        return



    def scan(self, hosts='127.0.0.1', ports=None, arguments='-sV', sudo=False):
        """
        Scan given hosts in a separate process and return host by host result using callback function

        PortScannerError exception from standard nmap is catched and you won't know about it

        :param hosts: string for hosts as nmap use it 'scanme.nmap.org' or '198.116.0-255.1-127' or '216.163.128.20/20'
        :param ports: string for ports as nmap use it '22,53,110,143-4564'
        :param arguments: string of arguments for nmap '-sU -sX -sC'
        :param callback: callback function which takes (host, scan_data) as arguments
        :param sudo: launch nmap with sudo if true

        """

        assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(type(hosts))
        assert type(ports) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(ports))
        assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(type(arguments))

        for redirecting_output in ['-oX', '-oA']:
            assert not redirecting_output in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'

        for host in self._nm.listscan(hosts):
            try:
                scan_data = self._nm.scan(host, ports, arguments, sudo)
            except PortScannerError:
                pass
            yield (host, scan_data)
        return



    def stop(self):
        pass

    def wait(self, timeout=None):
        pass
    

    def still_scanning(self):
        pass

    

############################################################################
    


class PortScannerHostDict(dict):
    """
    Special dictionnary class for storing and accessing host scan result

    """
    def hostnames(self):
        """
        :returns: list of hostnames

        """
        return self['hostnames']

    def hostname(self):
        """
        For compatibility purpose...
        :returns: try to return the user record or the first hostname of the list hostnames

        """
        hostname = ''
        for h in self['hostnames']:
            if h['type'] == 'user':
                return h['name']
        else:
            if len(self['hostnames']) > 0 and 'name' in self['hostnames']:
                return self['hostnames'][0]['name']
            else:
                return ''

        return hostname


    def state(self):
        """
        :returns: host state

        """
        return self['status']['state']

    def uptime(self):
        """
        :returns: host state

        """
        return self['uptime']

    def all_protocols(self):
        """
        :returns: a list of all scanned protocols

        """
        lp = list(self.keys())
        lp.remove('addresses')
        lp.remove('hostnames')
        lp.remove('status')
        lp.remove('vendor')
        lp.sort()
        return lp



    def all_tcp(self):
        """
        :returns: list of tcp ports

        """
        if 'tcp' in list(self.keys()):
            ltcp = list(self['tcp'].keys())
            ltcp.sort()
            return ltcp
        return []
            
    
    def has_tcp(self, port):
        """
        :param port: (int) tcp port
        :returns: True if tcp port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        
        if ('tcp' in list(self.keys())
            and port in list(self['tcp'].keys())):
            return True
        return False


    def tcp(self, port):
        """
        :param port: (int) tcp port
        :returns: info for tpc port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))
        return self['tcp'][port]


    def all_udp(self):
        """
        :returns: list of udp ports

        """
        if 'udp' in list(self.keys()):
            ludp = list(self['udp'].keys())
            ludp.sort()
            return ludp
        return []


    def has_udp(self, port):
        """
        :param port: (int) udp port
        :returns: True if udp port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('udp' in list(self.keys())
            and 'port' in list(self['udp'].keys())):
            return True
        return False


    def udp(self, port):
        """
        :param port: (int) udp port
        :returns: info for udp port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['udp'][port]


    def all_ip(self):
        """
        :returns: list of ip ports

        """
        if 'ip' in list(self.keys()):
            lip = list(self['ip'].keys())
            lip.sort()
            return lip
        return []


    def has_ip(self, port):
        """
        :param port: (int) ip port
        :returns: True if ip port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('ip' in list(self.keys())
            and port in list(self['ip'].keys())):
            return True
        return False


    def ip(self, port):
        """
        :param port: (int) ip port
        :returns: info for ip port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['ip'][port]


    def all_sctp(self):
        """
        :returns: list of sctp ports

        """
        if 'sctp' in list(self.keys()):
            lsctp = list(self['sctp'].keys())
            lsctp.sort()
            return lsctp
        return []


    def has_sctp(self, port):
        """
        :returns: True if sctp port has info, False otherwise

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        if ('sctp' in list(self.keys())
            and port in list(self['sctp'].keys())):
            return True
        return False


    def sctp(self, port):
        """
        :returns: info for sctp port

        """
        assert type(port) is int, 'Wrong type for [port], should be an int [was {0}]'.format(type(port))

        return self['sctp'][port]


    
############################################################################


class PortScannerError(Exception):
    """
    Exception error class for PortScanner class

    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'PortScannerError exception {0}'.format(self.value)


############################################################################

def __get_last_online_version():
    """
    Gets last python-nmap published version
    
    WARNING : it does an http connection to http://xael.org/pages/python-nmap/python-nmap_CURRENT_VERSION.txt

    :returns: a string which indicate last published version (example :'0.4.3')

    """
    import http.client
    conn = http.client.HTTPConnection("xael.org")
    conn.request("GET", "/pages/python-nmap/python-nmap_CURRENT_VERSION.txt")
    online_version = bytes.decode(conn.getresponse().read()).strip()
    return online_version


############################################################################

def convert_nmap_output_to_encoding(value, code="ascii"):
    """
    Change encoding for scan_result object from unicode to whatever
    
    :param value: scan_result as dictionnary
    :param code: default = "ascii", encoding destination

    :returns: scan_result as dictionnary with new encoding
    """
    new_value = {}
    for k in value:
        if type(value[k]) in [dict, nmap.PortScannerHostDict] :
            new_value[k] = convert_to_encoding(value[k], code)
        else:
            new_value[k] = value[k].encode(code)
    return new_value



#<EOF>######################################################################

