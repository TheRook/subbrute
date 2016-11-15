#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
nmap.py - version and date, see below

Source code : https://code.google.com/p/python-nmap/

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


Test strings :
^^^^^^^^^^^^^^
>>> import nmap
>>> if __get_last_online_version() != __version__:
...     raise ValueError('Current version is {0} - Last published version is {1}'.format(__version__, __get_last_online_version()))
>>> nm = nmap.PortScanner()
>>> try:
...     nm.scan(arguments='-wrongargs')
... except nmap.PortScannerError:
...     pass
>>> 'error' in nm.scan('yahoo.fs', arguments='-sP')['nmap']['scaninfo']
True
>>> r=nm.scan('127.0.0.1', '22-25')
>>> r=nm.analyse_nmap_xml_scan(open('../scanme_output.xml').read())
>>> nm.command_line()
'./nmap-6.40/nmap -sV -oX scanme_output.xml scanme.nmap.org'
>>> nm.scaninfo()
{'tcp': {'services': '1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389', 'method': 'connect'}}
>>> nm.all_hosts()
['74.207.244.221']
>>> nm['74.207.244.221'].hostname()
'scanme.nmap.org'
>>> nm['74.207.244.221'].state()
'up'
>>> nm['74.207.244.221'].all_protocols()
['tcp']
>>> nm['74.207.244.221']['tcp'].keys()
dict_keys([80, 9929, 22])
>>> nm['74.207.244.221'].has_tcp(22)
True
>>> nm['74.207.244.221'].has_tcp(23)
False
>>> nm['74.207.244.221']['tcp'][22]
{'product': 'OpenSSH', 'state': 'open', 'version': '5.3p1 Debian 3ubuntu7', 'name': 'ssh', 'conf': '10', 'extrainfo': 'Ubuntu Linux; protocol 2.0', 'reason': 'syn-ack', 'cpe': 'cpe:/o:linux:linux_kernel'}
>>> nm['74.207.244.221']['tcp'][22] == nm['74.207.244.221'].tcp(22)
True
>>> nm['74.207.244.221']['tcp'][22]['state']
'open'
>>> nm.scanstats()['uphosts']
'1'
>>> nm.scanstats()['downhosts']
'0'
>>> nm.scanstats()['totalhosts']
'1'
>>> 'timestr' in nm.scanstats().keys()
True
>>> 'elapsed' in nm.scanstats().keys()
True
>>> nm.listscan('192.168.1.0/30')
['192.168.1.0', '192.168.1.1', '192.168.1.2', '192.168.1.3']
>>> nm.listscan('localhost/30')
['127.0.0.0', '127.0.0.1', '127.0.0.2', '127.0.0.3']
>>> import os
>>> if os.getuid() == 0:
...   r=nm.scan('127.0.0.1', arguments='-O')
...   len(nm['127.0.0.1']['osclass'])>0
...   len(nm.csv()) > 0
... else:
...   True
...   True
True
True
>>> if os.getuid() == 0:
...   r=nm.scan(hosts='127.0.0.1', ports='139', arguments="-sC -T4")
>>> if os.getuid() == 0:
...   nm['127.0.0.1']['hostscript'][0].keys()
dict_keys(['output', 'id'])
>>> if os.getuid() == 0:
...   r=nm.scan('192.168.0.254', arguments='-O')
...   len(nm['192.168.0.254']['vendor']) > 0
... else:
...   True
True
"""


__author__ = 'Alexandre Norman (norman@xael.org)'
__version__ = '0.3.9'
__last_modification__ = '2015.07.31'


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
                p = subprocess.Popen([nmap_path, '-V'], bufsize=10000, stdout=subprocess.PIPE, close_fds=True)
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
        :param sudo: launch nmap with sudo if true

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

        p = subprocess.Popen(args, bufsize=100000, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

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
                
            hostname = ''
            for dhostname in dhost.findall('hostnames/hostname'):
                hostname = dhostname.get('name')
            scan_result['scan'][host] = PortScannerHostDict({'hostname': hostname})

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


            for dport in dhost.findall('osclass'):
                # <osclass type="general purpose" vendor="Linux" osfamily="Linux" osgen="2.6.X" accuracy="98"/>
                ostype = ''
                vendor = ''
                osfamily = ''
                osgen = ''
                accuracy = ''
                try:
                    ostype = dport.get('type')
                    vendor = dport.get('vendor')
                    osfamily = dport.get('osfamily')
                    osgen = dport.get('osgen')
                    accuracy = dport.get('accuracy')
                except AttributeError:
                    pass
                if not 'osclass' in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host]['osclass'] = []

                scan_result['scan'][host]['osclass'].append(
                    {
                        'type': ostype,
                        'vendor': vendor,
                        'osfamily': osfamily,
                        'osgen': osgen,
                        'accuracy': accuracy
                        }
                    )
                    


            for dport in dhost.findall('osmatch'):
                # <osmatch name="Linux 2.6.31" accuracy="98" line="30043"/>
                name = ''
                accuracy = ''
                line = ''
                try:
                    name = dport.get('name')
                    accuracy = dport.get('accuracy')
                    line = dport.get('line')
                except AttributeError:
                    pass
                if not 'osmatch' in list(scan_result['scan'][host].keys()):
                    scan_result['scan'][host]['osmatch'] = []

                scan_result['scan'][host]['osmatch'].append(
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
    def hostname(self):
        """
        :returns: hostname

        """
        return self['hostname']

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
        lp.remove('hostname')
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
    
    WARNING : it does an http connection to http://xael.org/norman/python/python-nmap/python-nmap_CURRENT_VERSION.txt

    :returns: a string which indicate last published version (example :'0.2.3')

    """
    import http.client
    conn = http.client.HTTPConnection("xael.org")
    conn.request("GET", "/norman/python/python-nmap/python-nmap_CURRENT_VERSION.txt")
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


############################################################################


# MAIN -------------------
if __name__ == '__main__':
    import doctest
    # non regression test
    doctest.testmod()


#<EOF>######################################################################

