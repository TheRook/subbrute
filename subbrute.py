#!/usr/bin/env python
#
#SubBrute v2.0
#A (very) fast subdomain spider.
#
#Maintained by rook
#Contributors:
#JordanMilne, KxCode, rc0r, memoryprint, ppaulojr  
#
import dnslib
import re
import optparse
import os
import signal
import time
import sys
import uuid
import random
import ctypes
import json
import string
import itertools
import datetime

#Python 2.x and 3.x compatiablity
#We need the Queue library for exception handling
try:
    import queue as Queue
except:
    import Queue

#The 'multiprocessing' library does not rely upon a Global Interpreter Lock (GIL)
import multiprocessing

#Microsoft compatiablity
if sys.platform.startswith('win'):
    #Drop-in replacement,  subbrute + multiprocessing throws exceptions on windows.
    import threading
    multiprocessing.Process = threading.Thread

#A resolver wrapper around dnslib.py
class resolver:
    #Google's DNS servers are only used if zero resolvers are specified by the user.
    pos = 0
    rcode = ""
    wildcards = {}
    failed_code = False
    last_resolver = ""

    def __init__(self, nameservers = ['8.8.8.8','8.8.4.4']):
        self.nameservers = nameservers

    def query(self, hostname, query_type = 'ANY', name_server = False, use_tcp = False):
        ret = []
        response = None
        if name_server == False:
            name_server = self.get_ns()
        else:
            self.wildcards = {}
            self.failed_code = None
        self.last_resolver = name_server
        query = dnslib.DNSRecord.question(hostname, query_type.upper().strip())
        try:
            response_q = query.send(name_server, 53, use_tcp, timeout = 30)
            if response_q:
                response = dnslib.DNSRecord.parse(response_q)
            else:
                raise IOError("Empty Response")
        except Exception as e:
            #IOErrors are all conditions that require a retry.
            raise IOError(str(e))
        if response:
            self.rcode = dnslib.RCODE[response.header.rcode]
            for r in response.rr:
                try:
                    rtype = str(dnslib.QTYPE[r.rtype])
                except:#Server sent an unknown type:
                    rtype = str(r.rtype)
                #Fully qualified domains may cause problems for other tools that use subbrute's output.
                rhost = str(r.rname).rstrip(".")
                ret.append((rhost, rtype, str(r.rdata)))
            #What kind of response did we get?
            if self.rcode not in ['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED']:
                trace('!Odd error code:', self.rcode, hostname, query_type)
            #Is this a perm error?  We will have to retry to find out.
            if self.rcode in ['SERVFAIL', 'REFUSED', 'FORMERR', 'NOTIMP', 'NOTAUTH']:
                raise IOError('DNS Failure: ' + hostname + " - " + self.rcode)
            #Did we get an empty body and a non-error code?
            elif not len(ret) and self.rcode != "NXDOMAIN":
                raise IOError("DNS Error - " + self.rcode + " - for:" + hostname)
        return ret

    def was_successful(self):
        ret = False
        if self.failed_code and self.rcode != self.failed_code:
            ret = True
        elif self.rcode == 'NOERROR':
            ret = True
        return ret

    def get_returncode(self):
        return self.rcode

    def get_ns(self):
        if self.pos >= len(self.nameservers):
            self.pos = 0
        ret = self.nameservers[self.pos]
        # we may have metadata on how this resolver fails
        try:
            ret, self.wildcards, self.failed_code = ret
        except:
            self.wildcards = {}
            self.failed_code = None
        self.pos += 1
        return ret

    def add_ns(self, resolver):
        if resolver:
            self.nameservers.append(resolver)

    def get_authoritative(self, hostname):
        ret = []
        while not ret and hostname.count(".") >= 1:
            try:
                trace("Looking for nameservers:", hostname)
                nameservers = self.query(hostname, 'NS', use_tcp=False)
            except IOError:#lookup failed.
                nameservers = []
            for n in nameservers:
                #A DNS server could return anything.
                rhost, record_type, record = n
                if record_type == "NS":
                    #Return all A records for this NS lookup.
                    a_lookup = self.query(record.rstrip("."), 'A', use_tcp=False)   
                    for a_host, a_type, a_record in a_lookup:
                        ret.append(a_record)
                #If a nameserver wasn't found try the parent of this sub.
            hostname = hostname[hostname.find(".") + 1:]
        return ret

    def get_last_resolver(self):
        return self.last_resolver

class verify_nameservers(multiprocessing.Process):

    def __init__(self, target, query_type, resolver_q, resolver_list, authoritative = False):
        multiprocessing.Process.__init__(self, target = self.run)
        self.daemon = True
        signal_init()
        self.authoritative = authoritative

        self.start_time = 0
        self.resolver_q = resolver_q
        self.query_type = query_type
        self.resolver_list = resolver_list
        self.resolver = resolver()
        #The domain provided by the user.
        self.target = target
        #Resolvers that will work in a pinch:
        self.backup_resolver = ['8.8.8.8', '8.8.4.4', '127.0.0.1']
        self.prev_wildcards = {}

    #This process cannot block forever,  it  needs to check if its time to die.
    def add_nameserver(self, nameserver):
        keep_trying = True
        while keep_trying:
            try:
                self.resolver_q.put(nameserver, timeout = 1)
                trace("Added nameserver:", nameserver)
                keep_trying = False
            except Exception as e:
                if type(e) == Queue.Full or str(type(e)) == "<class 'queue.Full'>":
                    keep_trying = True

    def verify(self, nameserver_list):
        added_resolver = False
        for server in nameserver_list:
            server = server.strip()
            if server:
                try:
                    #Only add the nameserver to the queue if we can detect wildcards.
                    verified_server = self.find_wildcards(self.target, server)
                    if verified_server:
                        #wildcards have been added to the set, it is now safe to be added to the queue.
                        #blocking queue,  this process will halt on put() when the queue is full:
                        self.add_nameserver(verified_server)
                        added_resolver = True
                    else:
                        trace("Rejected nameserver - wildcard:", server)
                except Exception as e:
                    #Rejected server :(
                    trace("Rejected nameserver - unreliable:", server, type(e)) 
        return added_resolver

    def run(self):
        #Every user will get a different set of resovlers, this helps redistribute traffic.
        random.shuffle(self.resolver_list)
        if not self.verify(self.resolver_list):
            #This should never happen,  inform the user.
            sys.stderr.write('Warning: No nameservers found, trying fallback list.\n')
            #Try and fix it for the user:
            self.verify(self.backup_resolver)
        #End of the resolvers list.
        try:
            self.resolver_q.put(False, timeout = 1)
        except:
            pass

    #Only add the nameserver to the queue if we can detect wildcards. 
    #Returns False on error.
    def find_wildcards(self, host, server):
        wildcards = {}
        resolver_fail_code = False
        #We want sovle the following three problems:
        #1)The target might have a wildcard DNS record.
        #2)The target maybe using geolocaiton-aware DNS.
        #I have seen a CloudFlare Enterprise customer with these two conditions.
        try:
            #start_time means this thread isn't dead
            self.start_time = datetime.datetime.now()
            #make sure we can query the host
            blanktest = self.resolver.query(self.target, self.query_type, server)
            if self.query_type == "ANY":
                #If the type was ANY we should have gotten some records
                if not len(blanktest) and not self.authoritative:
                    return False
            elif not self.resolver.was_successful():
                trace("Cannot perform ", self.query_type, " request:", host)
                return False
        except Exception as e:
            if not self.authoritative:
                trace("Cannot perform ", self.query_type, " request:", host)
                return False
        start_counter = 128
        test_counter = start_counter
        looking_for_wildcards = True
        while looking_for_wildcards and test_counter >= 0:
            looking_for_wildcards = False
            #Don't get lost, this nameserver could be playing tricks.
            test_counter -= 1            
            try:
                #Using a 32 char string every time may be too predictable.
                x = uuid.uuid4().hex[0:random.randint(6, 32)]
                testdomain = "%s.%s" % (x, host)
                self.start_time = datetime.datetime.now() # I'm not dead yet!
                wildtest = self.resolver.query(testdomain, self.query_type, server)
                #This record may contain a list of wildcards.
                if len(wildtest):
                    for w in wildtest:
                        return_name, record_type, data = w
                        if record_type in ["CNAME", "A", "AAAA", "MX"]:
                            data = str(data)
                            #All authoritative NS for the same hsot *should* have the same wildcards
                            if self.prev_wildcards:
                                #Have we need this wildcard before?
                                if data in self.prev_wildcards:
                                    #We have seen this wildcards before.
                                    #We do an update, because we may have found a new wildcard
                                    #specific to the NS server we are testing.
                                    wildcards.update(self.prev_wildcards)
                                    #Look for afew more wildcards, and then return.
                                    if test_counter > 2:
                                        test_counter = 2
                            if data not in wildcards:
                                #wildcards were detected.
                                wildcards[data] = None
                                #found atleast one wildcard, look for more.
                                looking_for_wildcards = True
                    #If we keep getting wildcards, keep looking (N * 8) + 8 times,
                    #where N is the total number of wildcards found.
                    #Test case: airbnb.com
                    if test_counter >= start_counter - len(wildcards) * 8 - 8:
                        looking_for_wildcards = True
            except Exception as e:
                #This resolver maybe flakey, we don't want it for our tests.
                if not self.authoritative:
                    trace("wildcard exception:", server, type(e))
                    return False
                else:
                    #The authoritative server isn't going to give us wildcards
                    looking_for_wildcards = False
            finally:
                #We always need the return code, it can be None
                resolver_fail_code = self.resolver.get_returncode()
        #If we hit the end of our depth counter and,
        #there are still wildcards, then reject this nameserver because it smells bad.
        if test_counter >= 0 or self.authoritative:
            self.prev_wildcards = wildcards
            return (server, wildcards, resolver_fail_code)
        else:
            return False

class lookup(multiprocessing.Process):

    def __init__(self, in_q, in_q_priority, out_q, resolver_q, domain):
        multiprocessing.Process.__init__(self, target = self.run)
        signal_init()
        self.required_nameservers = 16
        self.in_q = in_q
        self.in_q_priority = in_q_priority
        self.out_q = out_q
        self.resolver_q = resolver_q        
        self.domain = domain
        #Passing an empty array forces the resolver object to use our nameservers
        self.resolver = resolver([])
        self.start_time = 0
        self.current_work = None

    def get_ns(self):
        ret = False
        try:
            ret = self.resolver_q.get_nowait()
            if ret == False:
                #Queue is empty,  inform the rest.
                self.resolver_q.put(False)
        except:
            pass      
        return ret  

    def get_ns_blocking(self):
        ret = False
        ret = self.resolver_q.get()
        if ret == False:
            trace("get_ns_blocking - Resolver list is empty.")
            #Queue is empty,  inform the rest.
            self.resolver_q.put(False)
            ret = []
        return ret

    def check(self, host, record_type = "ANY", total_rechecks = 0):
        trace("Checking:", host)
        cname_record = []
        retries = 0        
        if len(self.resolver.nameservers) <= self.required_nameservers:
            #This process needs more nameservers,  lets see if we have one available
            self.resolver.add_ns(self.get_ns())
        #Ok we should be good to go.
        while True:
            try:
            #Query the nameserver, this is not simple...
                if not record_type or record_type == "ANY":
                    resp = self.resolver.query(host)
                    #A DNS record may exist without data. Usually this is a parent domain.
                    if self.resolver.was_successful() and not resp:
                        resp = [(host, self.resolver.get_returncode(), "")]
                    return resp
                if record_type == "CNAME":
                    added_cname = False
                    #A max 20 lookups
                    cname_host = host
                    resp = self.resolver.query(cname_host, "A", total_rechecks)
                    if not resp:
                        resp = self.resolver.query(cname_host, "AAAA", total_rechecks)
                    if not resp:
                        resp = self.resolver.query(cname_host, "CNAME", total_rechecks)
                    for r in resp:
                        return_name, record_type, record_data = r
                        #if record_type in ["CNAME", "A", "AAAA"]:
                        cname_host = str(record_data).rstrip(".")
                        cname_record.append(cname_host)
                    if not added_cname:
                        break
                    if cname_record:
                        ret = [(host, record_type, cname_record)]
                    else:
                        ret = False
                        #No response?  then return what we have.
                    return ret
                else:
                    #All other records:
                    return self.resolver.query(host, record_type)
            except (IOError, TypeError) as e:
                if total_rechecks >= 2 or \
                        (retries >= 1 and self.resolver.get_returncode() == "NOERROR"):
                    #Multiple threads have tried and given up
                    trace('Giving up:', host, self.resolver.get_returncode())
                    return [(host, self.resolver.get_returncode(), "")]
                elif retries >= 2:
                    #This thread has tried and given    up
                    trace('Exception:', type(e), " - ", e)
                    self.in_q_priority.put((host, record_type, total_rechecks + 1))
                    return False
                else:
                    #Retry the same request on the same thread.
                    time.sleep(retries)
                    #Give the DNS server a chance to cool off,  there maybe a rate-limit.
                    retries += 1

    def get_work(self):
        work = False
        #Check the priority queue first,  these results are more likely to have data.
        try:
            work = self.in_q_priority.get_nowait()
        except:
            work = False
        #the priority queue is empty, check the normal queue
        if not work:
            work = self.in_q.get()
        #Is this the end all work that needs to be done?
        if not work:
            trace('End of work queue')
            #Perpetuate the end marker for all threads to see
            self.in_q.put(False)
            #Notify the parent that we have died of natural causes
            self.out_q.put(False)
        return work

    def run(self):
        #This process needs one resolver before it can start looking.
        self.resolver.add_ns(self.get_ns_blocking())
        work = True
        while work:
            response = None
            work = self.get_work()
            #if the code above found work
            if work:
                #Keep track of what we are working on
                self.current_work = work
                self.start_time = datetime.datetime.now()
                #keep track of how many times this lookup has timedout.
                (hostname, query_type, timeout_retries) = work
                response = self.check(hostname, query_type, timeout_retries)
                sys.stdout.flush()
                #This variable doesn't need a muetex, because it has a queue. 
                #A queue ensure nameserver cannot be used before it's wildcard entries are found.
                reject = False
                found = []
                if response:
                    trace(response)
                    for record in response:
                        return_name, record_type, data = record
                        data = str(data)
                        if len(data) and len(record_type) and not len(return_name):
                            #The server we are dealing with is a monster.
                            return_name = hostname
                        if data in self.resolver.wildcards:
                            trace("resovled wildcard:", hostname)
                            reject= True
                            #reject this domain.
                            break
                        else:
                            found.append(record)
                    if not reject:
                        for f in found:
                            #This request is filled, send the results back
                            self.out_q.put(f)

#The multiprocessing queue will fill up, so a new process is required.
class loader(multiprocessing.Process):
    def __init__(self, in_q, subdomains, query_type, permute_len = 0):
        multiprocessing.Process.__init__(self, target = self.run)
        signal_init()
        self.in_q = in_q
        self.subdomains = subdomains
        self.query_type = query_type
        self.permute_len = permute_len

    #Python blocks on in_q for large datasets, even though the queue size is 'unlimited' :(
    def run(self):
        self.permute()
        #Remove items from the list that will be in the permutation set.
        permute_filter = re.compile("^[a-zA-Z0-9]{" + str(self.permute_len) + "}\.")
        #A list of subdomains is the input
        for s in self.subdomains:
            if not permute_filter.match(s):
                #Domains cannot contain whitespace,  and are case-insensitive.
                self.in_q.put((s, self.query_type, 0))
        #Terminate the queue
        self.in_q.put(False)

    #bruteforce a range.
    def permute(self):
        full_range = string.ascii_lowercase + string.digits + "_-"
        for l in range(1, self.permute_len + 1):
            for i in itertools.permutations(full_range, l):
                if i :
                    self.in_q.put((i, self.query_type, 0))

#Extract relevant hosts
#The dot at the end of a domain signifies the root,
#and all TLDs are subs of the root.
host_match = re.compile(r"((?<=[^a-zA-Z0-9_-])[a-zA-Z0-9_-]+\.(?:[a-zA-Z0-9_-]+\.?)+(?=[^a-zA-Z0-9_-]))")
def extract_hosts(data, hostname = ""):
    #made a global to avoid re-compilation
    global host_match
    ret = []
    hosts = re.findall(host_match, " " + data)
    for fh in hosts:
        host = fh.rstrip(".")
        #Is this host in scope?
        if host.endswith(hostname) and host != hostname:
            ret.append(host)
    return ret

#Return a unique list of subdomains to a given host
def extract_directory(dir_name, hostname = ""):
    ret = []
    dupe = {}
    for root, subdirs, files in os.walk(dir_name):
        for filename in files:
            full_path = os.path.join(root, filename)
            raw = open(full_path).read()
            for h in extract_hosts(raw, hostname):
                if h not in dupe:
                    dupe[h] = None
                    ret.append(h)
    return ret

def print_target(target, query_type = "ANY", subdomains = "names.txt", resolve_list = "resolvers.txt", process_count = 16, print_data = False, output = False, json_output = False):
    json_struct = {}
    if not print_data:
        dupe_filter = {}
    for result in run(target, query_type, subdomains, resolve_list, process_count):
        (hostname, record_type, record) = result
        if not print_data:
            #We just care about new names, filter multiple records for the same name.
            if hostname not in dupe_filter:
                dupe_filter[hostname] = None
                result = hostname
            else:
                result = False
        else:
            if type(record) is type([]):
                record = ",".join(record)
            result = "%s,%s,%s" % (hostname, record_type, record)
        if result:
            print(result)
            sys.stdout.flush()
            if hostname in json_struct:
                if record_type in json_struct:
                    json_struct[hostname][record_type].append(record)
                else:
                    json_struct[hostname][record_type] = []
                    json_struct[hostname][record_type].append(record)
            else:
                json_struct[hostname] = {}
                json_struct[hostname][record_type] = []
                json_struct[hostname][record_type].append(record)
            if output:
                output.write(result + "\n")
                output.flush()
    #The below formats the JSON to be semantically correct, after the scan has been completed
    if json_output:
        json_output = open(options.json, "w")
        json_output.write(json.dumps(json_struct))

def run(target, query_type = "ANY", subdomains = "names.txt", resolve_list = False, process_count = 8):
    spider_blacklist = {}
    result_blacklist = {}
    found_domains = {}
    #A thread fills the in_q, reduce memory usage, wait until we have space
    in_q = multiprocessing.Queue()
    in_q_priority = multiprocessing.Queue()
    out_q = multiprocessing.Queue()
    #Have a buffer of at most two new nameservers that lookup processes can draw from.
    resolve_q = multiprocessing.Queue(maxsize = 2)

    if os.path.isdir(subdomains):
        subdomains = extract_directory(subdomains, target)
    else:
        subdomains = check_open(subdomains)

    is_authoritative = False
    if resolve_list:
        resolve_list = check_open(resolve_list)
        if (len(resolve_list) / 16) < process_count:
            sys.stderr.write('Warning: Fewer than 16 resolvers per process, consider adding more nameservers to resolvers.txt.\n')
    else:
        #By default, use the authoritative nameservers for the target
        resolve = resolver()
        resolve_list = resolve.get_authoritative(target)
        is_authoritative = True
        if not resolve_list:
            sys.stderr.write("Unable to find authoritative resolvers for:" + target)
            return

    #If we are resolving against the authoratative NS, check AXFR,  we might get lucky :)
    if is_authoritative:
        ar = resolver(resolve_list)
        #Check every authoritative NS for AXFR support
        #These are distinct servers, one could be misconfigured
        for i in range(len(resolve_list)):
            res = []
            try:
                res = ar.query(target, 'AXFR')
            except:
                pass
            if res:
                trace("AXFR Successful for:", ar.get_last_resolver())
                for r in res:
                    result_blacklist[str(r)] = None
                    yield r
            #Even if the AXFR was a success, keep looking. Don't trust anyone.
    #Make a source of fast nameservers available for other processes.
    verify_nameservers_proc = verify_nameservers(target, query_type, resolve_q, resolve_list, is_authoritative)
    verify_nameservers_proc.start()
    #test the empty string
    in_q.put((target, query_type, 0))
    spider_blacklist[target + query_type] = None
    clean_subs = []
    for s in subdomains:
        s = str(s).strip().lower()
        find_csv = s.find(",")
        if find_csv > 1:
            #SubBrute should be forgiving, a comma will never be in a hostname
            #but the user might try an use a CSV file as input.
            s = s[0:find_csv]
        s = s.rstrip(".")
        if s:
            #A subbrute.py -o output.csv maybe our input.
            if not s.endswith(target):
                hostname = "%s.%s" % (s, target)
            else:
                #A user might feed an output list as a subdomain list.
                hostname = s
            spider_lookup = hostname + query_type
            if spider_lookup not in spider_blacklist:
                spider_blacklist[spider_lookup] = None
                clean_subs.append(hostname)

    #Free up some memory before the big show.
    del subdomains

    #load in the subdomains, can be quite large
    load = loader(in_q, clean_subs, query_type)
    load.start()

    #We may not have the resolvers needed to backup our thread count.
    list_len = len(resolve_list)
    if list_len < process_count:
        # // is floor division.  always return a full number.
        # We need a minimum of 2 resolvers per thread to hold by the 1 query per 5 sec limit.
        process_count = list_len // 2
        if process_count <= 0:
            process_count = 1
        trace("Too few resolvers:", list_len, " process_count reduced to:", process_count)
    worker_list = []
    for i in range(process_count):
        worker = lookup(in_q, in_q_priority, out_q, resolve_q, target)
        worker.start()
        worker_list.append(worker)
    threads_remaining = process_count
    while True:
        try:
            #The output is valid hostnames
            result = out_q.get(True, 10)
            #we will get an empty exception before this runs. 
            if not result:
                threads_remaining -= 1
            else:
                s_result = str(result)
                if s_result not in result_blacklist:
                    result_blacklist[s_result] = None
                    record_name, record_type, record_data = result
                    #Does this DNS record contain a useful subdomain?
                    #If the query_type is CNAME, then lookup() takes care of the CNAME record chain.
                    if query_type != "CNAME" and record_type not in ["AAAA", "A"]:
                        #did a record contain a new host?
                        hosts = extract_hosts(str(record_data), target)
                        for h in hosts:
                            spider_lookup = h + query_type
                            if spider_lookup not in spider_blacklist:
                                spider_blacklist[spider_lookup] = None
                                #spider newly found hostname
                                in_q_priority.put((h, query_type, 0))
                    if type(record_name) is tuple:
                        pass
                    #If we are using open resolvers we need to attempt every record type.
                    if query_type == "ANY" and record_name.endswith(target):
                        #Simulate an ANY query by requesting ALL types
                        for qt in dnslib.QTYPE.reverse:
                            #These query types are usually disabled and are not typically enabled on a per-sub basis.
                            if qt not in ["AXFR", "IXFR", "OPT", "TSIG", "TKEY"]:
                                spider_lookup = record_name + qt
                                if spider_lookup not in spider_blacklist:
                                    spider_blacklist[spider_lookup] = None
                                    #This will produce many NOERROR retries, reduce the retries.
                                    in_q_priority.put((record_name, qt, 2))
                    #if this is an error response, check if we have already found data for this domain.
                    if not record_data:
                        if not record_name in found_domains:
                            found_domains[record_name] = None
                            yield result
                    else:
                        found_domains[record_name] = None
                        yield result
                        #run() is a generator, and yields results from the work queue
        except Exception as e:
            #The cx_freeze version uses queue.Empty instead of Queue.Empty :(
            if type(e) == Queue.Empty or str(type(e)) == "<class 'queue.Empty'>":
                pass
            else:
                raise(e)
        #make sure everyone is complete
        if threads_remaining <= 0:
            break
    trace("About to kill nameserver process...")
    #We no longer require name servers.
    try:
        killproc(pid = verify_nameservers_proc.pid)
    except:
        #Windows threading.tread
        verify_nameservers_proc.end()
    trace("End")

#exit handler for signals.  So ctrl+c will work. 
#The 'multiprocessing' library each process is it's own process which side-steps the GIL
#If the user wants to exit prematurely,  each process must be killed.
def killproc(signum = 0, frame = 0, pid = False):
    if not pid:
        pid = os.getpid()
    if sys.platform.startswith('win'):
        try:
            kernel32 = ctypes.windll.kernel32
            handle = kernel32.OpenProcess(1, 0, pid)
            kernel32.TerminateProcess(handle, 0)
        except:
            #Oah windows, the above code *may* throw an exception and still succeed :/
            pass
    else:
        os.kill(pid, 9)

#Toggle debug output
verbose = False
def trace(*args, **kwargs):
    if verbose:
        for a in args:
            sys.stderr.write(str(a))
            sys.stderr.write(" ")
        sys.stderr.write("\n")

#dispaly error message, and then quit
def error(*args, **kwargs):
    for a in args:
        sys.stderr.write(str(a))
        sys.stderr.write(" ")
    sys.stderr.write("\n")
    sys.exit(1)

def check_open(input_file):
    ret = []
    #If we can't find a resolver from an input file, then we need to improvise.
    try:
        lines = open(input_file).readlines()
        #Check if this is CSV,  if it is, then use the first column.
        for l in lines:
            find_csv = l.find(",")
            if find_csv:
                ret.append(l[0:find_csv])
            else:
                ret.append(l)
    except:
        error("File not found:", input_file)
    if not len(ret):
        error("File is empty:", input_file)
    return ret

#Every 'multiprocessing' process needs a signal handler.
#All processes need to die, we don't want to leave zombies.
def signal_init():
    #killproc() escalates the signal to prevent zombies.
    signal.signal(signal.SIGINT, killproc)
    try:
        #These hanlders don't exist on every platform.
        signal.signal(signal.SIGTSTP, killproc)
        signal.signal(signal.SIGQUIT, killproc)
    except:
        #Windows
        pass

if __name__ == "__main__":
    if getattr(sys, 'frozen', False):
        # cx_freeze windows:
        base_path = os.path.dirname(sys.executable)
        multiprocessing.freeze_support()
    else:
        #everything else:
        base_path = os.path.dirname(os.path.realpath(__file__))
    parser = optparse.OptionParser("\n%prog [options] target_domain\n%prog -p target_domain")
    parser.add_option("-s", "--subs", dest = "subs", default = os.path.join(base_path, "names.txt"),
              type = "string", help = "(optional) A list of subdomains, accepts a single file, or a directory of files. default = 'names.txt'")
    parser.add_option("-r", "--resolvers", dest = "resolvers", default = "resolvers.txt",
              type = "string", help = "(optional) A list of DNS resolvers, if this list is empty it will OS's internal resolver default = 'resolvers.txt'")
    parser.add_option("-t", "--targets_file", dest = "targets", default = "",
              type = "string", help = "(optional) A file containing a newline delimited list of domains to brute force.")
    parser.add_option("-p", "-P", action = 'store_true', dest = "print_data", default = False,
              help = "(optional) Print data from found DNS records (default = off).")
    parser.add_option("-o", "--output", dest = "output",  default = False, help = "(optional) Output to file (Greppable Format)")
    parser.add_option("-j", "--json", dest="json", default = False, help="(optional) Output to file (JSON Format)")
    parser.add_option("--type", dest = "type", default = False,
              type = "string", help = "(optional) Print all reponses for an arbitrary DNS record type (CNAME, AAAA, TXT, SOA, MX...)")                  
    parser.add_option("-c", "--process_count", dest = "process_count",
              default = 8, type = "int",
              help = "(optional) Number of lookup theads to run. default = 8")
    parser.add_option("-v", "--verbose", action = 'store_true', dest = "verbose", default = False,
              help = "(optional) Print debug information.")
    (options, args) = parser.parse_args()

    verbose = options.verbose

    if len(args) < 1 and options.targets == "":
        parser.error("You must provide a target. Use -h for help.")

    if options.targets != "":
        targets = check_open(options.targets)
    else:
        targets = args #multiple arguments on the cli:  ./subbrute.py google.com gmail.com yahoo.com    if (len(resolver_list) / 16) < options.process_count:

    output = False
    if options.output:
        try:
            output = open(options.output, "w")
        except:
            error("Failed writing to file:", options.output)

    json_output = False
    if options.json:
        try:
            json_output = open(options.json, "w")
        except:
            error("Failed writing to file:", options.json)

    #subbrute with find the best record to use if the type is None.
    record_type = "ANY"
    if options.type:
        record_type = str(options.type).upper()

    threads = []
    for target in targets:
        target = target.strip()
        if target:
            trace("dnslib:",dnslib.version)
            trace(target, record_type, options.subs, options.resolvers, options.process_count, options.print_data, output, json_output)
            print_target(target, record_type, options.subs, options.resolvers, options.process_count, options.print_data, output, json_output)