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
import socket
import struct

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

#A resolver wraper around dnslib
class Resolver:
    #Google's DNS servers are only used if zero resolvers are specified by the user.
    pos = 0
    rcode = ""
    wildcards = {}
    failed_code = False

    def __init__(self, nameservers = ['8.8.8.8','8.8.4.4']):
        self.nameservers = nameservers

    def query(self, hostname, query_type = 'ANY', name_server = False, use_tcp = None):
        ret = []
        response = None
        if use_tcp is None:
            #Assuming meta-queries are the only queries that require TCP
            if query_type in ['ANY', 'AXFR']:
                use_tcp = True
            else:
                use_tcp = False
        if name_server == False:
            name_server = self.get_ns()
        query = dnslib.DNSRecord.question(hostname, query_type.upper().strip())
        try:
            response_q = query.send(name_server, 53, use_tcp)
            if response_q:
                response = dnslib.DNSRecord.parse(response_q)
            else:
                raise IOError("Empty Response")
        except Exception as e:
            #Detect perm error vs temp error
            #struct.error is some malformed response.
            #if type(e) in [socket.timeout, socket.error, dnslib.DNSError, struct.error, UnicodeError]:
            #IOErrors are all conditions that require a retry.
            raise IOError(str(e))
        if response:
            self.rcode = dnslib.RCODE[response.header.rcode]
            if self.rcode not in ['NOERROR', 'NXDOMAIN','REFUSED','SERVFAIL']:
                trace('!!Odd error code:', self.rcode, hostname, query_type)
            #perm errors ? ['FORMERR', 'NOTIMP', 'NXDOMAIN', 'NOTAUTH']
            if self.rcode in ['SERVFAIL','REFUSED']:
                raise IOError('Temporary DNS Failure: ', hostname," - " ,self.rcode)
            for r in response.rr:
                try:
                    rtype = str(dnslib.QTYPE[r.rtype])
                except:#Server sent an unknown type:
                    rtype = r.rtype
                ret.append((rtype, str(r.rdata)))
            if not len(ret) and self.rcode not in ["NXDOMAIN", "NOERROR"]:
                raise IOError("DNS Error - " + self.rcode + " - for:" + hostname)
        return ret

    def was_successful(self):
        return self.rcode == 'NOERROR'

    def record_exists(self):
        ret = False
        if self.failed_code is None and self.rcode != "NXDOMAIN":
            ret = True
        elif self.rcode != self.failed_code:
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
                nameservers = self.query(hostname, 'NS')
            except IOError:#lookup failed.
                nameservers = []
            for n in nameservers:
                ret.append(n[1])
                #If a nameserver wasn't found try the parent of this sub.
            hostname = hostname[hostname.find(".") + 1:]
        return ret

class verify_nameservers(multiprocessing.Process):

    def __init__(self, target, query_type, resolver_q, resolver_list, authoratative = False):
        multiprocessing.Process.__init__(self, target = self.run)
        self.daemon = True
        signal_init()
        self.authoratative = authoratative

        self.time_to_die = False
        self.resolver_q = resolver_q
        self.query_type = query_type
        self.resolver_list = resolver_list
        self.resolver = Resolver()
        #The domain provided by the user.
        self.target = target
        #Resolvers that will work in a pinch:
        self.backup_resolver = ['8.8.8.8', '8.8.4.4', '127.0.0.1']

    def end(self):
        self.time_to_die = True

    #This process cannot block forever,  it  needs to check if its time to die.
    def add_nameserver(self, nameserver):
        keep_trying = True
        while not self.time_to_die and keep_trying:
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
            if self.time_to_die:
                #We are done here.
                break
            server = server.strip()
            if server:
                try:
                    #Only add the nameserver to the queue if we can detect wildcards.
                    verified_server = self.find_wildcards(self.target, server)
                    if verified_server:# and self.find_wildcards(".com")
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
        #We want sovle the following three problems:
        #1)The target might have a wildcard DNS record.
        #2)The target maybe using geolocaiton-aware DNS.
        #I have seen a CloudFlare Enterprise customer with these two conditions.
        try:
            #This is case #3,  these spam nameservers seem to be more trouble then they are worth.
            blanktest = self.resolver.query(self.target, self.query_type)
            if self.query_type == "ANY":
                #If the type was ANY we should have gotten some records
                if not len(blanktest) and not self.authoratative:
                    return False
            elif not self.resolver.was_successful():
                trace("Cannot perform ", self.query_type, " request:", host)
                return False
        except Exception as e:
            if not self.authoratative:
                return False
        test_counter = 8
        looking_for_wildcards = True
        while looking_for_wildcards and test_counter >= 0:
            looking_for_wildcards = False
            #Don't get lost, this nameserver could be playing tricks.
            test_counter -= 1            
            try:
                testdomain = "%s.%s" % (uuid.uuid4().hex, host)
                wildtest = self.resolver.query(testdomain, self.query_type, server)
                resolver_fail_code = self.resolver.get_returncode()
                #This 'A' record may contain a list of wildcards.
                if len(wildtest):
                    for w in wildtest:
                        record_type, data = w
                        if record_type in ["CNAME", "A", "AAAA", "MX"]:
                            data = str(data)
                            if data not in wildcards:
                                #wildcards were detected.
                                wildcards[data] = None
                                #found atleast one wildcard, look for more.
                                looking_for_wildcards = True
            except Exception as e:
                #This resolver maybe flakey, we don't want it for our tests.
                if not self.authoratative:
                    trace("wildcard exception:", server, type(e))
                    return False
                else:
                    #The authoratative server isn't going to give us wildcards
                    looking_for_wildcards = False
        #If we hit the end of our depth counter and,
        #there are still wildcards, then reject this nameserver because it smells bad.
        if test_counter >= 0:
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
        self.resolver = Resolver([])

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
                    if self.resolver.record_exists() and not resp:
                        resp = [(self.resolver.get_returncode(), "")]
                    return resp
                if record_type == "CNAME":
                    added_cname = False
                    #A max 20 lookups
                    for x in range(20):
                        resp = self.resolver.query(host, record_type, total_rechecks)
                        for r in resp:
                            record_type, record = r
                            if record_type == "CNAME":
                                host = str(record).rstrip(".")
                                cname_record.append(host)
                                added_cname = True
                                break
                        if not added_cname:
                            break
                    if cname_record:
                        ret = [(record_type, cname_record)]
                    else:
                        ret = False
                        #No response?  then return what we have.
                    return ret
                else:
                    #All other records:
                    return self.resolver.query(host, record_type)
            except (IOError, TypeError) as e:
                if total_rechecks >= 3:
                    #Multiple threads have tried and given up
                    trace('Lookup failure due to 3 exception limit.')
                    return [(self.resolver.get_returncode(), "")]
                elif retries >= 3:
                    #This thread has tried and given up
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
                #keep track of how many times this lookup has timedout.
                (hostname, record_type, timeout_retries) = work
                response = self.check(hostname, record_type, timeout_retries)
                sys.stdout.flush()
                #This variable doesn't need a muetex, because it has a queue. 
                #A queue ensure nameserver cannot be used before it's wildcard entries are found.
                reject = False
                found = []
                if response:
                    trace(response)
                    for a in response:
                        record_type, data = a
                        data = str(data)
                        if data in self.resolver.wildcards:
                            trace("resovled wildcard:", hostname)
                            reject= True
                            #reject this domain.
                            break;
                        else:
                            found.append(a)
                    if not reject:
                        for f in found:
                            record_type, data = f
                            #This request is filled, send the results back
                            result = (hostname, record_type, data)
                            self.out_q.put(result)

#The multiprocessing queue will fill up, so a new process is required.
class loader(multiprocessing.Process):
    def __init__(self, in_q, subdomains, query_type):
        multiprocessing.Process.__init__(self, target = self.run)
        signal_init()
        self.in_q = in_q
        self.subdomains = subdomains
        self.query_type = query_type

    #Blocks on in_q for large datasets
    def run(self):
        #A list of subdomains is the input
        for s in self.subdomains:
            #Domains cannot contain whitespace,  and are case-insensitive.
            self.in_q.put((s, self.query_type, 0))
        #Terminate the queue
        self.in_q.put(False)

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
            if query_type == 'ANY':
                #Print everything we have found.
                result = "%s,%s,%s" % (hostname, record_type, record)
            elif query_type == record_type and record:
                #CNAME produces array records.
                if type(record) is type([]):
                    record = ",".join(record)
                result = "%s,%s,%s" % (hostname, record_type, record)
            else:
                result = False
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

def run(target, query_type = "ANY", subdomains = "names.txt", resolve_list = False, process_count = 16):
    if os.path.isdir(subdomains):
        subdomains = extract_directory(subdomains, target)
    else:
        subdomains = check_open(subdomains)

    is_authoratative = False
    if resolve_list:
        resolve_list = check_open(resolve_list)
        if (len(resolve_list) / 16) < process_count:
            sys.stderr.write('Warning: Fewer than 16 resovlers per process, consider adding more nameservers to resolvers.txt.\n')
    else:
        #By default, use the authoratative name servers for the target
        resolve = Resolver()
        resolve_list = resolve.get_authoritative(target)
        is_authoratative = True

    spider_blacklist = {}
    in_q = multiprocessing.Queue()
    in_q_priority = multiprocessing.Queue()
    out_q = multiprocessing.Queue()
    #have a buffer of at most two new nameservers that lookup processes can draw from.
    resolve_q = multiprocessing.Queue(maxsize = 2)

    #Make a source of fast nameservers avaiable for other processes.
    verify_nameservers_proc = verify_nameservers(target, query_type, resolve_q, resolve_list, is_authoratative)
    verify_nameservers_proc.start()
    #test the empty string
    in_q.put((target, query_type, 0))
    spider_blacklist[target] = None
    clean_subs = []
    for s in subdomains:
        s = str(s).strip().lower()
        find_csv = s.find(",")
        if find_csv > 1:
            #SubBrute should be forgiving, a comma will never be in a url
            #but the user might try an use a CSV file as input.
            s = s[0:find_csv]
        s = s.rstrip(".")
        if s:
            if not s.endswith(target):
                hostname = "%s.%s" % (s, target)
            else:
                #A user might feed an output list as a subdomain list.
                hostname = s
            if hostname not in spider_blacklist:
                spider_blacklist[hostname] = None
                clean_subs.append(hostname)

    #Free some memory before the big show.
    del subdomains

    #load in the subdomains,  can be quite large
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
    for i in range(process_count):
        worker = lookup(in_q, in_q_priority, out_q, resolve_q, target)
        worker.start()
    threads_remaining = process_count
    while True:
        try:
            #The output is valid hostnames
            result = out_q.get(True, 10)
            #we will get an empty exception before this runs. 
            if not result:
                threads_remaining -= 1
            else:
                #did a record contain a new host?
                if query_type != "CNAME":
                    hosts = extract_hosts(str(result[2]), target)
                    for h in hosts:
                        if h not in spider_blacklist:
                            spider_blacklist[h] = None
                            #spider newly found hostname
                            in_q_priority.put((h, query_type, 0))
                #run() is a generator, and yields results from the work queue
                yield result
                #if recursive_bruteforce:
                #    hostname = result[0].strip(".")
                    #Look for subdomains of the newly-found host.
                #    for cs in clean_subdomains:
                #        recursive_target = cs + hostname
                #        if recursive_target not in spider_blacklist:
                #            spider_blacklist[recursive_target] = None
                #            in_q.put((recursive_target, query_type, 0))
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
              type = "string", help = "(optional) A list of subdomains, accepts a file, or a directory of files. default = 'names.txt'")
    parser.add_option("-r", "--resolvers", dest = "resolvers", default = False,
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
              default = 16, type = "int",
              help = "(optional) Number of lookup theads to run. default = 16")
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

    record_type = "ANY"
    if options.type:
        record_type = str(options.type).upper()

    threads = []
    for target in targets:
        target = target.strip()
        if target:
            print_target(target, record_type, options.subs, options.resolvers, options.process_count, options.print_data, output, json_output)