#!/usr/bin/env python
#
#SubBrute v1.2
#A (very) fast subdomain enumeration tool.
#
#Maintained by rook
#Contributors:
#JordanMilne, KxCode, rc0r, memoryprint, ppaulojr  
#
import re
import optparse
import os
import signal
import sys
import uuid
import random
import ctypes
import dns.resolver
import dns.rdatatype

#Python 2.x and 3.x compatiablity
#We need the Queue library for exception handling
try:
    import queue as Queue
except:
    import Queue

#The 'multiprocessing' library does not rely upon a Global Interpreter Lock (GIL)
import multiprocessing

#Microsoft compatiablity
if  sys.platform.startswith('win'):
    #Drop-in replacement,  subbrute + multiprocessing throws exceptions on windows.
    import threading
    multiprocessing.Process = threading.Thread

class verify_nameservers(multiprocessing.Process):

    def __init__(self, resolver_q, resolver_list, target, wildcards, record_type):
        multiprocessing.Process.__init__(self, target = self.run)
        self.daemon = True
        signal_init()

        self.time_to_die = False
        self.resolver_q = resolver_q
        self.wildcards = wildcards
        self.record_type = "A"
        if record_type == "AAAA":
            self.record_type = record_type
        self.resolver_list = resolver_list
        resolver = dns.resolver.Resolver()
        #The domain provided by the user.
        self.target = target
        #1 website in the world,  modify the following line when this status changes.
        #www.google.cn,  I'm looking at you ;)
        self.most_popular_website = "www.google.com"
        #We shouldn't need the backup_resolver, but we we can use them if need be.
        #We must have a resolver,  and localhost can work in some environments.
        self.backup_resolver = resolver.nameservers + ['127.0.0.1', '8.8.8.8', '8.8.4.4']
        #Ideally a nameserver should respond in less than 1 sec.
        resolver.timeout = 1
        resolver.lifetime = 1
        try:
            #Lets test the letancy of our connection.
            #Google's DNS server should be an ideal time test.
            resolver.nameservers = ['8.8.8.8']
            resolver.query(self.most_popular_website, self.record_type)
        except:
            #Our connection is slower than a junebug in molasses
            resolver = dns.resolver.Resolver()
        self.resolver = resolver

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

    def verify_nameservers(self, nameserver_list):
        added_resolver = False
        for server in nameserver_list:
            if self.time_to_die:
                #We are done here.
                break
            server = server.strip()
            if server:
                self.resolver.nameservers = [server]
                try:
                    #test_result = self.resolver.query(self.most_popular_website, "A")
                    #should throw an exception before this line.
                    if True:#test_result:
                        #Only add the nameserver to the queue if we can detect wildcards. 
                        if(self.find_wildcards(self.target)):# and self.find_wildcards(".com")
                            #wildcards have been added to the set, it is now safe to be added to the queue.
                            #blocking queue,  this process will halt on put() when the queue is full:
                            self.add_nameserver(server)
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
        if not self.verify_nameservers(self.resolver_list):
            #This should never happen,  inform the user.
            sys.stderr.write('Warning: No nameservers found, trying fallback list.\n')
            #Try and fix it for the user:
            self.verify_nameservers(self.backup_resolver)
        #End of the resolvers list.
        try:
            self.resolver_q.put(False, timeout = 1)
        except:
            pass

    #Only add the nameserver to the queue if we can detect wildcards. 
    #Returns False on error.
    def find_wildcards(self, host):
        #We want sovle the following three problems:
        #1)The target might have a wildcard DNS record.
        #2)The target maybe using Geolocaiton-aware DNS.
        #3)The DNS server we are testing may respond to non-exsistant 'A' records with advertizements.
        #I have seen a CloudFlare Enterprise customer with the first two conditions.
        try:
            #This is case #3,  these spam nameservers seem to be more trouble then they are worth.
             wildtest = self.resolver.query(uuid.uuid4().hex + ".com", "A")
             if len(wildtest):
                trace("Spam DNS detected:", host)
                return False
        except:
            pass
        test_counter = 8
        looking_for_wildcards = True
        while looking_for_wildcards and test_counter >= 0 :
            looking_for_wildcards = False
            #Don't get lost, this nameserver could be playing tricks.
            test_counter -= 1            
            try:
                testdomain = "%s.%s" % (uuid.uuid4().hex, host)
                wildtest = self.resolver.query(testdomain, self.record_type)
                #This 'A' record may contain a list of wildcards.
                if wildtest:
                    for w in wildtest:
                        w = str(w)
                        if w not in self.wildcards:
                            #wildcards were detected.
                            self.wildcards[w] = None
                            #We found atleast one wildcard, look for more.
                            looking_for_wildcards = True
            except Exception as e:
                if type(e) == dns.resolver.NXDOMAIN or type(e) == dns.name.EmptyLabel:
                    #not found
                    return True
                else:
                    #This resolver maybe flakey, we don't want it for our tests.
                    trace("wildcard exception:", self.resolver.nameservers, type(e)) 
                    return False 
        #If we hit the end of our depth counter and,
        #there are still wildcards, then reject this nameserver because it smells bad.
        return (test_counter >= 0)

class lookup(multiprocessing.Process):

    def __init__(self, in_q, out_q, resolver_q, domain, wildcards):
        multiprocessing.Process.__init__(self, target = self.run)
        signal_init()
        self.required_nameservers = 16
        self.in_q = in_q
        self.out_q = out_q
        self.resolver_q = resolver_q        
        self.domain = domain
        self.wildcards = wildcards
        self.resolver = dns.resolver.Resolver()
        #Force pydns to use our nameservers
        self.resolver.nameservers = []

    def get_ns(self):
        ret = []
        try:
            ret = [self.resolver_q.get_nowait()]
            if ret == False:
                #Queue is empty,  inform the rest.
                self.resolver_q.put(False)
                ret = []
        except:
            pass      
        return ret  

    def get_ns_blocking(self):
        ret = []
        ret = [self.resolver_q.get()]
        if ret == False:
            trace("get_ns_blocking - Resolver list is empty.")
            #Queue is empty,  inform the rest.
            self.resolver_q.put(False)
            ret = []
        return ret

    def check(self, host, record_type = "A", timeout_retries = 0):
        trace("Checking:", host)
        cname_record = []
        retries = 0        
        if len(self.resolver.nameservers) <= self.required_nameservers:
            #This process needs more nameservers,  lets see if we have one avaible
            self.resolver.nameservers += self.get_ns()
        #Ok we should be good to go.
        while True:
            try:
                #Query the nameserver, this is not simple...
                if not record_type:
                    return self.resolver.query(host)
                if record_type != "CNAME":
                    return self.resolver.query(host, record_type)
                else:
                    #A max 20 lookups
                    for x in range(20):
                        try:
                            resp = self.resolver.query(host, record_type)
                        except dns.resolver.NoAnswer:
                            resp = False
                            pass
                        if resp and resp[0]:
                            host = str(resp[0]).rstrip(".")
                            cname_record.append(host)
                        else:
                            return cname_record
            except Exception as e:
                if type(e) == dns.resolver.NoNameservers:
                    #We should never be here.
                    #We must block,  another process should try this host.
                    self.in_q.put((host, record_type, 0))
                    self.resolver.nameservers += self.get_ns_blocking()
                    return False
                elif type(e) == dns.resolver.NXDOMAIN:
                    #"Non-existent domain name."
                    return False
                elif type(e) == dns.resolver.NoAnswer:
                    #"The response did not contain an answer."
                    if retries >= 1:
                        trace("NoAnswer retry")
                        return False
                    retries += 1
                elif type(e) == dns.resolver.Timeout:
                    trace("lookup failure:", host, retries)
                    #Check if it is time to give up.
                    if retries >= 3:
                        if timeout_retries > 3:
                            #Sometimes 'internal use' subdomains will timeout for every request.
                            #As far as I'm concerned, the authorative name server has told us this domain exists,
                            #we just can't know the address value using this method.
                            return ['Mutiple Query Timeout - External address resolution was restricted ']
                        else:
                            #Maybe another process can take a crack at it.
                            self.in_q.put((host, record_type, timeout_retries + 1))
                        return False
                    retries += 1
                    #retry...
                elif type(e) == IndexError:
                    #Some old versions of dnspython throw this error,
                    #doesn't seem to affect the results,  and it was fixed in later versions.
                    pass
                elif type(e) == TypeError:
                    # We'll get here if the number procs > number of resolvers.
                    self.in_q.put((host, record_type, 0))
                    return False
                elif type(e) == dns.rdatatype.UnknownRdatatype:
                    error("DNS record type not supported:", record_type)
                else:
                    trace("Problem processing host:", host)
                    #dnspython threw some strange exception...
                    raise e

    def run(self):
        #This process needs one resolver before it can start looking.
        self.resolver.nameservers += self.get_ns_blocking()
        while True:
            found_addresses = []
            work = self.in_q.get()
            #Check if we have hit the end marker
            while not work:
                #Look for a re-queued lookup
                try:
                    work = self.in_q.get(blocking = False)
                    #if we took the end marker of the queue we need to put it back
                    if work:
                        self.in_q.put(False)
                except:#Queue.Empty
                    trace('End of work queue')
                    #There isn't an item behind the end marker
                    work = False
                    break
            #Is this the end all work that needs to be done?
            if not work:
                #Perpetuate the end marker for all threads to see
                self.in_q.put(False)
                #Notify the parent that we have died of natural causes
                self.out_q.put(False)
                break
            else:
                if len(work) == 3:
                    #keep track of how many times this lookup has timedout.
                    (hostname, record_type, timeout_retries) = work
                    response = self.check(hostname, record_type, timeout_retries)
                else:
                    (hostname, record_type) = work
                    response = self.check(hostname, record_type) 
                sys.stdout.flush()
                trace(response)                  
                #self.wildcards is populated by the verify_nameservers() thread.
                #This variable doesn't need a muetex, because it has a queue. 
                #A queue ensure nameserver cannot be used before it's wildcard entries are found.
                reject = False
                if response:
                    for a in response:
                        a = str(a)
                        if a in self.wildcards:
                            trace("resovled wildcard:", hostname)
                            reject= True
                            #reject this domain.
                            break;
                        else:
                            found_addresses.append(a)
                    if not reject:
                        #This request is filled, send the results back  
                        result = (hostname, record_type, found_addresses)
                        self.out_q.put(result)

#Return a list of unique sub domains,  sorted by frequency.
def extract_subdomains(file_name):
    subs = {}
    sub_file = open(file_name).read()
    #Only match domains that have 3 or more sections subdomain.domain.tld
    domain_match = re.compile("([a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)+")
    f_all = re.findall(domain_match, sub_file)
    del sub_file
    for i in f_all:
        if i.find(".") >= 0:
            p = i.split(".")[0:-1]
            #gobble everything that might be a TLD
            while p and len(p[-1]) <= 3:
                p = p[0:-1]
            #remove the domain name
            p = p[0:-1]
            #do we have a subdomain.domain left?
            if len(p) >= 1:
                trace(str(p), " : ", i)
                for q in p:
                    if q :
                        #domain names can only be lower case.
                        q = q.lower()
                        if q in subs:
                            subs[q] += 1
                        else:
                            subs[q] = 1
    #Free some memory before the sort...
    del f_all
    #Sort by freq in desc order
    subs_sorted = sorted(subs.keys(), key = lambda x: subs[x], reverse = True)
    return subs_sorted

def run_target(target, subdomains, resolve_list, process_count, record_type, output = False):
    wildcards = multiprocessing.Manager().dict()
    in_q = multiprocessing.Queue()
    out_q = multiprocessing.Queue()
    #have a buffer of at most two new nameservers that lookup processes can draw from.
    resolve_q = multiprocessing.Queue(maxsize = 2)

    #Make a source of fast nameservers avaiable for other processes.
    verify_nameservers_proc = verify_nameservers(resolve_q, resolve_list, target, wildcards, record_type)
    verify_nameservers_proc.start()
    #A list of subdomains is the input
    for s in subdomains:
        s = str(s).strip()
        if s:
            hostname = "%s.%s" % (s, target)
            work = (hostname, record_type)
            in_q.put(work)
    #Terminate the queue
    in_q.put(False)
    for i in range(process_count):
        worker = lookup(in_q, out_q, resolve_q, target, wildcards)
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
                (hostname, record_type, response) = result
                if not record_type:
                    result = hostname
                else:
                    result = "%s,%s" % (hostname, ",".join(response).strip(","))
                print(result)
                sys.stdout.flush()
                if output:
                    output.write(result + "\n")
                    output.flush()
        except Exception as e:
            #The cx_freeze version uses queue.Empty instead of Queue.Empty :(
            if type(e) == Queue.Empty or str(type(e)) == "<class 'queue.Empty'>":
                pass
            else:
                raise(e)
        #make sure everyone is complete
        if threads_remaining <= 0:
            break
    trace("killing nameserver process")
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
            #Oah windows.
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
        ret = open(input_file).readlines()
    except:
        error("File not found:", input_file)
    if not len(ret):
        error("File is empty:", input_file)
    return ret

#Every 'multiprocessing' process needs a signal handler.
#All processes need to die, we don't want to leave zombies.
def signal_init():
    #Escliate signal to prevent zombies.
    signal.signal(signal.SIGINT, killproc)
    try:
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
    parser = optparse.OptionParser("usage: %prog [options] target")
    parser.add_option("-c", "--process_count", dest = "process_count",
              default = 32, type = "int",
              help = "(optional) Number of lookup theads to run. default = 32")
    parser.add_option("-s", "--subs", dest = "subs", default = os.path.join(base_path, "names.txt"),
              type = "string", help = "(optional) list of subdomains,  default = 'names.txt'")
    parser.add_option("-r", "--resolvers", dest = "resolvers", default = os.path.join(base_path, "resolvers.txt"),
              type = "string", help = "(optional) A list of DNS resolvers, if this list is empty it will OS's internal resolver default = 'resolvers.txt'")
    parser.add_option("-f", "--filter_subs", dest = "filter", default = "",
              type = "string", help = "(optional) A file containing unorganized domain names which will be filtered into a list of subdomains sorted by frequency.  This was used to build names.txt.")
    parser.add_option("-t", "--targets_file", dest = "targets", default = "",
              type = "string", help = "(optional) A file containing a newline delimited list of domains to brute force.")
    parser.add_option("-o", "--output", dest = "output",  default = False,
              help = "(optional) Output to file")    
    parser.add_option("-a", "-A", action = 'store_true', dest = "ipv4", default = False,
              help = "(optional) Print all IPv4 addresses for sub domains (default = off).")
    parser.add_option("--aaaa", "--AAAA", action = 'store_true', dest = "ipv6", default = False,
              help = "(optional) Print all IPv6 addresses for sub domains (default = off).")      
    parser.add_option("--cname", "--CNAME", action = 'store_true', dest = "cname", default = False,
              help = "(optional) Print all cname lookups for sub domains (default = off).")
    parser.add_option("--type", dest = "type", default = False,
              type = "string", help = "(optional) Print all reponses for an arbitrary DNS record type (TXT, SOA, MX...)")                  
    parser.add_option("-v", "--verbose", action = 'store_true', dest = "verbose", default = False,
              help = "(optional) Print debug information.")
    (options, args) = parser.parse_args()

    verbose = options.verbose

    if len(args) < 1 and options.filter == "" and options.targets == "":
        parser.error("You must provie a target. Use -h for help.")

    if options.filter != "":
        #cleanup this file and print it out
        for d in extract_subdomains(options.filter):
            print(d)
        sys.exit()

    if options.targets != "":
        targets = check_open(options.targets)
    else:
        targets = args #multiple arguments on the cli:  ./subbrute.py google.com gmail.com yahoo.com

    subdomains = check_open(options.subs)
    resolver_list = check_open(options.resolvers)
    
    if (len(resolver_list) / 16) < options.process_count:
        sys.stderr.write('Warning: Fewer than 16 resovlers per thread, consider adding more nameservers to resolvers.txt.\n')

    output = False
    if options.output:
        try:
             output = open(options.output, "w")
        except:
            error("Faild writing to file:", options.output)

    record_type = False
    if options.ipv4:
        record_type="A"
    elif options.ipv6:
        record_type="AAAA"
    elif options.cname:
        record_type="CNAME"
    if options.type:
        record_type = str(options.type).upper()

    threads = []
    for target in targets:
        target = target.strip()
        if target:
            run_target(target, subdomains, resolver_list, options.process_count, record_type, output)