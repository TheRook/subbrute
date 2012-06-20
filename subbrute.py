#!/usr/bin/python
import Queue
import re
import time
import optparse
import os
import signal
import sys
import dns.resolver
from threading import Thread

#exit handler for signals.  So ctrl+c will work,  even with py threads. 
def exit(signum=0, frame=0):
    os.kill(os.getpid(),9)

class lookup(Thread):
    
    def __init__(self,input, output, domain, resolver_list=[]):
        Thread.__init__(self)
	self.q=input
        self.output=output
        self.domain=domain
	self.resolver_list=resolver_list
        self.resolver=dns.resolver.Resolver()
        if len(resolver_list):
            self.resolver.nameservers=self.resolver_list

    def check(self, host):
	slept=0
        while True:
            try:
                answer = self.resolver.query(host)
                if answer:
                    return str(answer[0])
                else:
                    return False
            except Exception as e:
                if type(e) == dns.resolver.NXDOMAIN:
                    #not found
                    return False
                elif type(e) == dns.resolver.NoAnswer  or type(e) == dns.resolver.Timeout:
		    if slept == 4:
			#maybe this dns server stopped responding.
			#fall back on the system's dns name server
			self.resolver.nameservers=[]
		    elif slept>5:
		        return False
                    #Hmm,  we might have hit a rate limit on a resolver.
                    time.sleep(1)
		    slept+=1
                    #retry...
		elif type(e) == dns.resolver.NoNameservers:
		    #maybe the nameserver went down.
		    #so lets fall back on the  system's name server
		    #If we have already tried to fall back like this,  then except.
		    if self.resolver.nameservers == []:
			raise e
		    self.resolver.nameservers=[]
		elif type(e) == IndexError:
			#Some old versions of dnspython throw this error,
			#doesn't seem to affect the results,  and it was fixed in later versions.
			pass
                else:
                    #dnspython threw some strange exception...
                    raise e

    def run(self):
	while True:
            sub=self.q.get()
            if not sub:
                #perpetuate the terminator for all threads to see
                self.q.put(False)
                self.output.put(False)
                break
            test="%s.%s" % (sub, self.domain)     
            addr=self.check(test)
	    if addr:
                self.output.put((test,addr))

#Return a list of unique sub domains,  sorted by frequency.
def extract_subdomains(file_name):
    subs={}
    file=open(file_name).read()
    #Only match domains that have 3 or more sections subdomain.domain.tld
    domain_match=re.compile("([a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*)+")
    f_all=re.findall(domain_match,file)
    del file
    for i in f_all:
        if i.find(".") >=0:
            p=i.split(".")[0:-1]
            #gobble everything that might be a TLD
            while p and len(p[-1]) <= 3:
                p=p[0:-1]
            #remove the domain name
            p=p[0:-1]
            #do we have a subdomain.domain left?
            if len(p)>=1:
                #print(str(p)+" : "+i)
                for q in p:
                    if q :
                        if q in subs:
                            subs[q]+=1
                        else:
                            subs[q]=1
    #Free some memory before the sort...
    del f_all
    #Sort by freq in desc order
    subs_sorted=sorted(subs.keys(), key=lambda x: subs[x], reverse=True)
    return subs_sorted

def check_resolvers(file_name):
    ret=[]
    resolver=dns.resolver.Resolver()
    file=open(file_name).read()
    for server in file.split("\n"):
        resolver.nameservers=[server]
        try:
            resolver.query("www.google.com")
            ret.append(server)
            #should throw an exception before this line.
        except:
            pass
    return ret

def run_target(target,hosts,resolve_list,thread_count):
    #Hmm they might have a *.target dns record
    star_record=False
    try:
        resp=dns.resolver.Resolver().query("would-never-be-a-fucking-domain-name-ever-fuck."+target)
        star_record=str(resp[0])
    except:
        pass	
    input=Queue.Queue()
    output=Queue.Queue()
    for h in hosts:
        input.put(h)    
    #Terminate the queue
    input.put(False)	
    step_size=int(len(resolve_list)/thread_count)
    #Split up the resolver list between the threads. 
    if step_size <=0:
	step_size=1
    step=0
    for i in range(thread_count):
        threads.append(lookup(input,output,target,resolve_list[step:step+step_size]))
        threads[-1].start()
	step+=step_size
	if step >= len(resolve_list):
	    step=0

    threads_remaining=options.thread_count    
    while True:
        d=output.get()
        if not d:
            threads_remaining-=1
        else:
            if not star_record or (star_record and d[1] != star_record):
                print d[0]
        #make sure everyone is complete
        if threads_remaining <= 0:
            break

if __name__ == "__main__":
    parser = optparse.OptionParser("usage: %prog [options] targetx`")
    parser.add_option("-c", "--thread_count", dest="thread_count",
              default=10, type="int",
              help="(optional) Number of lookup theads to run,  more isn't always better. default=10")
    parser.add_option("-s", "--subs", dest="subs", default="subs.txt",
              type="string", help="(optional) list of subdomains,  default='subs.txt'")
    parser.add_option("-r", "--resolvers", dest="resolvers", default="resolvers.txt",
              type="string", help="(optional) A list of DNS resolvers, if this list is empty it will OS's internal resolver default='resolvers.txt'")              
    parser.add_option("-f", "--filter_subs", dest="filter", default="",
              type="string", help="(optional) A file containing unorganized domain names which will be filtered into a list of subdomains sorted by frequency.  This was used to build subs.txt.")
    parser.add_option("-t", "--target_file", dest="targets", default="",
              type="string", help="(optional) A file containing a newline delimited list of domains to brute force.")
  
    (options, args) = parser.parse_args()

    if len(args) < 1 and options.filter=="" and options.targets=="":
        parser.error("You must provie a target! Use -h for help.")

    if options.filter != "":
        #cleanup this file and print it out
        for d in extract_subdomains(options.filter):
            print d
        sys.exit()

    if options.targets != "":
	targets=open(options.targets).read().split("\n")
    else:
	targets=args #multiple arguments on the cli:  ./subbrute.py google.com gmail.com yahoo.com

    hosts=open(options.subs).read().split("\n")

    resolve_list=check_resolvers(options.resolvers)
    threads=[]
    signal.signal(signal.SIGINT, exit)
    
    for target in targets:
	target=target.strip()
	if target:
	    run_target(target,hosts,resolve_list,options.thread_count)
