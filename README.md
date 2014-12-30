
subdomain-bruteforcer (SubBrute)
=====================
SubBrute is a community driven project with the goal of creating the fastest, and most accurate subdomain enumeration tool.  Some of the magic behind SubBrute is that it uses open revolvers as a kind of proxy to circumvent DNS rate-limiting (https://www.us-cert.gov/ncas/alerts/TA13-088A).  This design also provides a layer of anonymity, as SubBrute does not send traffic directly to the target's name servers.

Whats new in v1.1?
=====================
This version merges pull requests from the community; changes from JordanMilne, KxCode and rc0r is in this release.  In SubBrute 1.1 we fixed bugs, improved  accuracy, and efficiency.  As requested, this project is now GPLv3.

Accuracy and better wildcard detection:
 - A new filter that can pickup Geolocation aware wildcards.
 - Filter misbehaving nameservers

Faster:
 - More than 2,000 high quality nameservers were added to resolvers.txt,  these servers will resolve multiple queries in under 1 sec.
 - Nameservers are verified when they are needed.  A seperate thread is responsible creating a feed of nameservers, and corresponding wildcard blacklist set.

New output:
- -a will list all addresses associated with a subdomain.
- -v debug output,  to help developers/hackers debug subbrute.
- -o output results to file.

More Information
=====================

The 'names.txt' list  was created using some creative Google hacks with additions from the community.  SubBrute has a feature to build your own subordinate lists by matching sub-domains with regular expression and sorting by frequency of occurrence:

 - python subroute.py -f full.html > my_subs.txt

names.txt contains 31291 subdomains.  subs_small.txt was stolen from fierce2 which contains 1896 subdomains.   If you find more subdomains to add,  open a bug report or pull request and I'll be happy to add them!

No install required for Windows,  just cd into the 'windows' folder:

 - subbrute.exe google.com

Easy to install:
You just need http://www.dnspython.org/ and python2.7 or python3.  This tool should work under any operating system:  bsd, osx, windows, linux...

(On a side note giving a makefile root always bothers me,  it would be a great way to install a backdoor...)

Under Ubuntu/Debian all you need is:

 - sudo apt-get install python-dnspython

On other operating systems you may have to install dnspython manually:

http://www.dnspython.org/ 

Easy to use:

 - ./subbrute.py google.com

Tests multiple domains:
 - ./subbrute.py google.com gmail.com blogger.com

or a newline delimited list of domains:
 - ./subbrute.py -t list.txt

Also keep in mind that subdomains can have subdomains (example: _xmpp-server._tcp.gmail.com):

 - ./subbrute.py gmail.com > gmail.out

 - ./subbrute.py -t gmail.out

Cheers!