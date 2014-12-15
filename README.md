Whats new in v1.1?
=====================
This version merges pull requests from the community; changes from JordanMilne, KxCode and rc0r is in this release.  From the community this project revived bug fixes, and improvements to accuracy.  As requsted, this project is now GPLv3.

Better wildcard detection:
 - Support for Geolocation aware DNS
 - Filter misbehaving nameservers

Faster:
 - More name servers, more than 2,000 high quality nameservers were added to resolvers.txt
 - Each lookup thread builds its own pool of resolver,  a separate thread is responsible for feeding these pools with high quality resolver.

New output:
-a will list all addresses associated with a subdomain
-v debug output,  to help developers/hackers track down bugs in subbrute.

subdomain-bruteforcer v1.1
=====================

This is a (fast) multi-threaded python tool for enumerating subdomains.  This tool also contains a large list of real subdomains that you will find in the wild.  Basically I was fed up with fierce / fierce2, and every other tool I used so I wrote something way faster in python.   This tool will "just work",  and work well.   By default this tool performs subdomain enumeration about 8 times faster than Fierce, and can chew through 31k lookups in about 5 minutes on a home cable connection.

Why is this tool so fast?

Other multi-threaded subdomain enumeration tools that I have seen are bottlenecked by using a single resolver.   In SubBrute, each thread is given its own slice of the resolvers list (resolvers.txt) so that a single resolver isn't overwhelmed.  The subdomain list (subs.txt) is sorted by frequency, so this tool will return the most common domains quickly.  

Using some creative google hacks I put together a disorganized list of well over a million domain names,  I then used a regex to rip out the subdomains and then sorted them by frequency. You can also use this data-mangling feature by using using this simple command:
python subroute.py -f full.html > my_subs.txt

I used this feature to create subs.txt which contains 31291 subdomains.  subs_small.txt was stolen from fierce2 which contains 1896 subdomains.   If you find more subdomains to add,  open a bug report and I'll be happy to add them!

Easy to install:
You just need http://www.dnspython.org/ and python2.7 or python3.  This tool should work under any operating system:  bsd, osx, windows, linux...

(On a side note giving a makefile root always bothers me,  it would be a great way to install a backdoor...)

Under Ubuntu/Debian all you need is:

sudo apt-get install python-dnspython

On other operating systems you may have to install dnspython manually:

http://www.dnspython.org/ 

Easy to use:

./subbrute.py google.com

Tests multiple domains:
./subbrute.py google.com gmail.com blogger.com

or a newline delimited list of domains:
./subbrute.py -t list.txt

Also keep in mind that subdomains can have subdomains (example: _xmpp-server._tcp.gmail.com):

./subbrute.py gmail.com > gmail.out

./subbrute.py -t gmail.out

Cheers!