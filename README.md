subdomain-bruteforcer
=====================

This is a (fast) multi-threaded python tool for enumerating subdomains.  This tool also contains a large  list of real subdomains that you will find in the wild.  Basically I was fed up with fierce / fierce2, and every other tool I used so I wrote something way better in python.   This tool will "just work",  and work well. 

A notable improvement over every other subdomain bruteforcing tool out there is that this tool has an awesome subdomain list and I included an awesome and flexible mangling feature to build your own subdomain list.   

Using some creative google hacks I put together a disorganized list of well over a million domain names,  I then used a regex to rip out the subdomains and then sorted them by frequency. You can also use this data-mangling feature by using using this simple command:
python subroute.py -f full.html > my_subs.txt
Simple!

I used this feature to create subs.txt which contains 30040 subdomains.  subs_small.txt was stolen from fierce2 which contains 1896 subdomains. 

Having a list of resolvers (resolvers.txt)  is best for a multi-threaded application because most dns resolvers have rate-limiting by default.  This feature is for speed.

Easy to install (And one huge 'FUCK YOU!' to fierce2):
You just need http://www.dnspython.org/ and python2.7,  should work under any operating system:  bsd, osx, windows, linux...
Under Ubuntu/Debian all you need is:
sudo apt-get install python-dnspython
and thats it!

Easy to use:
./subbrute.py target.com

Cheers!

(P.S. If you are looking for any other fierce features just use dig or nmap)