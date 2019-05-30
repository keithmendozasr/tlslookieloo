#tlslookieloo
Utility to view stream message between server and client

#Longer idea
tlslookieloo is a utility to help troubleshoot network-related issues between a server and client. A client will connect to tlslookieloo, who in turn, will connect to the target server. tlslookieloo will then store/display the unencrypted message between the two.
 
#Dependencies
These are all minimum version

* C++ 14 compatible compiler
* cmake 3.7.2
* OpenSSL 1.1.0j

#Submodules
The following are included as submodules of this project:
* googletest
* log4cplus

Make sure to process the git submodule with --recurse accordingly.
