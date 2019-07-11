# tlslookieloo
Utility to view stream message between server and client

![Coverity Scan Status](https://img.shields.io/coverity/scan/18672.svg)

# Longer idea
tlslookieloo is a utility to help troubleshoot network-related issues between a server and client. A client will connect to tlslookieloo, who in turn, will connect to the target server. tlslookieloo will then store/display the unencrypted message between the two.
 
# Dependencies
These are all minimum version

* C++ 17 compatible compiler
* cmake 3.7.2
* OpenSSL 1.1.0j
* yaml-cpp 0.6

# Submodules
The following are included as submodules of this project:
* googletest at master
* log4cplus at REL\_2\_0\_4

Make sure to process the git submodule with --recurse accordingly.
