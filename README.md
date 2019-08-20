# tlslookieloo
Utility to view stream message between server and client

![Coverity Scan](https://img.shields.io/coverity/scan/18672)
![Travis-CI](https://img.shields.io/travis/com/keithmendozasr/tlslookieloo)

# Longer idea
tlslookieloo is a utility to help troubleshoot network-related issues between a server and client. A client will connect to tlslookieloo, who in turn, will connect to the target server. tlslookieloo will then store/display the unencrypted message between the two.

# Dependencies
These are all minimum version

* C++ 17 compatible compiler
* cmake 3.13
* OpenSSL 1.1.1
* yaml-cpp 0.6

# Submodules
The following are included as submodules of this project:
* googletest
* log4cplus

Make sure to process the git submodule with --recurse accordingly.

# Compilation

This project uses cmake. Here's a way to compile it in Debian 10:
1. Make sure the following packages are installed:
	a. libss-dev
	b. cmake
2. mkdir build
3. cd build
4. cmake ..
5. cmake --build .
6. ctest (make sure all passes)

# How to run
1. cd to build directory from the previous section.
2. Generate a self-signed TLS certificate `openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes -out app1.crt -keyout app1.key`
3. Start tlslookieloo ```./src/tlslookieloo -t../samples/targets.yaml```  
4. Make the necessary system changes to resolve "www.example.com" to the IP of the machine you're running tlslookieloo on.
5. In a browser go to https://www.example.com:9988.
6. You should see a certificate warning if you're browser is connected to your tlslookieloo instance. Allow accordingly.
7. The "Example" page should load
8. Messages between your browser and www.example.com's server are recorded in app1.msgs
