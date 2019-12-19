FROM debian:10 AS build

RUN apt-get update && apt-get upgrade
RUN apt-get install -y build-essential git cmake libssl-dev libyaml-cpp-dev python3-pip
RUN pip3 install robotframework

RUN git clone https://github.com/keithmendozasr/tlslookieloo.git

WORKDIR tlslookieloo
RUN git submodule update --init --recursive

WORKDIR build
RUN cmake .. && cmake --build . && ctest
