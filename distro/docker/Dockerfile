FROM debian:10 AS build

RUN apt-get update
RUN apt-get upgrade
RUN apt-get install -y build-essential git cmake libssl-dev libyaml-cpp-dev python3-pip
RUN pip3 install robotframework

RUN git clone https://github.com/keithmendozasr/tlslookieloo.git

WORKDIR /tlslookieloo
RUN git submodule update --init --recursive

WORKDIR /tlslookieloo/log4cplus
RUN ./scripts/fix-timestamps.sh

WORKDIR /tlslookieloo/build
RUN cmake .. && cmake --build . && ctest

FROM debian:10 AS runtime

RUN apt-get update && \
    apt-get install -y libssl1.1 libyaml-cpp0.6 && \
    apt-get clean

WORKDIR /usr/bin
COPY --from=build /tlslookieloo/build/src/tlslookieloo .

ENTRYPOINT [ "tlslookieloo" ]