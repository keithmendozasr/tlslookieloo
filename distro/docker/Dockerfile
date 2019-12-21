FROM debian:10 AS build

RUN apt-get update
RUN apt-get install -y git cmake libssl-dev libyaml-cpp-dev python3-pip pkg-config
RUN pip3 install robotframework

RUN git clone https://github.com/keithmendozasr/tlslookieloo.git

WORKDIR /tlslookieloo
RUN git submodule update --init --recursive

WORKDIR /tlslookieloo/log4cplus
RUN ./scripts/fix-timestamps.sh

WORKDIR /tlslookieloo/build
RUN cmake .. && cmake --build . && ctest

FROM alpine:3.10 AS runtime

WORKDIR /customlibs
COPY --from=build \
    /lib64/ld-linux-x86-64.so.2 \
    /lib/x86_64-linux-gnu/libpthread.so.0 \
	/usr/lib/x86_64-linux-gnu/libyaml-cpp.so.0.6 \
    /usr/lib/x86_64-linux-gnu/libssl.so.1.1 \
    /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 \
    /usr/lib/x86_64-linux-gnu/libstdc++.so.6 \
    /lib/x86_64-linux-gnu/libm.so.6 \
    /lib/x86_64-linux-gnu/libgcc_s.so.1 \
    /lib/x86_64-linux-gnu/libc.so.6 \
    /lib/x86_64-linux-gnu/libdl.so.2 ./

WORKDIR /usr/bin
COPY --from=build /tlslookieloo/build/src/tlslookieloo ./
ENV LD_LIBRARY_PATH=/customlibs
ENTRYPOINT [ "/customlibs/ld-linux-x86-64.so.2", "/usr/bin/tlslookieloo" ]