/*
 * Copyright 2019-present tlslookieloo authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <cstring>
#include <memory>
#include <stdexcept>

#include <log4cplus/loggingmacros.h>

#include "socketinfo.h"

using namespace std;
using namespace log4cplus;

namespace tlslookieloo
{

SocketInfo::SocketInfo() :
    logger(Logger::getInstance("SocketInfo")),
    sockfd(-1),
    servInfo(nullptr, &freeaddrinfo)
{}

const bool SocketInfo::resolveHostPort(const unsigned int &port, const string &host)
{
    if(sockfd != -1)
    {
        if(servInfo)
            throw logic_error("Instance already initialized");
    }

    if(port > 65535)
        throw invalid_argument("port parameter > 65535");

    bool retVal = true;
    int rv;
    struct addrinfo hints;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    LOG4CPLUS_TRACE(logger, "Getting address info");
    struct addrinfo *tmp;
    rv = getaddrinfo(
        (host.size() ? host.c_str() : nullptr),
        to_string(port).c_str(),
        &hints, &tmp);
    if (rv != 0)
    {
        LOG4CPLUS_DEBUG(logger, "Failed to resolve host. " << gai_strerror(rv));
        retVal = false;
    }
    else
    {
        LOG4CPLUS_DEBUG(logger, "Hostname and port info resolved");
        servInfo = unique_ptr<struct addrinfo, decltype(&freeaddrinfo)>(
            tmp, &freeaddrinfo);
        LOG4CPLUS_TRACE(logger, "servInfo set: " <<
            (servInfo ? "yes" : "no"));
        nextServ = servInfo.get();
    }

    return retVal;
}

void SocketInfo::initNextSocket()
{
    LOG4CPLUS_TRACE(logger,
        "Value of servInfo at start: " << servInfo.get() <<
        " nextServ: " << nextServ
    );
    if(!servInfo)
        throw logic_error("Host info not resolved yet");
    else if(nextServ == nullptr)
        throw range_error("No more resolved IP's to try");
    else
        LOG4CPLUS_TRACE(logger, "Initialize socket");

    struct addrinfo *addrInfoItem = nextServ;
    static const bool logTrace = logger.isEnabledFor(TRACE_LOG_LEVEL);
    if(logTrace)
    {
        char hostname[NI_MAXHOST];
        int errnum = getnameinfo(addrInfoItem->ai_addr, addrInfoItem->ai_addrlen,
            &hostname[0], sizeof(hostname), nullptr, 0, NI_NUMERICHOST);
        if((errnum != 0))
            LOG4CPLUS_TRACE(logger, "getnameinfo errored out: " <<
                gai_strerror(errnum));
        else
            LOG4CPLUS_TRACE(logger, "IP to try: "<<hostname);
    }
    LOG4CPLUS_TRACE(logger, "Attempt to get socket");
    sockfd = socket(addrInfoItem->ai_family,
        addrInfoItem->ai_socktype | SOCK_NONBLOCK, addrInfoItem->ai_protocol);
    if (sockfd == -1)
    {
        int err = errno;
        char buf[256];
        char *errmsg = strerror_r(err, &buf[0], 256);
        LOG4CPLUS_TRACE(logger, "Value of err: " << err << " String: " <<
            errmsg);
        throw runtime_error(string("Failed to get socket fd: ") + errmsg);
    }
    else
    {
        LOG4CPLUS_DEBUG(logger, "Socket ready");
        setAddrInfo((const struct sockaddr_storage *)addrInfoItem->ai_addr,
            addrInfoItem->ai_addrlen);
        nextServ = addrInfoItem->ai_next;
    }
    LOG4CPLUS_TRACE(logger, "Value of nextServ: "<<nextServ);
}

const string SocketInfo::getSocketIP() const
{
    if(sockfd == -1)
        throw logic_error("Address info not initialized");

    string ip;
    unique_ptr<char[]>buf;
    int af;
    int bufSize;
    void *addrPtr = nullptr;

    if(addrInfo.ss_family == AF_INET)
    {
        LOG4CPLUS_TRACE(logger, __PRETTY_FUNCTION__ << " ai_family is AF_INET");
        bufSize = INET_ADDRSTRLEN;
        const struct sockaddr_in *t =
            reinterpret_cast<const struct sockaddr_in *>(&addrInfo); // NOLINT
        addrPtr = const_cast<void *>(
            reinterpret_cast<const void *>(&(t->sin_addr)));
        af = t->sin_family;
    }
    else if(addrInfo.ss_family == AF_INET6)
    {
        LOG4CPLUS_TRACE(logger, __PRETTY_FUNCTION__ << " ai_family is AF_INET6");
        bufSize = INET6_ADDRSTRLEN;
        const struct sockaddr_in6 *t =
            reinterpret_cast<const struct sockaddr_in6 *>(&addrInfo); // NOLINT
        addrPtr = const_cast<void *>(
            reinterpret_cast<const void *>(&(t->sin6_addr)));
        af = t->sin6_family;
    }
    else
        throw invalid_argument("Unexpected sa_family value");

    buf = make_unique<char[]>(bufSize);
    if(inet_ntop(af, addrPtr, buf.get(), bufSize)
        == nullptr)
    {
        auto err = errno;
        const int errbuflen = 256;
        char errbuf[errbuflen];
        char *errmsg = strerror_r(err, &errbuf[0], errbuflen);
        string msg("Failed to translate IP address: ");
        msg += errmsg;
        throw msg;
    }

    ip = string(buf.get(), bufSize);
    LOG4CPLUS_TRACE(logger, __PRETTY_FUNCTION__<<" Value of ip: "<<ip);
    return ip;
}

void SocketInfo::setAddrInfo(const sockaddr_storage *addr, const size_t &addrSize)
{
    memmove(&addrInfo, addr, addrSize);
    addrInfoSize = addrSize;
}

const bool SocketInfo::waitForReading(const unsigned int timeout)
{
    fd_set readFd;
    FD_ZERO(&readFd);
    FD_SET(sockfd, &readFd); // NOLINT

    timeval waitTime;
    timeval *timevalPtr = nullptr;

    bool retVal = true;

    if(timeout != 0)
    {
        waitTime.tv_sec=timeout;
        waitTime.tv_usec=0;
        timevalPtr = &waitTime;
    }

    do
    {
        auto retVal = select(sockfd+1, &readFd, nullptr, nullptr, timevalPtr);
        if(retVal == -1)
        {
            auto err = errno;
            throwSystemError(err,
                "Error waiting for socket to be ready for reading.");
        }
        else if(retVal == 0)
        {
            LOG4CPLUS_DEBUG(logger, "Read wait time expired");
            retVal = false;
        }
        else if(FD_ISSET(sockfd, &readFd)) // NOLINT
        {
            LOG4CPLUS_DEBUG(logger, "Socket ready for reading");
            break;
        }
    } while(true);

    return retVal;
}

const size_t SocketInfo::readData(char *data, const size_t &dataSize)
{
    if(data == nullptr)
        throw invalid_argument("\"data\" parameter is null");

    auto retVal = read(sockfd, data, dataSize);
    if(retVal < 0)
    {
        auto err = errno;
        throwSystemError(err, "Error reading from socket");
    }
    else if(retVal == 0)
        throwSystemError(EPIPE);
    else
        LOG4CPLUS_TRACE(logger, "read complete. Value of retVal: " <<retVal);

    return retVal;
}

const bool SocketInfo::waitForWriting(const unsigned int timeout)
{
    fd_set writeFd;
    FD_ZERO(&writeFd);
    FD_SET(sockfd, &writeFd);

    timeval waitTime;
    timeval *timevalPtr = nullptr;
    
    bool retVal = true;

    if(timeout != 0)
    {
        waitTime.tv_sec = timeout;
        waitTime.tv_usec = 0;
        timevalPtr = &waitTime;
    }

    do
    {
        auto retVal = select(sockfd+1, nullptr, &writeFd, nullptr, timevalPtr);
        if(retVal == -1)
        {
            auto err = errno;
            throwSystemError(err,
                "Error waiting for socket to be ready for writing.");
        }
        else if(retVal == 0)
        {
            LOG4CPLUS_DEBUG(logger, "Write wait time expired");
            retVal = false;
        }
        else if(FD_ISSET(sockfd, &writeFd))
        {
            LOG4CPLUS_DEBUG(logger, "Socket ready for writing");
            break;
        }
    } while(1);

    return retVal = true;
}

} //namespace tlslookieloo
