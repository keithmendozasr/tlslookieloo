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
#include <csignal>
#include <algorithm>

#include <log4cplus/loggingmacros.h>

#include "socketinfo.h"

using namespace std;
using namespace log4cplus;

namespace tlslookieloo
{
// NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init)
SocketInfo::SocketInfo(shared_ptr<Wrapper> wrapper) :
    wrapper(wrapper),
    sslCtx(nullptr, &SSL_CTX_free)
{}

SocketInfo::SocketInfo(const SocketInfo &rhs) :
    socketIP(rhs.socketIP),
    sockfd(rhs.sockfd),
    servInfo(rhs.servInfo),
    sockAddr(rhs.sockAddr),
    nextServ(rhs.nextServ),
    timeout(rhs.timeout),
    sslCtx(nullptr, &SSL_CTX_free),
    sslObj(rhs.sslObj)
{
    wrapper = rhs.wrapper;
}

SocketInfo::SocketInfo(SocketInfo &&rhs) :
    wrapper(std::move(rhs.wrapper)),
    socketIP(std::move(rhs.socketIP)),
    sockfd(std::move(rhs.sockfd)),
    servInfo(std::move(rhs.servInfo)),
    sockAddr(std::move(rhs.sockAddr)),
    nextServ(std::move(rhs.nextServ)),
    timeout(std::move(rhs.timeout)),
    sslCtx(nullptr, &SSL_CTX_free),
    sslObj(std::move(rhs.sslObj))
{}

SocketInfo &SocketInfo::operator =(const SocketInfo &rhs)
{
    wrapper = rhs.wrapper;
    socketIP = rhs.socketIP;
    sockfd = rhs.sockfd;
    servInfo = rhs.servInfo;
    sockAddr = rhs.sockAddr;
    nextServ = rhs.nextServ;
    timeout = rhs.timeout;
    sslObj = rhs.sslObj;
    
    return *this;
}

SocketInfo &SocketInfo::operator =(SocketInfo &&rhs)
{
    wrapper = std::move(rhs.wrapper);
    socketIP = std::move(rhs.socketIP);
    sockfd = std::move(rhs.sockfd);
    servInfo = std::move(rhs.servInfo);
    sockAddr = std::move(rhs.sockAddr);
    nextServ = std::move(rhs.nextServ);
    timeout = std::move(rhs.timeout);
    sslObj = std::move(rhs.sslObj);

    return *this;
}

const bool SocketInfo::resolveHostPort(const unsigned int &port, const string &host)
{
    if(sockfd && servInfo)
            throw logic_error("Instance already initialized");

    if(port > 65535)
        throw invalid_argument("port parameter > 65535");

    bool retVal = true;
    int rv;
    struct addrinfo hints; // NOLINT

    memset(&hints, 0, sizeof hints); // NOLINT
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    LOG4CPLUS_TRACE(logger, "Getting address info"); // NOLINT
    struct addrinfo *tmp;
    rv = getaddrinfo(
        (host.size() ? host.c_str() : nullptr),
        to_string(port).c_str(),
        &hints, &tmp);
    if (rv != 0)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_DEBUG(logger, "Failed to resolve host. " << gai_strerror(rv));
        retVal = false;
    }
    else
    {
        LOG4CPLUS_DEBUG(logger, "Hostname and port info resolved"); // NOLINT
        servInfo = shared_ptr<struct addrinfo>(tmp, &freeaddrinfo);
        LOG4CPLUS_TRACE(logger, "servInfo set: " << // NOLINT
            (servInfo ? "yes" : "no"));
        sockAddr = nextServ = servInfo.get();
    }

    return retVal;
}

void SocketInfo::initNextSocket()
{
    LOG4CPLUS_TRACE(logger, // NOLINT
        "Value of servInfo at start: " << servInfo.get() <<
        " nextServ: " << nextServ
    );


    if(!servInfo)
        throw logic_error("Host info not resolved yet");
    else if(nextServ == nullptr)
        throw range_error("No more resolved IP's to try");
    else
        LOG4CPLUS_TRACE(logger, "Initialize socket"); // NOLINT

    sockAddr = nextServ;
    saveSocketIP(
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        reinterpret_cast<const struct sockaddr_storage *>(sockAddr->ai_addr)
    );
    LOG4CPLUS_TRACE(logger, "Attempt to get socket"); // NOLINT
    sockfd = shared_ptr<int>(new int(socket(sockAddr->ai_family,
        sockAddr->ai_socktype | SOCK_NONBLOCK, sockAddr->ai_protocol)),
        SockfdDeleter()
    );
    if (*sockfd == -1)
    {
        int err = errno;
        char buf[256];
        char *errmsg = strerror_r(err, &buf[0], 256);
        LOG4CPLUS_TRACE(logger, "Value of err: " << err << " String: " << // NOLINT
            errmsg);
        throw runtime_error(string("Failed to get socket fd: ") + errmsg);
    }
    else
    {
        LOG4CPLUS_DEBUG(logger, "Socket ready"); // NOLINT
        nextServ = sockAddr->ai_next;
    }
    LOG4CPLUS_TRACE(logger, "Value of nextServ: "<<nextServ); // NOLINT
}

void SocketInfo::saveSocketIP(const sockaddr_storage *addrInfo)
{
    //unique_ptr<char[]>buf;
    int af;
    int bufSize;
    void *addrPtr = nullptr;

    if(addrInfo->ss_family == AF_INET)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_TRACE(logger, __PRETTY_FUNCTION__ << " ai_family is AF_INET");
        bufSize = INET_ADDRSTRLEN;
        const struct sockaddr_in *t =
            reinterpret_cast<const struct sockaddr_in *>(addrInfo); // NOLINT
        addrPtr = const_cast<void *>( // NOLINT
            reinterpret_cast<const void *>(&(t->sin_addr))); // NOLINT
        af = t->sin_family;
    }
    else if(addrInfo->ss_family == AF_INET6)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_TRACE(logger, __PRETTY_FUNCTION__ << " ai_family is AF_INET6");
        bufSize = INET6_ADDRSTRLEN;
        const struct sockaddr_in6 *t =
            reinterpret_cast<const struct sockaddr_in6 *>(addrInfo); // NOLINT
        addrPtr = const_cast<void *>( // NOLINT
            reinterpret_cast<const void *>(&(t->sin6_addr))); // NOLINT
        af = t->sin6_family;
    }
    else
        throw invalid_argument("Unexpected sa_family value");

    auto buf = make_unique<char[]>(bufSize);
    LOG4CPLUS_TRACE(logger, "Value of af: " << af); // NOLINT
    LOG4CPLUS_TRACE(logger, "Value of bufSize: " << bufSize); // NOLINT
    if(inet_ntop(af, addrPtr, buf.get(), bufSize)
        == nullptr)
    {
        auto err = errno;
        throwSystemError(err, "Failed to translate IP address");
    }

    socketIP = make_optional(string(buf.get(), bufSize));
    LOG4CPLUS_TRACE(logger, __PRETTY_FUNCTION__<<" Value of ip: "<< socketIP.value()); // NOLINT
}

const bool SocketInfo::waitForReading(const bool &withTimeout)
{
    if(!sockfd)
        throw logic_error("no socket");

    fd_set readFd;
    FD_ZERO(&readFd);
    FD_SET(*sockfd, &readFd); // NOLINT

    timeval waitTime; // NOLINT
    timeval *timevalPtr = nullptr;

    bool retVal = false;

    if(withTimeout)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_TRACE(logger, "Setting timeout to " << timeout << " seconds");
        waitTime.tv_sec=timeout;
        waitTime.tv_usec=0;
        timevalPtr = &waitTime;
    }

    do
    {
        LOG4CPLUS_TRACE(logger, "Wait on " << *sockfd); // NOLINT
        auto rslt = wrapper->select((*sockfd)+1, &readFd, nullptr, nullptr,
            timevalPtr);
        LOG4CPLUS_TRACE(logger, "Value of rslt: " << rslt); // NOLINT
        if(rslt == -1)
        {
            auto err = errno;
            LOG4CPLUS_TRACE(logger, "Error code: " << err << ": " // NOLINT
                << strerror(err));
            if(err != 0 && err != EINTR)
            {
                throwSystemError(err,
                    "Error waiting for socket to be ready for reading.");
            }
            else
            {
                LOG4CPLUS_TRACE(logger, "Caught signal"); // NOLINT
                break;
            }
        }
        else if(rslt == 0)
        {
            LOG4CPLUS_DEBUG(logger, "Read wait time expired"); // NOLINT
            break;
        }
        else if(FD_ISSET(*sockfd, &readFd)) // NOLINT
        {
            LOG4CPLUS_DEBUG(logger, "Socket ready for reading"); // NOLINT
            retVal = true;
            break;
        }
    } while(true);

    return retVal;
}

optional<const size_t> SocketInfo::readData(char *data, const size_t &dataSize)
{

    bool shouldRetry = false;
    auto ptr = getSSLPtr();
    ERR_clear_error();
    optional<size_t> retVal;
    do
    {
        auto rslt = wrapper->SSL_read(ptr, data, dataSize);
        LOG4CPLUS_TRACE(logger, "SSL_read return: " << rslt); // NOLINT
        if(rslt <= 0)
        {
            LOG4CPLUS_TRACE(logger, "SSL_read reporting error"); // NOLINT
            if(wrapper->SSL_get_error(ptr, rslt) == SSL_ERROR_SYSCALL && errno == 0)
            {
                LOG4CPLUS_DEBUG(logger, "Remote-end disconnected while reading"); // NOLINT
                shouldRetry = false;
            }
            else
            {
                LOG4CPLUS_DEBUG(logger, "Wait for read ready"); // NOLINT
                shouldRetry = handleRetry(rslt);
            }
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, to_string(rslt) << // NOLINT
                " received over the wire");
            shouldRetry = false;
            retVal = rslt;
        }

    } while(shouldRetry);

    return retVal;
}

const bool SocketInfo::waitForWriting(const bool &withTimeout)
{
    if(!sockfd)
        throw logic_error("no socket");

    fd_set writeFd;
    FD_ZERO(&writeFd);
    FD_SET(*sockfd, &writeFd); // NOLINT

    timeval waitTime; // NOLINT
    timeval *timevalPtr = nullptr;
    
    bool retVal = false;

    if(withTimeout)
    {
        LOG4CPLUS_TRACE(logger, "Setting timeout to " << timeout << // NOLINT
            " seconds");
        waitTime.tv_sec = timeout;
        waitTime.tv_usec = 0;
        timevalPtr = &waitTime;
    }

    do
    {
        auto rslt = wrapper->select((*sockfd)+1, nullptr, &writeFd, nullptr,
            timevalPtr);
        if(rslt == -1)
        {
            auto err = errno;
            LOG4CPLUS_TRACE(logger, "Error code: " << err << ": " // NOLINT
                << strerror(err));
            if(err != 0 && err != EINTR)
            {
                throwSystemError(err,
                    "Error waiting for socket to be ready for writing.");
            }
            else
            {
                LOG4CPLUS_TRACE(logger, "Caught signal"); // NOLINT
                break;
            }
        }
        else if(rslt == 0)
        {
            LOG4CPLUS_DEBUG(logger, "Write wait time expired"); // NOLINT
            break;
        }
        else if(FD_ISSET(*sockfd, &writeFd)) // NOLINT
        {
            LOG4CPLUS_DEBUG(logger, "Socket ready for writing"); // NOLINT
            retVal = true;
            break;
        }
    } while(true);

    return retVal;
}

const size_t SocketInfo::writeData(const char *msg, const size_t &msgSize)
{
    ERR_clear_error();

    bool shouldRetry = false;
    auto ptr = getSSLPtr();
    size_t retVal = 0;
    do
    {
        auto rslt = wrapper->SSL_write(ptr, msg, msgSize);
        LOG4CPLUS_TRACE(logger, "SSL_write return: " << rslt); // NOLINT
        if(rslt <= 0)
        {
            LOG4CPLUS_TRACE(logger, "SSL_write reporting error"); // NOLINT
            shouldRetry = handleRetry(rslt);
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, to_string(msgSize) << // NOLINT
                " sent over the wire");
            shouldRetry = false;
            retVal = rslt;
        }

    } while(shouldRetry);

    return retVal;
}

void SocketInfo::newSSLCtx()
{
    // Allow old SSL protocol; because we don't control what protocol the
    //  system under test supports
    sslCtx = unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), &SSL_CTX_free);
    if(!sslCtx)
    {
        const string msg = sslErrMsg("Failed to create SSL context. Cause: ");
        LOG4CPLUS_ERROR(logger, msg); // NOLINT
        throw bad_alloc();
    }
    else
        LOG4CPLUS_TRACE(logger, "Context object created"); // NOLINT

    if(SSL_CTX_set_min_proto_version(sslCtx.get(), SSL3_VERSION) != 1)
    {
        const string msg = sslErrMsg("Failed to set minimum SSL version. Cause: ");
        LOG4CPLUS_ERROR(logger, msg); // NOLINT
        logSSLErrorStack();
        throw logic_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Minimum version set to SSL v3"); // NOLINT
}

void SocketInfo::newSSLObj()
{
    sslObj = shared_ptr<SSL>(SSL_new(getSSLCtxPtr()), SSLDeleter());
    if(!sslObj)
    {
        const string msg = sslErrMsg("Failed to create SSL instance. Cause: ");
        LOG4CPLUS_ERROR(logger, msg); // NOLINT
        throw bad_alloc();
    }
    else
        LOG4CPLUS_TRACE(logger, "SSL object created"); // NOLINT
}

void SocketInfo::logSSLErrorStack()
{
    LOG4CPLUS_ERROR(logger, "SSL error encountered. Error stack"); // NOLINT
    unsigned long errCode;
    do
    {
        errCode = ERR_get_error();
        if(errCode != 0)
        {
            const char *msg = ERR_reason_error_string(errCode);
            LOG4CPLUS_ERROR(logger, "\t" << // NOLINT
                (msg != nullptr ? msg : "Code " + to_string(errCode)));
        }
    } while(errCode != 0);
}

const bool SocketInfo::handleRetry(const int &rslt)
{
    bool retVal = true;

    auto ptr = getSSLPtr();
    auto code = wrapper->SSL_get_error(ptr, rslt);

    LOG4CPLUS_TRACE(logger, "Code: " << code); // NOLINT

    switch(code)
    {
    case SSL_ERROR_WANT_READ:
        LOG4CPLUS_TRACE(logger, "Wait for read ready"); // NOLINT
        if(!waitForReading())
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger, "Network timeout waiting to read data");
            retVal = false;
        }
        else
            LOG4CPLUS_TRACE(logger, "Socket ready for reading"); // NOLINT
        break;
    case SSL_ERROR_WANT_WRITE:
        LOG4CPLUS_TRACE(logger, "Wait for write ready"); // NOLINT
        if(!waitForWriting())
        {
            LOG4CPLUS_INFO(logger, "Network timeout waiting to write data"); // NOLINT
            retVal = false;
        }
        else
            LOG4CPLUS_TRACE(logger, "Socket ready for writing"); // NOLINT
        break;
    case SSL_ERROR_ZERO_RETURN:
        LOG4CPLUS_TRACE(logger, "Remote closed SSL session"); // NOLINT
        retVal = false;
        break;
    default:
        logSSLErrorStack();
        throw logic_error(string("SSL error"));
    }

    return retVal;
}

} //namespace tlslookieloo
