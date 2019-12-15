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

#include <openssl/err.h>

#include "log4cplus/loggingmacros.h"

#include "socketinfo.h"

#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK   O_NONBLOCK
#endif

using namespace std;
using namespace log4cplus;

namespace tlslookieloo
{
// NOLINTNEXTLINE(cppcoreguidelines-pro-type-member-init)
SocketInfo::SocketInfo(shared_ptr<Wrapper> wrapper) :
    wrapper(wrapper)
{}

SocketInfo::SocketInfo(const SocketInfo &rhs) :
    socketIP(rhs.socketIP),
    sockfd(rhs.sockfd),
    servInfo(rhs.servInfo),
    sockAddr(rhs.sockAddr),
    nextServ(rhs.nextServ),
    timeout(rhs.timeout),
    sslCtx(rhs.sslCtx),
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
    sslCtx(std::move(rhs.sslCtx)),
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
    sslCtx = rhs.sslCtx;
    
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
    sslCtx = std::move(rhs.sslCtx);

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
    rv = wrapper->getaddrinfo(
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
        nextServ = servInfo.get();
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
    sockfd = shared_ptr<int>(new int(wrapper->socket(sockAddr->ai_family,
        sockAddr->ai_socktype | SOCK_NONBLOCK, sockAddr->ai_protocol)),
        SockfdDeleter()
    );
    if (*sockfd == -1)
    {
        throw system_error(errno, std::generic_category(),
            "Failed to get socket fd");
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

const SocketInfo::OP_STATUS SocketInfo::handleRetry(const int &rslt)
{
    fd_set monitorFd;
    FD_ZERO(&monitorFd);
    FD_SET(*sockfd, &monitorFd); // NOLINT
    fd_set *readFds, *writeFds;

    OP_STATUS retVal = OP_STATUS::INITIALIZED;
    readFds = writeFds = nullptr;

    auto code = wrapper->SSL_get_error(getSSLPtr(), rslt);
    LOG4CPLUS_TRACE(logger, "Code: " << code); // NOLINT
    switch(code)
    {
    case SSL_ERROR_NONE:
        throw logic_error("Cannot retry operation on SSL_ERROR_NONE");
        break;
    case SSL_ERROR_WANT_READ:
        LOG4CPLUS_DEBUG(logger, "Wait for socket to be readable"); // NOLINT
        readFds = &monitorFd;
        break;
    case SSL_ERROR_WANT_WRITE:
        LOG4CPLUS_DEBUG(logger, "Wait for socket to be writable"); // NOLINT
        writeFds = &monitorFd;
        break;
    case SSL_ERROR_ZERO_RETURN:
        // Handle case of an orderly shutdown from remote
        LOG4CPLUS_DEBUG(logger, "Remote side closed TLS connection"); // NOLINT
        retVal = OP_STATUS::DISCONNECTED;
        break;
    case SSL_ERROR_SYSCALL:
        {
            auto err = errno;
            // Handle case where connection to remote system was lost. Think
            // someone pulled the network cable
            if(err == 0)
            {
                LOG4CPLUS_DEBUG(logger, "Socket connection lost"); // NOLINT
                retVal = OP_STATUS::DISCONNECTED;
            }
            else
            {
                throwSystemError(err,
                    "System-level error encountered during TLS operation");
            }
        }
        break;
    default:
        if(ERR_FATAL_ERROR(ERR_peek_error()))
        {
            const string msg = "SSL API-related error encountered";
            logSSLError(msg);
            throw runtime_error(msg);
        }
        else
        {
            // Log the issue; but, move on
            logSSLError("Error encountered retrying operation, continuing.");
            retVal = OP_STATUS::SUCCESS;
        }
    }

    // Error was either SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
    if(retVal == OP_STATUS::INITIALIZED)
    {
        LOG4CPLUS_DEBUG(logger, "Wait for socket to be ready"); // NOLINT
        unique_ptr<timeval> waitTime = nullptr;
        if(timeout)
        {
            // NOLINTNEXTLINE
            auto timeoutVal = this->timeout.value();

            // NOLINTNEXTLINE
            LOG4CPLUS_TRACE(logger, "Setting timeout to " << timeoutVal
                << " seconds");
            waitTime = unique_ptr<timeval>(new timeval);
            if(!waitTime)
                throw bad_alloc();
            else
            {
                waitTime->tv_sec = timeoutVal;
                waitTime->tv_usec = 0;
            }
        }

        switch(wrapper->select((*sockfd)+1, readFds, writeFds, nullptr,
            waitTime.get()))
        {
        case -1:
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
                    LOG4CPLUS_DEBUG(logger, "Caught signal"); // NOLINT
                    retVal = OP_STATUS::INTERRUPTED;
                }
            }
            break;
        case 0:
            LOG4CPLUS_DEBUG(logger, "Wait time expired"); // NOLINT
            retVal = OP_STATUS::TIMEOUT;
            break;
        default:
            if(FD_ISSET(*sockfd, &monitorFd)) // NOLINT
            {
                LOG4CPLUS_DEBUG(logger, "Socket ready for reading"); // NOLINT
                retVal = OP_STATUS::SUCCESS;
            }
            else
            {
                auto err = errno;
                throwSystemError(err, "Socket not marked as ready");
            }
        }
    }
    else
        LOG4CPLUS_DEBUG(logger, "No need to wait for socket"); // NOLINT

    return retVal;
}

const SocketInfo::OP_STATUS SocketInfo::readData(char *data, size_t &dataSize)
{

    bool shouldRetry = true;
    auto ptr = getSSLPtr();
    ERR_clear_error();
    OP_STATUS retVal = OP_STATUS::INITIALIZED;
    do
    {
        auto rslt = wrapper->SSL_read(ptr, data, dataSize);
        LOG4CPLUS_TRACE(logger, "SSL_read return: " << rslt); // NOLINT
        if(rslt > 0)
        {
            shouldRetry = false;
            dataSize = rslt;
            retVal = OP_STATUS::SUCCESS;
            LOG4CPLUS_DEBUG(logger, "Read " << dataSize << " bytes of data"); // NOLINT
        }
        else if(wrapper->SSL_get_error(ptr, rslt) == SSL_ERROR_WANT_READ)
        {
            LOG4CPLUS_DEBUG(logger, "No application data available"); // NOLINT
            dataSize = 0;
            retVal = OP_STATUS::SUCCESS;
            shouldRetry = false;
        }
        else
        {
            retVal = handleRetry(rslt);
            if(retVal == OP_STATUS::SUCCESS)
                LOG4CPLUS_DEBUG(logger, "Retry reading data"); // NOLINT
            else
            {
                LOG4CPLUS_DEBUG(logger, "Stop attempts to read data"); // NOLINT
                shouldRetry = false;
            }
        }
    } while(shouldRetry);

    return retVal;
}

const SocketInfo::OP_STATUS SocketInfo::writeData(const char *msg, const size_t &msgSize)
{
    ERR_clear_error();

    bool shouldRetry = true;
    auto ptr = getSSLPtr();
    OP_STATUS retVal;
    do
    {
        auto rslt = wrapper->SSL_write(ptr, msg, msgSize);
        LOG4CPLUS_TRACE(logger, "SSL_write return: " << rslt); // NOLINT
        if(rslt <= 0)
        {
            retVal = handleRetry(rslt);
            if(retVal == OP_STATUS::SUCCESS)
                LOG4CPLUS_DEBUG(logger, "Retry writing data"); // NOLINT
            else
            {
                LOG4CPLUS_DEBUG(logger, "Stop attempts to write data"); // NOLINT
                shouldRetry = false;
            }
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, to_string(msgSize) << // NOLINT
                " sent over the wire");
            shouldRetry = false;
            retVal = OP_STATUS::SUCCESS;
        }
    } while(shouldRetry);

    return retVal;
}

void SocketInfo::newSSLCtx()
{
    // Allow old SSL protocol; because we don't control what protocol the
    //  system under test supports
    sslCtx = shared_ptr<SSL_CTX>(
        SSL_CTX_new(TLS_method()), &SSL_CTX_free);
    if(!sslCtx)
    {
        logSSLError("Failed to create SSL context.");
        throw bad_alloc();
    }
    else
        LOG4CPLUS_TRACE(logger, "Context object created"); // NOLINT

    if(SSL_CTX_set_min_proto_version(sslCtx.get(), SSL3_VERSION) != 1)
    {
        const string msg = "Failed to set minimum SSL version.";
        logSSLError(msg);
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
        logSSLError("Failed to create SSL instance.");
        throw bad_alloc();
    }
    else
        LOG4CPLUS_TRACE(logger, "SSL object created"); // NOLINT
}

void SocketInfo::logSSLError(const string &msg)
{
    LOG4CPLUS_ERROR(logger, msg << " SSL error stack"); // NOLINT
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

} //namespace tlslookieloo
