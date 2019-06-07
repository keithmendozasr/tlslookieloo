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
#include <stdexcept>
#include <string>
#include <cerrno>

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include <log4cplus/loggingmacros.h>

#include <openssl/err.h>

#include "clientside.h"

using namespace std;

namespace tlslookieloo
{

void ClientSide::startListener(const unsigned int &port,
    const unsigned int &backlog)
{
    try
    {
        if(resolveHostPort(port))
        {
            initNextSocket();
            auto sockFd = getSocket();

            const int yes = 1;
            if(setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))
                == -1)
                throwSystemError(errno, "Error setting socket options");
            
            LOG4CPLUS_TRACE(logger, "Attempt to listen to port " << port);
            auto addr = getAddrInfo();
            if(bind(
                sockFd, reinterpret_cast<const struct sockaddr *>(&addr),
                (addr.ss_family == AF_INET ? sizeof(sockaddr_in) :
                    sizeof(sockaddr_in6))) == -1
            )
                throwSystemError(errno, "Failed to bind");
            
            LOG4CPLUS_TRACE(logger, "Bound to port " << port);

            if(listen(sockFd, backlog) == -1)
                throwSystemError(errno, "Failed to listen");


        }
        else
        {
            string msg("Failed to resolve port ");
            msg += to_string(port);
            LOG4CPLUS_DEBUG(logger, msg);
            throw logic_error(msg);
        }
    }
    catch(system_error &e)
    {
        LOG4CPLUS_ERROR(logger, "System error encountered starting listener. " <<
            e.what());
        closeSocket();
        throw;
    }

    LOG4CPLUS_DEBUG(logger, "Listening on port " << port);
}

ClientSide ClientSide::acceptClient()
{
    struct sockaddr_storage addr;
    socklen_t addrLen = sizeof(addr);

    waitForReading(); // We're waiting forever, so no need to check timeout
    int fd = accept(getSocket(), reinterpret_cast<struct sockaddr *>(&addr),
        &addrLen);
    if(fd < 0)
    {
        int err = errno;
        throwSystemError(err, "Accept error");
    }

    LOG4CPLUS_DEBUG(logger, "Received connection. New FD: " << fd);

    if(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1)
    {
        int err = errno;
        throwSystemError(err, "Failed to set client FD non-blocking");
    }
    else
        LOG4CPLUS_TRACE(logger, "New FD non-blocking set");

    ClientSide c;
    c.setSocket(fd);
    c.setAddrInfo(&addr, addrLen);

    return move(c);
}

optional<const size_t> ClientSide::readData(char *data, const size_t &dataSize)
{
    if(!sslObj)
        throw logic_error("Attempting to read when SSL not initialized");

    ERR_clear_error();

    bool shouldRetry = false;
    auto ptr = sslObj.get();
    optional<size_t> retVal;
    do
    {
        auto rslt = SSL_read(ptr, data, dataSize);
        LOG4CPLUS_TRACE(logger, "SSL_read return: " << rslt);
        if(rslt <= 0)
        {
            LOG4CPLUS_TRACE(logger, "SSL_read reporting error");
            if(SSL_get_error(ptr, rslt) == SSL_ERROR_SYSCALL && errno == 0)
            {
                LOG4CPLUS_TRACE(logger, "No more data to read");
                shouldRetry = false;
            }
            else
            {
                LOG4CPLUS_TRACE(logger, "Wait for read ready");
                shouldRetry = handleRetry(rslt);
            }
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, to_string(rslt) << " received over the wire");
            shouldRetry = false;
            retVal = rslt;
        }

    } while(shouldRetry);

    return retVal;
}

const size_t ClientSide::writeData(const char *msg, const size_t &msgSize)
{
    if(!sslObj)
        throw logic_error("Attempting to write when SSL not initialized");

    ERR_clear_error();

    bool shouldRetry = false;
    auto ptr = sslObj.get();
    do
    {
        auto rslt = SSL_write(ptr, msg, msgSize);
        LOG4CPLUS_TRACE(logger, "SSL_write return: " << rslt);
        if(rslt <= 0)
        {
            LOG4CPLUS_TRACE(logger, "SSL_write reporting error");
            shouldRetry = handleRetry(rslt);
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, to_string(msgSize) << " sent over the wire");
            shouldRetry = false;
        }

    } while(shouldRetry);

    return msgSize;
}

const string ClientSide::sslErrMsg(const string &prefix)
{
    auto code = ERR_get_error();
    auto txt = ERR_reason_error_string(code);
    return prefix + txt;
}

void ClientSide::initializeSSLContext(const string &certFile, const string &privKeyFile)
{
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    sslCtx = unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_server_method()), &SSL_CTX_free
    );

    if(!sslCtx)
    {
        const string msg = sslErrMsg("Failed to create SSL context. Cause: ");
        LOG4CPLUS_ERROR(logger, msg);
        throw bad_alloc();
    }
    else
        LOG4CPLUS_TRACE(logger, "Context object created");

    auto ptr = sslCtx.get();

    LOG4CPLUS_TRACE(logger, "Loading separate certificate chain");
    if(SSL_CTX_use_certificate_chain_file(ptr, certFile.c_str()) == 0)
    {
        const string msg = sslErrMsg(
            string("Failed to load certificate file ") + certFile +
            ". Cause: "
        );
        LOG4CPLUS_ERROR(logger, msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Certificate file loaded");

    if(SSL_CTX_use_PrivateKey_file(ptr, privKeyFile.c_str(),
        SSL_FILETYPE_PEM) == 0)
    {
        const string msg = sslErrMsg(
            string("Failed to load private key ") + privKeyFile +
            ". Cause: "
        );
        LOG4CPLUS_ERROR(logger, msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Private key file loaded");
}

const bool ClientSide::handleRetry(const int &rslt)
{
    bool retVal = true;

    auto ptr = sslObj.get();
    auto code = SSL_get_error(ptr, rslt);

    LOG4CPLUS_TRACE(logger, "Code: " << code);

    switch(code)
    {
    case SSL_ERROR_WANT_READ:
        LOG4CPLUS_TRACE(logger, "Wait for read ready");
        if(!waitForReading(timeout))
        {
            LOG4CPLUS_INFO(logger, "Network timeout waiting to read data");
            retVal = false;
        }
        else
            LOG4CPLUS_TRACE(logger, "Socket ready for reading");
        break;
    case SSL_ERROR_WANT_WRITE:
        LOG4CPLUS_TRACE(logger, "Wait for write ready");
        if(!waitForWriting(timeout))
        {
            LOG4CPLUS_INFO(logger, "Network timeout waiting to write data");
            retVal = false;
        }
        else
            LOG4CPLUS_TRACE(logger, "Socket ready for writing");
        break;
    case SSL_ERROR_ZERO_RETURN:
        LOG4CPLUS_TRACE(logger, "Remote closed SSL session");
        retVal = false;
        break;
    default:
        {
            LOG4CPLUS_ERROR(logger, "SSL error encountered. Error stack");
            unsigned long errCode;
            do
            {
                errCode = ERR_get_error();
                if(errCode != 0)
                {
                    const char *msg = ERR_reason_error_string(errCode);
                    LOG4CPLUS_ERROR(logger, "\t" <<
                        (msg != nullptr ? msg : "Code " + to_string(code)));
                }
            } while(errCode != 0);
        }
        throw logic_error(string("SSL error"));
    }

    return retVal;
}

const bool ClientSide::sslHandshake()
{
    bool retVal = true;

    if(!sslCtx)
        throw logic_error("Attempting handshake before SSL context initialized");

    ERR_clear_error();
    sslObj = unique_ptr<SSL, SSLDeleter>(SSL_new(sslCtx.get()));
    if(!sslObj)
    {
        const string msg = sslErrMsg("Failed to create SSL instance. Cause: ");
        LOG4CPLUS_ERROR(logger, msg);
        throw bad_alloc();
    }
    else
        LOG4CPLUS_TRACE(logger, "SSL object created");

    auto ptr = sslObj.get();
    if(SSL_set_fd(ptr, getSocket()) == 0)
    {
        const string msg = sslErrMsg("Failed to set FD to SSL. Cause: ");
        LOG4CPLUS_ERROR(logger, msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "FD set to SSL instance: " << getSocket());

    bool shouldRetry = false;
    do
    {
        LOG4CPLUS_DEBUG(logger, "Start SSL accept");
        auto rslt = SSL_accept(ptr);
        LOG4CPLUS_TRACE(logger, "SSL_accept return: " << rslt);
        if(rslt == -1)
        {
            LOG4CPLUS_TRACE(logger, "SSL_accept reporting error");
            shouldRetry = handleRetry(rslt);
        }
        else if(rslt == 0)
        {
            const string msg = sslErrMsg("Remote closed SSL handshake. Cause: ");
            LOG4CPLUS_WARN(logger, msg);
            retVal = shouldRetry = false;
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, "Handshake complete");
            shouldRetry = false;
        }
    } while(shouldRetry);

    return retVal;
}

} // namespace tlslookieloo
