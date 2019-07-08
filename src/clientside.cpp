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
#include <utility>

#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>

#include <log4cplus/loggingmacros.h>

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
            
            LOG4CPLUS_TRACE(logger, "Attempt to listen to port " << port); // NOLINT
            auto addr = getAddrInfo();
            if(bind(
                sockFd, reinterpret_cast<const struct sockaddr *>(addr->ai_addr), // NOLINT
                addr->ai_addrlen
                ) == -1
            )
                throwSystemError(errno, "Failed to bind");
            
            LOG4CPLUS_TRACE(logger, "Bound to port " << port); // NOLINT

            if(listen(sockFd, backlog) == -1)
                throwSystemError(errno, "Failed to listen");


        }
        else
        {
            string msg("Failed to resolve port ");
            msg += to_string(port);
            LOG4CPLUS_DEBUG(logger, msg); // NOLINT
            throw logic_error(msg);
        }
    }
    catch(system_error &e)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "System error encountered starting listener. " <<
            e.what());
        throw;
    }

    LOG4CPLUS_DEBUG(logger, "Listening on port " << port); // NOLINT
}

optional<ClientSide> ClientSide::acceptClient()
{
    struct sockaddr_storage addr; // NOLINT
    socklen_t addrLen = sizeof(addr);

    // We're waiting forever, so no need to check timeout
    waitSocketReadable();
    int fd = accept(getSocket(), reinterpret_cast<struct sockaddr *>(&addr), // NOLINT
        &addrLen);
    if(fd < 0)
    {
        int err = errno;
        throwSystemError(err, "Accept error");
    }

    LOG4CPLUS_DEBUG(logger, "Received connection. New FD: " << fd); // NOLINT

    if(fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) == -1) // NOLINT
    {
        int err = errno;
        throwSystemError(err, "Failed to set client FD non-blocking");
    }
    else
        LOG4CPLUS_TRACE(logger, "New FD non-blocking set"); // NOLINT

    ClientSide c(getWrapper());
    c.setSocket(fd);
    // NOLINTNEXTLINE
    c.saveSocketIP(reinterpret_cast<struct sockaddr_storage *>(&addr));

    return make_optional(c);
}

void ClientSide::initializeSSLContext(const string &certFile, const string &privKeyFile)
{
    newSSLCtx();
    auto ptr = getSSLCtxPtr();
    LOG4CPLUS_TRACE(logger, "Loading separate certificate chain"); // NOLINT
    if(SSL_CTX_use_certificate_chain_file(ptr, certFile.c_str()) == 0)
    {
        const string msg = sslErrMsg(
            string("Failed to load certificate file ") + certFile +
            ". Cause: "
        );
        LOG4CPLUS_ERROR(logger, msg); // NOLINT
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Certificate file loaded"); // NOLINT

    if(SSL_CTX_use_PrivateKey_file(ptr, privKeyFile.c_str(),
        SSL_FILETYPE_PEM) == 0)
    {
        const string msg = sslErrMsg(
            string("Failed to load private key ") + privKeyFile +
            ". Cause: "
        );
        LOG4CPLUS_ERROR(logger, msg); // NOLINT
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Private key file loaded"); // NOLINT
}

const bool ClientSide::sslHandshake()
{
    bool retVal = true;

    ERR_clear_error();

    newSSLObj();
    auto ptr = getSSLPtr();
    if(SSL_set_fd(ptr, getSocket()) == 0)
    {
        const string msg = sslErrMsg("Failed to set FD to SSL. Cause: ");
        LOG4CPLUS_ERROR(logger, msg); // NOLINT
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "FD set to SSL instance: " << getSocket()); // NOLINT

    bool shouldRetry = false;
    do
    {
        LOG4CPLUS_DEBUG(logger, "Start SSL accept"); // NOLINT
        auto rslt = SSL_accept(ptr);
        LOG4CPLUS_TRACE(logger, "SSL_accept return: " << rslt); // NOLINT
        if(rslt == -1)
        {
            LOG4CPLUS_TRACE(logger, "SSL_accept reporting error"); // NOLINT
            shouldRetry = handleRetry(rslt);
        }
        else if(rslt == 0)
        {
            const string msg = sslErrMsg("Remote closed SSL handshake. Cause: ");
            LOG4CPLUS_WARN(logger, msg); // NOLINT
            retVal = shouldRetry = false;
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, "Handshake complete"); // NOLINT
            shouldRetry = false;
        }
    } while(shouldRetry);

    return retVal;
}

void ClientSide::waitSocketReadable()
{
    fd_set readFd;
    FD_ZERO(&readFd);
    FD_SET(getSocket(), &readFd);

    if(select(getSocket() + 1, &readFd, nullptr, nullptr, nullptr) > 0)
    {
        if(!FD_ISSET(getSocket(), &readFd))
            throw logic_error("Socket FD not set after select returned ready");
        else
            LOG4CPLUS_DEBUG(logger, "Socket ready for reading");
    }
    else
    {
        auto err = errno;
        throwSystemError(err, "Error encountered waiting for a client to connect");
    }
}

} // namespace tlslookieloo
