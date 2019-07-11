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

#include <sys/socket.h>

#include <log4cplus/loggingmacros.h>


#include "serverside.h"

using namespace std;

namespace tlslookieloo
{

const bool ServerSide::connect(const unsigned int &port, const string &host)
{
    bool retVal = true;

    LOG4CPLUS_DEBUG(logger, "Start socket connection"); // NOLINT
    if(sockConnect(port,  host) == false)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "Failed to connect to " << host << ":" << port);
        retVal = false;
    }
    else
    {
        LOG4CPLUS_DEBUG(logger, // NOLINT
            "Socket connection successful. Start TLS handshake");
        try
        {
            initializeSSLContext();
            if(!sslHandshake(host))
            {
                // NOLINTNEXTLINE
                LOG4CPLUS_ERROR(logger, "SSL handshake with " << host << " failed");
                retVal = false;
            }
            else
            {
                // NOLINTNEXTLINE
                LOG4CPLUS_INFO(logger, "Connection to " << host << ":" << port <<
                    " successful");
            }
        }
        catch(const exception &e)
        {
            LOG4CPLUS_ERROR(logger, // NOLINT
                "Error encountered during TLS handshake: " <<e.what()
            );
            retVal = false;
        }
    }

    return retVal;
}

bool ServerSide::waitForConnect()
{
    bool retVal = true;
    if(socketReady())
    {
        LOG4CPLUS_DEBUG(logger, "Connection ready"); // NOLINT

        int val;
        socklen_t len = sizeof(val);
        auto err = getsockopt(getSocket(), SOL_SOCKET, SO_ERROR, &val, &len);
        const string ip = getSocketIP();
        if(err != 0)
            throwSystemError(err, "getsockopt error");

        LOG4CPLUS_TRACE(logger, "Got socket option"); // NOLINT
        if(val == 0)
            // NOLINTNEXTLINE
            LOG4CPLUS_DEBUG(logger, "Connected to " << ip << " after waiting");
        else
        {
            LOG4CPLUS_DEBUG(logger, "Failed to connect to " << ip << // NOLINT
                " after waiting. Try next IP if available");
            retVal = false;
        }
    }
    else
    {
        LOG4CPLUS_INFO(logger, "Connection timed out");
        retVal = false;
    }

    return retVal;
}

const bool ServerSide::sockConnect(const unsigned int &port, const string &host)
{
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ServerSide");
    bool retVal = true;
    try
    {
        if(resolveHostPort(port, host))
        {
            string ip;
            do
            {
                initNextSocket();
                ip = getSocketIP();
                auto addrInfo = getAddrInfo();
                LOG4CPLUS_DEBUG(logger, "Attempt connecting to " << ip); // NOLINT
                if(::connect(getSocket(),
                    reinterpret_cast<const struct sockaddr *>(addrInfo->ai_addr), // NOLINT
                    addrInfo->ai_addrlen) != 0
                )
                {
                    auto err = errno;
                    if(err == EINPROGRESS)
                    {
                        if(waitForConnect())
                        {
                            LOG4CPLUS_DEBUG(logger, "Connected after wait"); // NOLINT
                            break;
                        }
                        else
                            LOG4CPLUS_DEBUG(logger, // NOLINT
                                "Connect failed after wait. Try next IP");
                    }
                    else
                    {
                        char buf[256];
                        char *errmsg = strerror_r(err, &buf[0], 256);
                        LOG4CPLUS_DEBUG(logger, // NOLINT
                            "Failed to connect to IP " << ip <<
                            ". Error message: " << errmsg << ". Try next IP");
                    }
                }
                else
                {
                    LOG4CPLUS_DEBUG(logger, "Connected to IP " << ip); // NOLINT
                    break;
                }
            }while(1);
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, "Failed to resolve " << host << ":" << // NOLINT
                port);
            retVal = false;
        }
    }
    catch(system_error &e)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "System error encountered connecting to remote. " <<
            e.what());
        throw;
    }
    catch(const range_error &e)
    {
        LOG4CPLUS_DEBUG(logger, "Unable to connect to host"); // NOLINT
        retVal = false;
    }

    return retVal;
}

void ServerSide::initializeSSLContext()
{
    newSSLCtx();
    auto ptr = getSSLCtxPtr();
    if(SSL_CTX_set_default_verify_paths(ptr) == 0)
    {
        const string msg = sslErrMsg("Failed to set CA verify paths");
        LOG4CPLUS_ERROR(logger, msg); // NOLINT
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "CA verify paths set"); // NOLINT
}

const bool ServerSide::sslHandshake(const std::string &host)
{
    bool retVal = true;
    newSSLObj();
    auto ptr = getSSLPtr();
    ERR_clear_error();
    if(SSL_set_fd(ptr, getSocket()) == 0)
    {
        const string msg = sslErrMsg("Failed to set FD to SSL. Cause: ");
        LOG4CPLUS_ERROR(logger, msg); // NOLINT
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "FD set to SSL instance"); // NOLINT

    if(SSL_set1_host(ptr, host.c_str()) != 1)
    {
        const string msg = sslErrMsg("Failed to set expected host. Cause: ");
        LOG4CPLUS_ERROR(logger, msg); // NOLINT
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Expected host set"); // NOLINT

    bool shouldRetry = false;
    do
    {
        LOG4CPLUS_DEBUG(logger, "Start SSL connection"); // NOLINT
        auto rslt = SSL_connect(ptr);
        LOG4CPLUS_TRACE(logger, "SSL_connect return: " << rslt); // NOLINT
        if(rslt == -1)
        {
            LOG4CPLUS_TRACE(logger, "SSL_connect reporting error"); // NOLINT
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

    if(retVal)
    {
        LOG4CPLUS_TRACE(logger, "Process peer validation"); // NOLINT
        auto certPtr = SSL_get_peer_certificate(ptr);
        LOG4CPLUS_TRACE(logger, "Value of certPtr: " << certPtr); // NOLINT
        if(certPtr != nullptr)
        {
            X509_free(certPtr);
            auto peerVal = SSL_get_verify_result(ptr);
            LOG4CPLUS_TRACE(logger, "Value of peerVal: " << peerVal); // NOLINT
            if(peerVal != X509_V_OK)
            {
                LOG4CPLUS_WARN(logger, "Failed to verify peer. Cause: " << // NOLINT
                    X509_verify_cert_error_string(peerVal)
                );
            }
        }
        else
            // NOLINTNEXTLINE
            LOG4CPLUS_WARN(logger, "Remote server did not provide a certificate");
    }
    else
        LOG4CPLUS_DEBUG(logger, "Handshake failed"); // NOLINT

    return retVal;
}

const bool ServerSide::socketReady()
{
    bool retVal = true;

    fd_set writeFd;
    FD_ZERO(&writeFd);
    FD_SET(getSocket(), &writeFd);

    timeval waitTime;
    waitTime.tv_sec = getTimeout();
    waitTime.tv_usec = 0;

    auto rslt = wrapper->select(getSocket() + 1, nullptr, &writeFd, nullptr, &waitTime);
    if(rslt > 0)
    {
        if(!FD_ISSET(getSocket(), &writeFd))
            throw logic_error("Socket FD not set after select returned ready");
        else
            LOG4CPLUS_DEBUG(logger, "Socket ready for writing");
    }
    else if(rslt == 0)
    {
        LOG4CPLUS_DEBUG(logger, "Timed-out waiting for socket");
        retVal = false;
    }
    else
    {
        auto err = errno;
        throwSystemError(err, "Error encountered waiting to connect to server");
    }

    return retVal;
}

} // namespace tlslookieloo
