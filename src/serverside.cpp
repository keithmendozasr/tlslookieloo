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

#include <openssl/err.h>

#include "serverside.h"

using namespace std;

namespace tlslookieloo
{

const bool ServerSide::connect(const unsigned int &port, const string &host)
{
    bool retVal = true;

    LOG4CPLUS_DEBUG(logger, "Start socket connection");
    if(sockConnect(port,  host) == false)
    {
        LOG4CPLUS_ERROR(logger, "Failed to connect to " << host << ":" << port);
        retVal = false;
    }
    else
    {
        LOG4CPLUS_DEBUG(logger,
            "Socket connection successful. Start TLS handshake");
        try
        {
            initializeSSLContext();
            if(!sslHandshake(host))
            {
                LOG4CPLUS_ERROR(logger, "SSL handshake with " << host << " failed");
                retVal = false;
            }
            else
            {
                LOG4CPLUS_INFO(logger, "Connection to " << host << ":" << port <<
                    " successful");
            }
        }
        catch(const exception &e)
        {
            LOG4CPLUS_ERROR(logger,
                "Error encountered during TLS handshake: " <<e.what()
            );
            retVal = false;
        }
    }

    return retVal;
}

const size_t ServerSide::readData(char *data, const size_t &dataSize)
{
    if(!sslObj)
        throw logic_error("Attempting to read when SSL not initialized");

    ERR_clear_error();

    bool shouldRetry = false;
    auto ptr = sslObj.get();
    int rslt;
    do
    {
        rslt = SSL_read(ptr, data, dataSize);
        LOG4CPLUS_TRACE(logger, "SSL_read return: " << rslt);
        if(rslt <= 0)
        {
            LOG4CPLUS_TRACE(logger, "SSL_read reporting error");
            shouldRetry = handleRetry(rslt);
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, to_string(rslt) << " received over the wire");
            shouldRetry = false;
        }

    } while(shouldRetry);

    return rslt;
}
const size_t ServerSide::writeData(const char *msg, const size_t &msgSize)
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

bool ServerSide::waitForConnect()
{
    bool retVal = true;
    if(!waitForWriting(timeout))
    {
        LOG4CPLUS_INFO(logger, "Connection timed out");
        retVal = false;
    }
    else
    {
        LOG4CPLUS_DEBUG(logger, "Connection ready");

        int val;
        socklen_t len = sizeof(val);
        auto err = getsockopt(getSocket(), SOL_SOCKET, SO_ERROR, &val, &len);
        const string ip = getSocketIP();
        if(err != 0)
            throwSystemError(err, "getsockopt error");

        LOG4CPLUS_TRACE(logger, "Got socket option");
        if(val == 0)
            LOG4CPLUS_DEBUG(logger, "Connected to " << ip << " after waiting");
        else
        {
            LOG4CPLUS_DEBUG(logger, "Failed to connect to " << ip <<
                " after waiting. Try next IP if available");
            retVal = false;
        }
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
                struct sockaddr_storage addr;
                try
                {
                    initNextSocket();
                    addr = getAddrInfo();
                    ip = getSocketIP();
                    if(::connect(getSocket(), reinterpret_cast<struct sockaddr *>(&addr),
                        getAddrInfoSize()) != 0)
                    {
                        auto err = errno;
                        if(err == EINPROGRESS)
                        {
                            if(waitForConnect())
                            {
                                LOG4CPLUS_DEBUG(logger, "Connected after wait");
                                break;
                            }
                            else
                                LOG4CPLUS_DEBUG(logger,
                                    "Connect failed after wait. Try next IP");
                        }
                        else
                        {
                            char buf[256];
                            char *errmsg = strerror_r(err, buf, 256);
                            LOG4CPLUS_DEBUG(logger,
                                "Failed to connect to IP " << ip <<
                                ". Error message: " << errmsg << ". Try next IP");
                        }
                    }
                    else
                    {
                        LOG4CPLUS_DEBUG(logger, "Connected to IP " << ip);
                        break;
                    }
                }
                catch(const range_error &e)
                {
                    LOG4CPLUS_DEBUG(logger, "Unable to connect to host");
                    retVal = false;
                    break;
                }

                // If it gets here closed the previously-opened socket for the next
                // try
                closeSocket();
            }while(1);
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, "Failed to resolve " << host << ":" << port);
            retVal = false;
        }
    }
    catch(system_error &e)
    {
        LOG4CPLUS_ERROR(logger, "System error encountered connecting to remote. " <<
            e.what());
        throw;
    }

    return retVal;
}

const string ServerSide::sslErrMsg(const string &prefix)
{
    auto code = ERR_get_error();
    auto txt = ERR_reason_error_string(code);
    return prefix + txt;
}

void ServerSide::initializeSSLContext()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();

    sslCtx = unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_client_method()), &SSL_CTX_free
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
    if(SSL_CTX_set_min_proto_version(ptr, TLS1_1_VERSION) == 0)
    {
        const string msg = sslErrMsg(
            "Failed to configure min TLS version. Cause: "
        );
        LOG4CPLUS_ERROR(logger, msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Min TLS version set");

    if(SSL_CTX_set_default_verify_paths(ptr) == 0)
    {
        const string msg = sslErrMsg("Failed to set CA verify paths");
        LOG4CPLUS_ERROR(logger, msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "CA verify paths set");
}

const bool ServerSide::handleRetry(const int &rslt)
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
            LOG4CPLUS_INFO(logger, "Network timeout during handshake");
            retVal = false;
        }
        else
            LOG4CPLUS_TRACE(logger, "Socket ready for reading");
        break;
    case SSL_ERROR_WANT_WRITE:
        LOG4CPLUS_TRACE(logger, "Wait for write ready");
        if(!waitForWriting(timeout))
        {
            LOG4CPLUS_INFO(logger, "Network timeout during handshake");
            retVal = false;
        }
        else
            LOG4CPLUS_TRACE(logger, "Socket ready for writing");
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

const bool ServerSide::sslHandshake(const std::string &host)
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
        LOG4CPLUS_TRACE(logger, "FD set to SSL instance");

    if(SSL_set1_host(ptr, host.c_str()) != 1)
    {
        const string msg = sslErrMsg("Failed to set expected host. Cause: ");
        LOG4CPLUS_ERROR(logger, msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Expected host set");

    bool shouldRetry = false;
    do
    {
        LOG4CPLUS_DEBUG(logger, "Start SSL connection");
        auto rslt = SSL_connect(ptr);
        LOG4CPLUS_TRACE(logger, "SSL_connect return: " << rslt);
        if(rslt == -1)
        {
            LOG4CPLUS_TRACE(logger, "SSL_connect reporting error");
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

    if(retVal)
    {
        LOG4CPLUS_TRACE(logger, "Process peer validation");
        auto certPtr = SSL_get_peer_certificate(ptr);
        LOG4CPLUS_TRACE(logger, "Value of certPtr: " << certPtr);
        if(certPtr != nullptr)
        {
            X509_free(certPtr);
            auto peerVal = SSL_get_verify_result(ptr);
            LOG4CPLUS_TRACE(logger, "Value of peerVal: " << peerVal);
            if(peerVal != X509_V_OK)
            {
                LOG4CPLUS_WARN(logger, "Failed to verify peer. Cause: " <<
                    X509_verify_cert_error_string(peerVal)
                );
            }
        }
        else
            LOG4CPLUS_WARN(logger, "Remote server did not provide a certificate");
    }
    else
        LOG4CPLUS_DEBUG(logger, "Handshake failed");

    return retVal;
}

} // namespace tlslookieloo
