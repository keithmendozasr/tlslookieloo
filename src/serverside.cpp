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
#include <optional>
#include <tuple>

#include <sys/socket.h>

#include <log4cplus/loggingmacros.h>


#include "serverside.h"

using namespace std;

namespace tlslookieloo
{

const bool ServerSide::connect(const unsigned int &port, const string &host,
        ClientCertInfo clientCert)
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
            if(!sslHandshake(host, clientCert))
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

bool ServerSide::waitForConnect()
{
    bool retVal = true;
    if(socketReady())
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
                LOG4CPLUS_DEBUG(logger, "Attempt connecting to " << ip);
                if(::connect(getSocket(),
                    reinterpret_cast<const struct sockaddr *>(addrInfo->ai_addr),
                    addrInfo->ai_addrlen) != 0
                )
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
                        char *errmsg = strerror_r(err, &buf[0], 256);
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
            }while(1);
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, "Failed to resolve " << host << ":" <<
                port);
            retVal = false;
        }
    }
    catch(system_error &e)
    {
        LOG4CPLUS_ERROR(logger, "System error encountered connecting to remote. " <<
            e.what());
        throw;
    }
    catch(const range_error &e)
    {
        LOG4CPLUS_DEBUG(logger, "Unable to connect to host");
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
        LOG4CPLUS_ERROR(logger, msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "CA verify paths set");
}

const bool ServerSide::sslHandshake(const std::string &host,
    ClientCertInfo clientCert)
{
    bool retVal = true;
    newSSLObj();
    auto ptr = getSSLPtr();
    ERR_clear_error();
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

    if(clientCert)
    {
        LOG4CPLUS_DEBUG(logger, "Client cert files provided");
        string clientPubKeyPath, clientPrivKeyPath;
        tie(clientPubKeyPath, clientPrivKeyPath) = clientCert.value();
        loadClientCertificate(clientPubKeyPath, clientPrivKeyPath);
    }
    else
        LOG4CPLUS_TRACE(logger, "No client cert files provided");


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
        unique_ptr<X509, decltype(&X509_free)>certPtr(
            SSL_get_peer_certificate(ptr),
            &X509_free
        );
        if(certPtr)
        {
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

void ServerSide::loadClientCertificate(const string &clientCertFile,
    const string &clientPrivKeyFile)
{
    auto ptr = getSSLPtr();
    LOG4CPLUS_TRACE(logger, "Public key file: " << clientCertFile);
    if(SSL_use_certificate_file(ptr, clientCertFile.c_str(),
        SSL_FILETYPE_PEM) == 0)
    {
        const string msg = sslErrMsg(
            string("Failed to load certificate file ") + clientCertFile +
            ". Cause: "
        );
        LOG4CPLUS_ERROR(logger, msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Certificate file loaded");

    LOG4CPLUS_TRACE(logger, "Private key file: " << clientPrivKeyFile);
    if(SSL_use_PrivateKey_file(ptr, clientPrivKeyFile.c_str(),
        SSL_FILETYPE_PEM) == 0)
    {
        const string msg = sslErrMsg(
            string("Failed to load private key ") + clientPrivKeyFile +
            ". Cause: "
        );
        LOG4CPLUS_ERROR(logger, msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Private key file loaded");
}

} // namespace tlslookieloo
