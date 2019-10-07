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
#include <memory>

#include <sys/socket.h>

#include <log4cplus/loggingmacros.h>

#include "serverside.h"

using namespace std;

namespace tlslookieloo
{

const bool ServerSide::connect(const unsigned int &port, const string &host,
    ClientCertInfo clientCert, const bool allowInsecure,
    const optional<const string> serverCACertFile)
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
            initializeSSLContext(serverCACertFile);
            if(!sslHandshake(host, clientCert, allowInsecure))
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
        auto err = wrapper->getsockopt(getSocket(), SOL_SOCKET, SO_ERROR, &val, &len);
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
        LOG4CPLUS_INFO(logger, "Connection timed out"); // NOLINT
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
                if(wrapper->connect(getSocket(),
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

void ServerSide::initializeSSLContext(const optional<const string> &serverCAChainFile)
{
    newSSLCtx();
    auto ptr = getSSLCtxPtr();

    if(serverCAChainFile)
    {
        auto CAChainFile = serverCAChainFile.value();
        LOG4CPLUS_INFO(logger, "Using CA cert chain in " << CAChainFile); // NOLINT
        if(SSL_CTX_use_certificate_chain_file(ptr, CAChainFile.c_str()) == 0)
        {
            const string msg = "Failed to load CA certificate chain file.";
            logSSLError(msg);
            throw runtime_error(msg);
        }
        else
            LOG4CPLUS_TRACE(logger, "CA cert chain file loaded"); // NOLINT
    }
    else
        LOG4CPLUS_TRACE(logger, "Extra CA chain not provided"); // NOLINT

    // Load certificates from store
    if(SSL_CTX_set_default_verify_paths(ptr) == 0)
    {
        const string msg = "Failed to set CA verify paths.";
        logSSLError(msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "CA verify paths set"); // NOLINT
}

const bool ServerSide::sslHandshake(const std::string &host,
    ClientCertInfo clientCert, const bool allowInsecure)
{
    bool retVal = true;
    newSSLObj();
    auto ptr = getSSLPtr();
    ERR_clear_error();
    if(SSL_set_fd(ptr, getSocket()) == 0)
    {
        const string msg = "Failed to set FD to SSL.";
        logSSLError(msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "FD set to SSL instance"); // NOLINT

    if(SSL_set1_host(ptr, host.c_str()) != 1)
    {
        const string msg = "Failed to set expected host.";
        logSSLError(msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Expected host set"); // NOLINT

    if(clientCert)
    {
        LOG4CPLUS_DEBUG(logger, "Client cert files provided"); // NOLINT
        string clientPubKeyPath, clientPrivKeyPath;
        tie(clientPubKeyPath, clientPrivKeyPath) = clientCert.value();
        loadClientCertificate(clientPubKeyPath, clientPrivKeyPath);
    }
    else
        LOG4CPLUS_TRACE(logger, "No client cert files provided"); // NOLINT


    bool shouldRetry = false;
    do
    {
        LOG4CPLUS_DEBUG(logger, "Start SSL connection"); // NOLINT
        auto rslt = SSL_connect(ptr);
        LOG4CPLUS_TRACE(logger, "SSL_connect return: " << rslt); // NOLINT
        if(rslt == -1)
        {
            LOG4CPLUS_TRACE(logger, "SSL_connect reporting error"); // NOLINT
            shouldRetry = (handleRetry(rslt) == SocketInfo::OP_STATUS::SUCCESS);
        }
        else if(rslt == 0)
        {
            const string msg = "Remote closed SSL handshake.";
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
        unique_ptr<X509, decltype(&X509_free)>certPtr(
            SSL_get_peer_certificate(ptr),
            &X509_free
        );
        if(certPtr)
        {
            auto peerVal = SSL_get_verify_result(ptr);
            LOG4CPLUS_TRACE(logger, "Value of peerVal: " << peerVal); // NOLINT
            if(peerVal != X509_V_OK)
            {
                LOG4CPLUS_WARN(logger, "Failed to verify server identity. Cause: " << // NOLINT
                    X509_verify_cert_error_string(peerVal)
                );
                retVal = (allowInsecure == true);
            }
        }
        else
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_WARN(logger, "Remote server did not provide a certificate");
            retVal = (allowInsecure == true);
        }
    }
    else
        LOG4CPLUS_DEBUG(logger, "Handshake failed"); // NOLINT

    LOG4CPLUS_TRACE(logger, "Handshake result to return: " << retVal); // NOLINT
    return retVal;
}

const bool ServerSide::socketReady()
{
    bool retVal = true;

    fd_set writeFd;
    FD_ZERO(&writeFd);
    FD_SET(getSocket(), &writeFd); // NOLINT

    unique_ptr<timeval>waitTime(nullptr);
    auto timeout = getTimeout();
    if(timeout)
    {
        LOG4CPLUS_DEBUG(logger, "Setting timeout to " << timeout.value());
        waitTime = make_unique<timeval>();
        waitTime->tv_sec = timeout.value();
        waitTime->tv_usec = 0;
    }
    else
        LOG4CPLUS_DEBUG(logger, "No timeout set");

    auto rslt = wrapper->select(getSocket() + 1, nullptr, &writeFd, nullptr, waitTime.get());
    if(rslt > 0)
    {
        if(!FD_ISSET(getSocket(), &writeFd)) // NOLINT
            throw logic_error("Socket FD not set after select returned ready");
        else
            LOG4CPLUS_DEBUG(logger, "Socket ready for writing"); // NOLINT
    }
    else if(rslt == 0)
    {
        LOG4CPLUS_DEBUG(logger, "Timed-out waiting for socket"); // NOLINT
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
    LOG4CPLUS_TRACE(logger, "Public key file: " << clientCertFile); // NOLINT
    if(SSL_use_certificate_file(ptr, clientCertFile.c_str(),
        SSL_FILETYPE_PEM) == 0)
    {
        const string msg = string("Failed to load certificate file ") +
            clientCertFile + ".";
        logSSLError(msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Certificate file loaded"); // NOLINT

    LOG4CPLUS_TRACE(logger, "Private key file: " << clientPrivKeyFile); // NOLINT
    if(SSL_use_PrivateKey_file(ptr, clientPrivKeyFile.c_str(),
        SSL_FILETYPE_PEM) == 0)
    {
        const string msg =  string("Failed to load private key ") +
            clientPrivKeyFile + ".";
        logSSLError(msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Private key file loaded"); // NOLINT
}

} // namespace tlslookieloo
