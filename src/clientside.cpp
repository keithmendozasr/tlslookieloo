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
#include <cstdio>

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
            if(wrapper->setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes))
                == -1)
                throwSystemError(errno, "Error setting socket options");
            
            LOG4CPLUS_TRACE(logger, "Attempt to listen to port " << port); // NOLINT
            auto addr = getAddrInfo();
            if(wrapper->bind(
                sockFd, reinterpret_cast<const struct sockaddr *>(addr->ai_addr), // NOLINT
                addr->ai_addrlen
                ) == -1
            )
                throwSystemError(errno, "Failed to bind");
            
            LOG4CPLUS_TRACE(logger, "Bound to port " << port); // NOLINT

            if(wrapper->listen(sockFd, backlog) == -1)
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

ClientSide ClientSide::acceptClient()
{
    struct sockaddr_storage addr; // NOLINT
    socklen_t addrLen = sizeof(addr);

    // We're waiting forever, so no need to check timeout
    waitSocketReadable();
    int fd = wrapper->accept(getSocket(), reinterpret_cast<struct sockaddr *>(&addr), // NOLINT
        &addrLen);
    if(fd < 0)
    {
        int err = errno;
        throwSystemError(err, "Accept error");
    }

    LOG4CPLUS_DEBUG(logger, "Received connection. New FD: " << fd); // NOLINT

    if(wrapper->fcntl(fd, F_SETFL, wrapper->fcntl(fd, F_GETFL, 0) | O_NONBLOCK) // NOLINT
        == -1)
    {
        int err = errno;
        throwSystemError(err, "Failed to set client FD non-blocking");
    }
    else
        LOG4CPLUS_TRACE(logger, "New FD non-blocking set"); // NOLINT

    ClientSide c(*this);
    c.setSocket(fd);
    // NOLINTNEXTLINE
    c.saveSocketIP(&addr);

    return c;
}

void ClientSide::initializeSSLContext(const string &certFile, const string &privKeyFile)
{
    ERR_clear_error();

    newSSLCtx();
    auto ptr = getSSLCtxPtr();

    LOG4CPLUS_TRACE(logger, "Loading listener certificate file"); // NOLINT
    if(SSL_CTX_use_certificate_file(ptr, certFile.c_str(),
        SSL_FILETYPE_PEM) == 0)
    {
        const string msg = string("Failed to load certificate file ") +
            certFile + ".";
        logSSLError(msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "Certificate file loaded"); // NOLINT

    if(SSL_CTX_use_PrivateKey_file(ptr, privKeyFile.c_str(),
        SSL_FILETYPE_PEM) == 0)
    {
        const string msg = string("Failed to load private key ") +
            privKeyFile + ".";
        logSSLError(msg);
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
        const string msg = "Failed to set FD to SSL.";
        logSSLError(msg);
        throw runtime_error(msg);
    }
    else
        LOG4CPLUS_TRACE(logger, "FD set to SSL instance: " << getSocket()); // NOLINT

    bool shouldRetry = true;
    do
    {
        LOG4CPLUS_DEBUG(logger, "Start SSL accept"); // NOLINT
        auto rslt = SSL_accept(ptr);
        LOG4CPLUS_TRACE(logger, "SSL_accept return: " << rslt); // NOLINT
        if(rslt == -1)
        {
            LOG4CPLUS_TRACE(logger, "SSL_accept reporting error"); // NOLINT
            switch(handleRetry(rslt))
            {
            case SocketInfo::OP_STATUS::SUCCESS:
                LOG4CPLUS_DEBUG(logger, "Retry SSL accept"); // NOLINT
                break;
            default:
                LOG4CPLUS_DEBUG(logger, "Not retrying SSL accept"); // NOLINT
                retVal = shouldRetry = false;
                break;
            }
        }
        else if(rslt == 0)
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger,
                "Remote disconnected during SSL handshake");
            retVal = shouldRetry = false;
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, "Handshake complete"); // NOLINT
            shouldRetry = false;
        }
    } while(shouldRetry);

    if(retVal && refClientPubKey)
    {
        LOG4CPLUS_DEBUG(logger, "Check for client cert"); // NOLINT
        unique_ptr<X509, decltype(&X509_free)> clientCert(
            SSL_get_peer_certificate(ptr), &X509_free);
        if(!clientCert)
        {
            LOG4CPLUS_WARN(logger, "Client didn't send a certificate"); // NOLINT
            retVal = false;
        }
        else
        {
            LOG4CPLUS_TRACE(logger, "Received client certificate"); // NOLINT
            unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pubKey(
                X509_get_pubkey(clientCert.get()), &EVP_PKEY_free);
            retVal = EVP_PKEY_cmp(pubKey.get(), refClientPubKey.get()) == 1;
            if(retVal)
                LOG4CPLUS_DEBUG(logger, "Client certificate match"); // NOLINT
            else
                LOG4CPLUS_DEBUG(logger, "Client certificate didn't match"); // NOLINT
        }
    }
    else
        LOG4CPLUS_DEBUG(logger, "Not checking for client cert"); // NOLINT

    return retVal;
}

void ClientSide::loadRefClientCertPubkey(const string &certFile,
    const string &caFile)
{
    LOG4CPLUS_DEBUG(logger, "Load expected public key"); // NOLINT

    // No point setting this if context is not initialized
    auto ptr = getSSLCtxPtr();
    ERR_clear_error();

    LOG4CPLUS_TRACE(logger, "Extract expected public key"); // NOLINT
    auto pubCert = loadCertFile(certFile);
    refClientPubKey = shared_ptr<EVP_PKEY>(
        X509_get_pubkey(pubCert.get()), &EVP_PKEY_free);
    if(!refClientPubKey)
    {
        const string msg = "Failed to extract expected client public key.";
        logSSLError(msg);
        throw runtime_error(msg);
    }

    LOG4CPLUS_TRACE(logger, "Set client cert verification callback"); // NOLINT
    SSL_CTX_set_verify(ptr, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
        &verifyCB);

    exDataIndex = SSL_CTX_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    if(exDataIndex == -1)
    {
        const string msg = "Failed to get verify callback data index.";
        logSSLError(msg);
        throw runtime_error(msg);
    }
        
    LOG4CPLUS_TRACE(logger, "Value of exDataIndex: " << exDataIndex); // NOLINT
    SSL_CTX_set_ex_data(ptr, exDataIndex, this);

    LOG4CPLUS_TRACE(logger, "Load client CA"); // NOLINT
    auto caCert = loadCertFile(caFile);
    if(!SSL_CTX_add_client_CA(ptr, caCert.get()))
    {
        const string msg = "Failed to add client CA.";
        logSSLError(msg);
        throw runtime_error(msg);
    }

    LOG4CPLUS_DEBUG(logger, "Expected client certificate loaded"); // NOLINT
}

void ClientSide::waitSocketReadable()
{
    fd_set readFd;
    FD_ZERO(&readFd);
    FD_SET(getSocket(), &readFd); // NOLINT

    if(wrapper->select(getSocket() + 1, &readFd, nullptr, nullptr, nullptr) > 0)
    {
        if(!FD_ISSET(getSocket(), &readFd)) // NOLINT
            throw logic_error("Socket FD not set after select returned ready");
        else
            LOG4CPLUS_DEBUG(logger, "Socket ready for reading"); // NOLINT
    }
    else
    {
        auto err = errno;
        throwSystemError(err, "Error encountered waiting for a client to connect");
    }
}

ClientSide::X509Mem ClientSide::loadCertFile(const string &fileName)
{
    LOG4CPLUS_TRACE(logger, "Open " << fileName); // NOLINT
    unique_ptr<FILE, decltype(&fclose)> f(
        fopen(fileName.c_str(), "rb"), &fclose);
    if(!f)
    {
        auto msg = string("Failed to open cert file ") + fileName;
        throwSystemError(errno, msg);
    }

    LOG4CPLUS_TRACE(logger, "Read " << fileName); // NOLINT
    unique_ptr<X509, decltype(&X509_free)> pubCert(
        PEM_read_X509(f.get(), nullptr, nullptr, nullptr), &X509_free);
    if(!pubCert)
    {
        const string msg = "Error encountered reading pubkey.";
        logSSLError(msg);
        throw runtime_error(msg);
    }

    LOG4CPLUS_DEBUG(logger, "Certificate in " << fileName << " loaded"); // NOLINT
    return pubCert;
}

int ClientSide::verifyCB(int preverifyOk, X509_STORE_CTX *x509Ctx)
{
    auto logger = log4cplus::Logger::getInstance("ClientSide");
    auto depth = X509_STORE_CTX_get_error_depth(x509Ctx);
    LOG4CPLUS_TRACE(logger, "Value of depth: " << depth); // NOLINT
    if(depth != 0)
    {
        LOG4CPLUS_DEBUG(logger, "Bypassing client cert verification"); // NOLINT
        return 1;
    }

    auto cert = X509_STORE_CTX_get_current_cert(x509Ctx);
    if(cert == nullptr)
    {
        LOG4CPLUS_DEBUG(logger, "Error not caused by a certificate"); // NOLINT
        return preverifyOk;
    }

    LOG4CPLUS_DEBUG(logger, "Verify peer certificate's public key"); // NOLINT
    auto ssl = static_cast<SSL *>(X509_STORE_CTX_get_ex_data(x509Ctx,
        SSL_get_ex_data_X509_STORE_CTX_idx()));
    auto sslCtx = SSL_get_SSL_CTX(ssl);

    auto obj = static_cast<ClientSide *>(SSL_CTX_get_ex_data(sslCtx,
        exDataIndex));
    if(obj == nullptr)
        throw logic_error("ClientSide object not available in SSL CTX ex data");

    auto rslt = EVP_PKEY_cmp(obj->refClientPubKey.get(), X509_get0_pubkey(cert));
    LOG4CPLUS_TRACE(logger, "Compare result: " << rslt); // NOLINT
    if(rslt != 1)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_INFO(logger,
            "Client-provided certificate public key doesn't match expected public key");
    }
    else
    {
        LOG4CPLUS_INFO(logger, "Received expected client public key"); // NOLINT
    }

    return (rslt == 1 ? 1 : 0);
}

thread_local int ClientSide::exDataIndex;

} // namespace tlslookieloo
