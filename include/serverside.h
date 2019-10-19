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

#pragma once

#include <string>
#include <tuple>
#include <optional>

#include "log4cplus/logger.h"

#include "socketinfo.h"
#include "wrapper.h"
#include "concretewrapper.h"


namespace tlslookieloo
{

class ServerSide : public SocketInfo
{
public:
    /**
     * Constructor taking Wrapper
     */
    ServerSide(std::shared_ptr<Wrapper> wrapper =
        std::make_shared<ConcreteWrapper>()) :
        SocketInfo(wrapper)
    {}

    /**
     * Copy constructor
     */
    ServerSide(const ServerSide &rhs) :
        SocketInfo(rhs)
    {}

    ServerSide(ServerSide &&rhs) :
        SocketInfo(std::move(rhs))
    {}

    ServerSide &operator = (ServerSide const &rhs)
    {
        SocketInfo::operator =(rhs);
        return *this;
    }

    ServerSide &operator = (ServerSide &&rhs)
    {
        SocketInfo::operator =(std::move(rhs));
        return *this;
    }

    /**
     * Destructor
     */
    virtual ~ServerSide() {}

    typedef std::optional<std::tuple<std::string, std::string>> ClientCertInfo;

    /**
     * \brief TLS connection to server side
     *
     * Connect to the remote TLS server-end of the system under test. Connection
     * failure can be caused by failing to connect to the remote port, or a
     * failure during the TLS handshake.
     *
     * \param[in] port Server port to connect to
     * \param[in] host Server host to connect to
     * \param[in] clientCert Client authentication certificate
     * \param[in] allowInsecure If true, contine with handshake when TLS peer
     *  verification fails.
     * \param[in] serverCACertFile If provided, use the certificates in the
     *  chain file to verify the peer. Otherwise, CAs in the default cert store
     *  will be used.
     * \return true if the tls connection was successful. False otherwise
     **/
    const bool connect(const unsigned int &port, const std::string &host,
        ClientCertInfo clientCert, const bool allowInsecure,
        const std::optional<const std::string> serverCACertFile);

    /**
     * Wait for connect() call to complete
     **/
    bool waitForConnect();

    /**
     * Do TCP socket connection to remote end
     *
     * \seee ServerSide::connect() for parameter and return info
     **/
    const bool sockConnect(const unsigned int &port, const std::string &host);

    /**
     * Wait for socket to be writable
     * \throws system_error if an error occurred during the select() operation
     * \return true if socket is writable. False if it times out
     **/
    const bool socketReady();

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ServerSide");

    /**
     * Create the socket context for this instance
     * \param[in] serverCAChainFile Path to CA chain file, if provided
     **/
    void initializeSSLContext(
        const std::optional<const std::string> &serverCAChainFle);

    /**
     * Go through the SSL handshake
     *
     * \param host Expected hostname to connect to
     * \param clientCert tuple of client key files, if server expects client certs
     * \param allowInsecure Allow "insecure" TLS connection
     **/
    const bool sslHandshake(const std::string &host, ClientCertInfo clientCert,
        const bool allowInsecure);

    /**
     * Load client-side certificate.
     *
     * \param clientCertFile Path to the client certificate public key file
     * \param clientPrivateKeyFile Path to the client private key file
     **/
    void loadClientCertificate(const std::string &clientCertFile,
        const std::string &clientPrivateKeyFile);
};

} //namespace tlslookieloo
