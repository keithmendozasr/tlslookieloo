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
#include <optional>

#include <log4cplus/logger.h>

#include "socketinfo.h"
#include "wrapper.h"
#include "concretewrapper.h"

namespace tlslookieloo
{

class ClientSide : public SocketInfo
{
public:
    /**
     * Constructor taking Wrapper
     */
    ClientSide(std::shared_ptr<Wrapper> wrapper =
        std::make_shared<ConcreteWrapper>()) :
        SocketInfo(wrapper)
    {}

    /**
     * Copy constructor
     */
    ClientSide(const ClientSide &rhs) :
        SocketInfo(rhs),
        refClientPubKey(rhs.refClientPubKey)
    {}

    ClientSide(ClientSide &&rhs) :
        SocketInfo(std::move(rhs)),
        refClientPubKey(std::move(rhs.refClientPubKey))
    {}

    ClientSide &operator =(ClientSide const &rhs)
    {
        refClientPubKey = rhs.refClientPubKey;
        SocketInfo::operator =(rhs);
        return *this;
    }

    ClientSide &operator =(ClientSide &&rhs)
    {
        refClientPubKey = std::move(rhs.refClientPubKey);
        SocketInfo::operator =(std::move(rhs));
        return *this;
    }

    /**
     * Destructor
     */
    virtual ~ClientSide() {}

    /**
     * \brief Start server listener
     *
     * Start listening on the port provided in the port parameter.
     *
     * \arg port Port to listen for clients on
     * \arg backlog Listener backlog
     **/
    void startListener(const unsigned int &port,
        const unsigned int &backlog);

    /**
     * Accept connection
     */
    std::optional<ClientSide> acceptClient();
    
    /**
     * Create the SSL context for this instance
     *
     * \arg certFile Path to the certificate file
     * \arg privKeyFile Path to the separate private key file if not
     *  in certFile
     */
    void initializeSSLContext(const std::string &certFile, const std::string &privKeyFile);

    /**
     * Go through the SSL handshake
     */
    const bool sslHandshake();

    /**
     * Load the public key to expect from the client
     *
     * If the received client cert doesn't match the reference public key
     * certificate the handshake should be considered failed.
     *
     * \param certFile Reference client certificate file
     * \param caFile Client CA file
     */
    void loadRefClientCertPubkey(const std::string &certFile,
        const std::string &caFile);

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ClientSide");
    std::shared_ptr<EVP_PKEY> refClientPubKey;
    static int exDataIndex;

    /**
     * Wait for socket to be readable
     * \throws system_error if an error occurred during the select() operation
     */
    void waitSocketReadable();

    typedef std::unique_ptr<X509, decltype(&X509_free)> X509Mem;

    /**
     * Read a certificate file
     *
     * \param fileName File name of certificate file
     * \return unique_ptr<X509> of the read certificate
     */
    X509Mem loadCertFile(const std::string &fileName);

    /**
     * Client certificate verify callback. If an expected client certificate is
     * set, verify that the peer certificate sent by the remote client contains
     * the expected public key. This largely ignores the certificate
     * verification results.
     *
     * \return 1 if the remote client sent the expected peer public key; or for
     * other certificates in the chain. Returns 0 otherwise.
     */
    static int verifyCB(int preverifyOk, X509_STORE_CTX *x509Ctx);

    FRIEND_TEST(ClientSideTest, waitSocketReadableGood);
    FRIEND_TEST(ClientSideTest, waitSocketReadableError);
    FRIEND_TEST(ClientSideTest, loadCertFileGood);
    FRIEND_TEST(ClientSideTest, loadCertFileOpenFailed);
    FRIEND_TEST(ClientSideTest, loadCertFileWrongFormat);
    FRIEND_TEST(ClientSideTest, loadRefClientCertPubkey);
};

} //namespace tlslookieloo
