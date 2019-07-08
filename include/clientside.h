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
        SocketInfo(rhs)
    {}

    ClientSide(ClientSide &&rhs) :
        SocketInfo(rhs)
    {}

    ClientSide &operator =(ClientSide const &rhs)
    {
        SocketInfo::operator =(rhs);
        return *this;
    }

    ClientSide &operator =(ClientSide &&rhs)
    {
        SocketInfo::operator =(rhs);
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
    const bool startSSL(const std::string &certFile, const std::string &privKeyFile)
    {
        initializeSSLContext(certFile, privKeyFile);
        return sslHandshake();
    }

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ClientSide");

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
     * Wait for socket to be readable
     * \throws system_error if an error occurred during the select() operation
     */
    void waitSocketReadable();
};

} //namespace tlslookieloo
