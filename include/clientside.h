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
#include <memory>
#include <optional>

#include <log4cplus/logger.h>

#include "socketinfo.h"

namespace tlslookieloo
{

class ClientSide : public SocketInfo
{
public:
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
};

} //namespace tlslookieloo
