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

class ServerSide : public SocketInfo
{
public:
    /**
     * Default constructor
     */
    explicit ServerSide(){}

    /**
     * Move constructor
     */
    ServerSide(ServerSide &&rhs) :
        SocketInfo(std::move(rhs))
    {}

    /**
     * Move assignment operator
     */
    ServerSide &operator =(ServerSide && rhs)
    {
        SocketInfo::operator =(std::move(rhs));

        return *this;
    }

    /**
     * Destructor
     */
    virtual ~ServerSide() {}

    /**
     * \brief TLS connection to server side
     *
     * Connect to the remote TLS server-end of the system under test. Connection
     * failure can be caused by failing to connect to the remote port, or a
     * failure during the TLS handshake.
     *
     * \arg port Server port to connect to
     * \arg host Server host to connect to
     * \return true if the tls connection was successful. False otherwise
     **/
    const bool connect(const unsigned int &port, const std::string &host);

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ServerSide");

    /**
     * Wait for connect() call to complete
     */
    bool waitForConnect();

    /**
     * Do TCP socket connection to remote end
     *
     * \seee ServerSide::connect() for parameter and return info
     */
    const bool sockConnect(const unsigned int &port, const std::string &host);

    /**
     * Create the socket context for this instance
     */
    void initializeSSLContext();

    /**
     * Go through the SSL handshake
     *
     * \param host Expected hostname to connect to
     */
    const bool sslHandshake(const std::string &host);

    // Deleted constructors/operators
    ServerSide(const ServerSide &) = delete;
    ServerSide(ServerSide &) = delete;
    ServerSide &operator = (const ServerSide &) = delete;
    ServerSide &operator = (ServerSide &) = delete;
};

} //namespace tlslookieloo
