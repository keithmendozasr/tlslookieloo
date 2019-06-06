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

#include <log4cplus/logger.h>

#include <openssl/ssl.h>

#include "socketinfo.h"

namespace tlslookieloo
{

class ServerSide : public SocketInfo
{
public:
    ServerSide() :
        sslCtx(nullptr, &SSL_CTX_free)
    {}

    ServerSide(ServerSide &&rhs) :
        logger(std::move(rhs.logger)),
        sslCtx(std::move(rhs.sslCtx)),
        sslObj(std::move(rhs.sslObj)),
        timeout(std::move(rhs.timeout))
    {}

    virtual ~ServerSide() {}

    /**
     * Set the network timeout to use for all operations
     *
     * \param time new timeout
     */
    inline void setTimeout(const unsigned int &time)
    {
        timeout = time;
    }

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

    /**
     * Read data from server
     *
     * \see SocketInfo::readData
     */
    const size_t readData(char *data, const size_t &dataSize)
    {
        return 0;
    }

    /**
     * Write data to server
     *
     * \see SocketInfo::writeData
     */
    const size_t writeData(const char *msg, const size_t &msgSize);

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ServerSide");
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> sslCtx;

    struct SSLDeleter {
        void operator()(SSL * ptr)
        {
            if(ptr)
            {
                SSL_shutdown(ptr);
                SSL_free(ptr);
            }
        }
    };
    std::unique_ptr<SSL, SSLDeleter> sslObj;

    ServerSide(const ServerSide &) = delete;

    unsigned int timeout = 5;

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
     * Collect the SSL error message
     */
    const std::string sslErrMsg(const std::string &prefix);

    /**
     * Create the socket context for this instance
     */
    void initializeSSLContext();

    /**
     * Handle SSL conditions that requires a retry
     *
     * \arg rslt Error code returned by the last operation
     * \return true if the operation should be retried. False otherwise
     * \throw logic_error When an unexpected code was received
     *  from SSL_get_error
     */
    const bool handleRetry(const int &rslt);

    /**
     * Go through the SSL handshake
     *
     * \param host Expected hostname to connect to
     */
    const bool sslHandshake(const std::string &host);

};

} //namespace tlslookieloo
