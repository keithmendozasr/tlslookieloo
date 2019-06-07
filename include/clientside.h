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

#include <openssl/ssl.h>

#include "socketinfo.h"

namespace tlslookieloo
{

class ClientSide : public SocketInfo
{
public:
    ClientSide() :
        sslCtx(nullptr, &SSL_CTX_free)
    {}

    ClientSide(ClientSide &&rhs) :
        SocketInfo(std::move(rhs)),
        logger(std::move(rhs.logger)),
        sslCtx(std::move(rhs.sslCtx)),
        sslObj(std::move(rhs.sslObj)),
        timeout(std::move(rhs.timeout))
    {}

    virtual ~ClientSide() {}

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
    ClientSide acceptClient();
    
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

    /**
     * Read data from server
     *
     * \see SocketInfo::readData
     */
    std::optional<const size_t> readData(char *data, const size_t &dataSize);

    /**
     * Write data to server
     *
     * \see SocketInfo::writeData
     */
    const size_t writeData(const char *msg, const size_t &msgSize);

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ClientSide");
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

    ClientSide(const ClientSide &) = delete;

    unsigned int timeout = 5;

    /**
     * Collect the SSL error message
     */
    const std::string sslErrMsg(const std::string &prefix);

    /**
     * Create the SSL context for this instance
     *
     * \arg certFile Path to the certificate file
     * \arg privKeyFile Path to the separate private key file if not
     *  in certFile
     */
    void initializeSSLContext(const std::string &certFile, const std::string &privKeyFile);

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
     */
    const bool sslHandshake();
};

} //namespace tlslookieloo
