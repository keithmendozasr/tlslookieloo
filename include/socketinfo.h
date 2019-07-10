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
#include <stdexcept>

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <log4cplus/logger.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "log4cplus/loggingmacros.h"

#include "gtest/gtest_prod.h"

#include "wrapper.h"

namespace tlslookieloo
{

/**
 * Class to manage sockets
 */
class SocketInfo
{
public:
    /**
     * Constructor
     */
    SocketInfo(std::shared_ptr<Wrapper> wrapper);
    /**
     * Copy constructor
     */
    SocketInfo(const SocketInfo &rhs);

    /**
     * Move constructor
     */
    SocketInfo(SocketInfo &&rhs);

    /**
     * Copy assignment operator
     */
    SocketInfo & operator = (SocketInfo const &rhs);

    /**
     * Move assignment operator
     */
    SocketInfo & operator = (SocketInfo &&rhs);

    /**
     * Destructor
     */
    virtual ~SocketInfo(){}

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
     * Get the network timeout to use for all operations
     *
     */
    inline unsigned int getTimeout() const
    {
        return timeout;
    }

    /**
     * Return the socket descriptor
     */
    inline const int &getSocket() const
    {
        if(!sockfd)
            throw std::logic_error("Socket not created");

        return *sockfd;
    }

    /**
     * Get the IP address the socket is connected to
     */
    inline const std::string getSocketIP() const
    {
        return socketIP.value();
    }

    /**
     * Get the address info associated to the socket
     */
    inline const addrinfo *getAddrInfo() const
    {
        if(sockAddr == nullptr)
            throw std::logic_error("No address associated to socket");
        return sockAddr;
    }

    /**
     * Operation status
     */
    enum OP_STATUS
    {
        INITIALIZED,    //< Variable is in an initialized state. Should never
                        //< be returned.
        SUCCESS,        //< See individual functions returning this enum
        DISCONNECTED,     //< Remote-side disconnected
        TIMEOUT,        //< Operation timed-out
        INTERRUPTED,    //< Signal received
    };

    /**
     * Attempt to read from remote-side.
     *
     * \throws std::invalid_argument data parameter is null
     * \param[out] data Buffer to place received data
     * \param[in,out] dataSize Available space for data. At function end, size
     *  of data placed in data, if reading is successful
     * \return read state. If value is not OP_STATUS::SUCCESS data and dataSize
     *  should be ignored.
     */
    // TODO: Change "data" param to weak_ptr
    const OP_STATUS readData(char *data, size_t &dataSize);

    /**
     * Attempt to send to client
     *
     * \param msg Data to send
     * \param msgSize Size of msg
     * \return State of sending operation
     */
    // TODO: Change "msg" param to weak_ptr
    const OP_STATUS writeData(const char *msg, const size_t &msgSize);

protected:
    /**
     * Resolve the host and port in preparation for connection
     *
     * \throws invalid_argument if port param not valid port number
     * \throws logic_error if socket instance already created
     * \param port Port number to use with socket connection
     * \param host Host to connect to as client, or host to listen from as
     *  server
     * \return true if the hostname and service is resolved. False otherwise
     */
    const bool resolveHostPort(const unsigned int &port, const std::string &host = "");

    /**
     * Initialize a socket connection for the next IP
     *
     * \throws range_error No more available IP's to try
     * \throws logic_error host/port resolution has not been completed yet
     * \throws runtime_error if unable to create socket instance
     */
     void initNextSocket();

    /**
     * Set the socket FD
     *
     * \arg fd New socket to set
     */
    inline void setSocket(const int &fd)
    {
        if(!sockfd)
        {
            LOG4CPLUS_TRACE(logger, "Allocating sockfd"); // NOLINT
            sockfd = std::shared_ptr<int>(new int, SockfdDeleter());
        }

        *sockfd = fd;
    }

    /**
     * Initialize and throw a system_error exception
     *
     * \arg err Error code
     * \arg msg Additional message to include in the system_object instance
     */
    inline void throwSystemError(const int &err, const std::string &msg = "")
    {
        if(msg == "")
            throw std::system_error(err, std::generic_category());
        else
            throw std::system_error(err, std::generic_category(), msg);
    }

    /**
     * Collect the SSL error message
     */
    const inline std::string sslErrMsg(const std::string &prefix)
    {
        auto code = ERR_get_error();
        auto txt = ERR_reason_error_string(code);
        return prefix + txt;
    }

    /**
     * Allocate a new SSL_CTX object
     */
    void newSSLCtx();

    /**
     * Get the raw SSL_CTX pointer
     */
    inline SSL_CTX *getSSLCtxPtr()
    {
        if(!sslCtx)
            throw std::logic_error("SSL Context not initialized");

        return sslCtx.get();
    }

    /**
     * Allocate a new SSL object
     */
    void newSSLObj();

    /**
     * Get the raw SSL pointer
     */
    inline SSL *getSSLPtr()
    {
        if(!sslObj)
            throw std::logic_error("SSL object not initialized");

        return sslObj.get();
    }

    /**
     * Log the SSL error stack
     */
    void logSSLErrorStack();

    /**
     * Save the socket IP information
     *
     * \arg addrInfo Address info to get the IP from
     */
    void saveSocketIP(const struct sockaddr_storage *addrInfo);

    std::shared_ptr<Wrapper> getWrapper()
    {
        return wrapper;
    }

    /**
     * Handle SSL conditions that requires a retry
     *
     * \arg rslt Error code returned by the last operation
     * \return true if the operation should be retried. False otherwise
     * \throw logic_error When an unexpected code was received
     *  from SSL_get_error
     */
    const OP_STATUS handleRetry(const int &rslt, const bool withTimeout = true);

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("SocketInfo");
    std::shared_ptr<Wrapper> wrapper;

    std::optional<std::string> socketIP;

    // Use shared_ptr on the sockfd holder to allow this class to be copyable
    // without having to implement the reference counters in this class
    struct SockfdDeleter
    {
        void operator()(int *ptr)
        {
            // NOLINTNEXTLINE
            if(ptr != nullptr)
            {
                log4cplus::Logger logger = log4cplus::Logger::getInstance("SocketInfo");
                LOG4CPLUS_DEBUG(logger, "Closing FD " << *ptr); // NOLINTEXTLINE
                shutdown(*ptr, SHUT_RDWR);
                close(*ptr);
                delete ptr; // NOLINT(cppcoreguidelines-owning-memory)
            }
        }
    };
    
    std::shared_ptr<int> sockfd = nullptr;

    std::shared_ptr<struct addrinfo> servInfo;
    struct addrinfo *sockAddr = nullptr;
    struct addrinfo *nextServ = nullptr;

    unsigned int timeout = 5;

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
    std::shared_ptr<SSL> sslObj;

    friend class SocketInfoTest;
    FRIEND_TEST(SocketInfoTest, handleRetryReady);
    FRIEND_TEST(SocketInfoTest, handleRetryTimeout);
    FRIEND_TEST(SocketInfoTest, handleRetrySetTimeout);
    FRIEND_TEST(SocketInfoTest, handleRetryInterrupted);
    FRIEND_TEST(SocketInfoTest, handleRetryError);
    FRIEND_TEST(SocketInfoTest, handleRetryNoTimeout);
    FRIEND_TEST(SocketInfoTest, handleRetryRemoteDisconnect);
    FRIEND_TEST(SocketInfoTest, handleRetryNoError);

    FRIEND_TEST(SocketInfoTest, readDataExact);
    FRIEND_TEST(SocketInfoTest, readDataShort);
    FRIEND_TEST(SocketInfoTest, readDataFail);
    FRIEND_TEST(SocketInfoTest, readDataNoData);

    FRIEND_TEST(SocketInfoTest, writeDataExact);
    FRIEND_TEST(SocketInfoTest, writeDataShort);
    FRIEND_TEST(SocketInfoTest, writeDataRemoteDisconnect);

    friend class ClientSideTest;

    friend class TargetTest;
    FRIEND_TEST(TargetTest, passClientToServerGood);
    FRIEND_TEST(TargetTest, passClientToServerNoData);
    FRIEND_TEST(TargetTest, passClientToServerRemoteDisconnect);
    FRIEND_TEST(TargetTest, waitForReadableTimeout);
    FRIEND_TEST(TargetTest, waitForReadableClient);
    FRIEND_TEST(TargetTest, waitForReadableServer);
    FRIEND_TEST(TargetTest, waitForReadableInterrupted);
    FRIEND_TEST(TargetTest, waitForReadableError);
};

} //namespace tlslookieloo
