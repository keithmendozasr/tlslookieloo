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

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <log4cplus/logger.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

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
    explicit SocketInfo();

    /**
     * Copy constructor
     */
    SocketInfo(const SocketInfo &rhs);


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
    const std::string getSocketIP() const;
    
    /**
     * Access the sockaddr_storage structure associated with the socket connection
     */
    inline const struct sockaddr_storage &getAddrInfo() const
    {
        return addrInfo;
    }

    /**
     * Get the address info structure's size
     */
    inline const size_t &getAddrInfoSize() const
    {
        return addrInfoSize;
    }

    /**
     * Wait for data to be available for reading
     *
     * \throws std::system_error Error encountered while waiting for message to
     *  arrive
     * \param timeout Number of seconds to wait for data. 0 for no timeout
     * \return true if the socket is ready for reading before timeout expires
     */
    const bool waitForReading(const bool &withTimeout = true);

    /**
     * Attempt to read from client.
     *
     * \throws std::invalid_argument data parameter is null
     * \param data Buffer to place received data
     * \param dataSize Size of data
     * \return Number of bytes received
     */
    std::optional<const size_t> readData(char *data, const size_t &dataSize);

    /**
     * Wait for socket to be ready for writing
     *
     * \throws std::system_error Error encountered while waiting for socket to
     *  be ready to send message
     * \param timeout Number of seconds to wait for socket to be writable. 0
     *  for no timeout
     * \return true if the socket is ready for writing before timeout expires
     */
    const bool waitForWriting(const bool &withTimeout = true);

    /**
     * Attempt to send to client
     *
     * \param msg Data to send
     * \param msgSize Size of msg
     * \return Number of bytes sent
     */
    const size_t writeData(const char *msg, const size_t &msgSize);

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
     * Set the sockaddr_storage structure to associate to this class' instance
     *
     * \param addr Pointer to sockaddr_storage to asssociate
     */
    void setAddrInfo(const sockaddr_storage *addr, const size_t &addrSize);

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
     * Handle SSL conditions that requires a retry
     *
     * \arg rslt Error code returned by the last operation
     * \return true if the operation should be retried. False otherwise
     * \throw logic_error When an unexpected code was received
     *  from SSL_get_error
     */
    const bool handleRetry(const int &rslt);

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("SocketInfo");
    struct sockaddr_storage addrInfo;
    size_t addrInfoSize;

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

    // Delete unneeded constructors/operators
    SocketInfo(SocketInfo &&) = delete;
    SocketInfo & operator = (SocketInfo const &) = delete;
    SocketInfo & operator = (SocketInfo &&) = delete;
};

} //namespace tlslookieloo
