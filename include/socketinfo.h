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

#include <stdexcept>
#include <system_error>
#include <string>
#include <memory>

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <log4cplus/logger.h>

namespace tlslookieloo
{

/**
 * Class to manage sockets
 */
class SocketInfo
{
public:
    /**
     * Default constructor
     */
    explicit SocketInfo();

    virtual ~SocketInfo()
    {
        closeSocket();
    }

    /**
     * Return the socket descriptor
     */
    inline const int &getSocket() const
    {
        if(sockfd == -1)
            throw std::logic_error("Socket not created");

        return sockfd;
    }

    /**
     * Close the socket connection
     */
    inline void closeSocket()
    {
        if(sockfd != -1)
        {
            shutdown(sockfd, SHUT_RDWR);
            close(sockfd);
            sockfd = -1;
        }
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
    const bool waitForReading(const unsigned int timeout = 0);

    /**
     * Attempt to read from client.
     *
     * \throws std::invalid_argument data parameter is null
     * \param data Buffer to place received data
     * \param dataSize Size of data
     * \return Number of bytes received
     */
    const size_t readData(char *data, const size_t &dataSize);

    /**
     * Wait for socket to be ready for writing
     *
     * \throws std::system_error Error encountered while waiting for socket to
     *  be ready to send message
     * \param timeout Number of seconds to wait for socket to be writable. 0
     *  for no timeout
     * \return true if the socket is ready for writing before timeout expires
     */
    const bool waitForWriting(const unsigned int timeout = 0);

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

private:
    log4cplus::Logger logger;
    struct sockaddr_storage addrInfo;
    size_t addrInfoSize;
    int sockfd;

    std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> servInfo;
    struct addrinfo *nextServ = nullptr;
};

} //namespace tlslookieloo
