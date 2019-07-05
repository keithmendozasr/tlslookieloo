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
#include <atomic>
#include <fstream>

#include "concretewrapper.h"
#include "serverside.h"
#include "clientside.h"

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

#include "gtest/gtest_prod.h"

namespace tlslookieloo
{

class Target
{
public:
    /**
     * "Default" constructor
     *
     * \arg wrapper Wrapper instance
     */
    Target(std::shared_ptr<Wrapper> wrapper =
        std::make_shared<ConcreteWrapper>()) :
        wrapper(wrapper)
    {}

    /**
     * Constructor that takes the target information.
     *
     * \arg tgtName Target name to use in logs
     * \arg serverHost Hostname of server-side
     * \arg serverPort Port server-side is listening on
     * \arg clientPort Port to listen for client-side
     * \arg clientCert SSL public key for client-side listener
     * \arg clientKey Private key for client-side listener
     */
    Target(const std::string &tgtName, const std::string &serverHost,
        const unsigned int serverPort, const unsigned int clientPort,
        const std::string &clientCert, const std::string &clientKey,
        const std::string &msgFileName);

    /**
     * Copy constructor
     */
    Target(const Target &rhs);

    /**
     * Copy assignment operator
     */
    Target & operator = (const Target &rhs);

    /**
     * Move constructor
     */
    Target(Target && rhs);

    /**
     * Move assignment operator
     */
    Target & operator = (Target && rhs);

    /**
     * Start listening for client-side
     */
    void start();

    /**
     * Stop processing client request
     */
    void stop()
    {
        LOG4CPLUS_INFO(logger, "Stopping " << tgtName << " target handling");
        keepRunning = false;
    }

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("Target");
    std::string tgtName, serverHost, clientCert, clientKey, msgFileName;
    unsigned int serverPort = 0;
    unsigned int clientPort = 0;
    std::shared_ptr<Wrapper> wrapper;
    int timeout = 5;

    std::atomic_bool keepRunning = true;

    std::ofstream msgFile;

    /**
     * Bridge message from client to server
     */
    bool passClientToServer(ClientSide &client, ServerSide &server);

    /**
     * Bridge message from server to client
     */
    bool passServerToClient(ClientSide &client, ServerSide &server);

    /**
     * Handle clientside connection and message processing
     * \arg client ClientSide object containing the client connection info
     */
    void handleClient(ClientSide client);

    FRIEND_TEST(TargetTest, passClientToServerGood);
    FRIEND_TEST(TargetTest, passClientToServerNoData);
    FRIEND_TEST(TargetTest, passClientToServerRemoteDisconnect);

    enum READREADYSTATE
    {
        CLIENT_READY,
        SERVER_READY,
        TIMEOUT,
        SIGNAL
    };

    /**
     * Wait for either socket to have data for reading
     *
     * \arg client ClientSide object
     * \arg server ServerSide object
     */
    READREADYSTATE waitForReadable(ClientSide &client, ServerSide &server);

    enum MSGOWNER
    {
        CLIENT,
        SERVER
    };

    /**
     * Log the data received with indicator of origin
     *
     * \arg data char pointer to the data to store
     * \arg len Length of data
     * \arg owner Which side sent the message
     */
    void storeMessage(const char *data, const size_t &len,
        const MSGOWNER & owner);

    FRIEND_TEST(TargetTest, waitForReadableTimeout);
    FRIEND_TEST(TargetTest, waitForReadableClient);
    FRIEND_TEST(TargetTest, waitForReadableServer);
    FRIEND_TEST(TargetTest, waitForReadableInterrupted);
    FRIEND_TEST(TargetTest, waitForReadableError);

    FRIEND_TEST(TargetTest, storeMessageClient);
    FRIEND_TEST(TargetTest, storeMessageServer);
    FRIEND_TEST(TargetTest, storeMessageBinary);
    FRIEND_TEST(TargetTest, storeMessageNullPtr);
};

} // namespace tlslookieloo
