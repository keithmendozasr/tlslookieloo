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

#include "socketinfo.h"
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
     * Default constructor
     */
    explicit Target(){}

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
        const std::string &clientCert, const std::string &clientKey);

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
    std::string tgtName, serverHost, clientCert, clientKey;
    unsigned int serverPort = 0;
    unsigned int clientPort = 0;

    std::atomic_bool keepRunning = true;

    /**
     * Bridge message from server to client
     */
    bool passClientToServer(ClientSide &client, ServerSide &server);

    /**
     * Handle clientside connection and message processing
     * \arg client ClientSide object containing the client connection info
     */
    void handleClient(ClientSide client);

    friend class TargetTest;
    FRIEND_TEST(TargetTest, passClientToServerGood);
    FRIEND_TEST(TargetTest, passClientToServerNoData);
    FRIEND_TEST(TargetTest, passClientToServerRemoteDisconnect);

};

} // namespace tlslookieloo
