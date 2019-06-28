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

namespace tlslookieloo
{

class Target
{
public:
    explicit Target(){}

    Target(const std::string &tgtName, const std::string &serverHost,
        const unsigned int serverPort, const unsigned int clientPort,
        const std::string &clientCert, const std::string &clientKey);

    Target(const Target &rhs);

    Target & operator = (const Target &rhs);

    Target(Target && rhs);

    Target & operator = (Target && rhs);

    void start();

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

    ServerSide server;
    ClientSide client;

    std::atomic_bool keepRunning = true;

    void handleClient(ClientSide client);

};

} // namespace tlslookieloo
