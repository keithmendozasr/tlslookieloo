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
#include <vector>
#include <mutex>
#include <optional>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

#include "concretewrapper.h"
#include "serverside.h"
#include "clientside.h"
#include "targetitem.h"

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
     * \arg targetInfo TargetInfo for this instance
     */
    Target(const TargetItem &);

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
     * Destructor
     */
    virtual ~Target(){}

    /**
     * Start listening for client-side
     */
    void start();

    /**
     * Stop processing client request
     */
    static void stop()
    {
        auto logger = log4cplus::Logger::getInstance("Target");
        LOG4CPLUS_INFO(logger, "Stopping target handling"); // NOLINT
        keepRunning = false;
    }

protected:
    enum MSGOWNER
    {
        CLIENT,
        SERVER
    };

    /**
     * Relay message between 2 sides
     */
    bool messageRelay(SocketInfo &src, SocketInfo &dest, const Target::MSGOWNER owner);

    enum READREADYSTATE
    {
        CLIENT_READY,
        SERVER_READY,
    };

    /**
     * Wait for either socket to have data for reading
     *
     * \arg client ClientSide object
     * \arg server ServerSide object
     */
    std::vector<READREADYSTATE> waitForReadable(ClientSide &client, ServerSide &server);

    /**
     * Log the data received with indicator of origin
     *
     * \arg data char pointer to the data to store
     * \arg len Length of data
     * \arg owner Which side sent the message
     */
    void storeMessage(const char *data, const size_t &len,
        const MSGOWNER & owner);

    /**
     * Set the target's timeout
     * \arg t Timeout value
     */
    inline void setTimeout(const unsigned int &t)
    {
        timeout = t;
    }

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("Target");
    TargetItem tgtItem;
    std::shared_ptr<Wrapper> wrapper;
    std::optional<unsigned int> timeout;
    static std::atomic_bool keepRunning;
    std::ofstream recordFileStream;
    std::mutex tmGuard;

    std::optional<MSGOWNER> lastMsgOwner;

    /**
     * Handle clientside connection and message processing
     * \arg client ClientSide object containing the client connection info
     */
    void handleClient(ClientSide &client);
};

} // namespace tlslookieloo
