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

#include <log4cplus/logger.h>

#include "socketinfo.h"

namespace tlslookieloo
{

class ClientSocket : public SocketInfo
{
public:
    /**
     * Default constructor
     **/
    void connect(const unsigned int &port, const std::string &host);

private:
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ClientSocket");

    /**
     * Wait for connect() call to complete
     */
    bool waitForConnect();
};

} //namespace tlslookieloo
