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

#include <cstring>

#include <sys/socket.h>

#include <log4cplus/loggingmacros.h>

#include "socketinfo.h"
#include "serverside.h"

using namespace std;

namespace tlslookieloo
{

const bool ServerSide::connect(const unsigned int &port, const string &host)
{
    LOG4CPLUS_DEBUG(logger, "Start socket connection");
    if(sockConnect(port,  host))
    {
        LOG4CPLUS_DEBUG(logger,
            "Socket connection successful. Start TLS handshake");
    }
    else
    {
        LOG4CPLUS_ERROR(logger, "Failed to connect to " << host << ":" << port);
        return false;
    }

    LOG4CPLUS_INFO(logger, "Connection to " << host << ":" << port <<
        " successful");

    return true;
}

bool ServerSide::waitForConnect()
{
    bool retVal = true;
    if(!waitForWriting(3))
    {
        LOG4CPLUS_INFO(logger, "Connection timed out");
        retVal = false;
    }
    else
    {
        LOG4CPLUS_DEBUG(logger, "Connection ready");

        int val;
        socklen_t len = sizeof(val);
        auto err = getsockopt(getSocket(), SOL_SOCKET, SO_ERROR, &val, &len);
        const string ip = getSocketIP();
        if(err != 0)
            throwSystemError(err, "getsockopt error");

        LOG4CPLUS_TRACE(logger, "Got socket option");
        if(val == 0)
            LOG4CPLUS_DEBUG(logger, "Connected to " << ip << " after waiting");
        else
        {
            LOG4CPLUS_DEBUG(logger, "Failed to connect to " << ip <<
                " after waiting. Try next IP if available");
            retVal = false;
        }
    }

    return retVal;
}

const bool ServerSide::sockConnect(const unsigned int &port, const string &host)
{
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ServerSide");
    bool retVal = true;
    try
    {
        if(resolveHostPort(port, host))
        {
            string ip;
            do
            {
                struct sockaddr_storage addr;
                try
                {
                    initNextSocket();
                    addr = getAddrInfo();
                    ip = getSocketIP();
                    if(::connect(getSocket(), reinterpret_cast<struct sockaddr *>(&addr),
                        getAddrInfoSize()) != 0)
                    {
                        auto err = errno;
                        if(err == EINPROGRESS)
                        {
                            if(waitForConnect())
                            {
                                LOG4CPLUS_DEBUG(logger, "Connected after wait");
                                break;
                            }
                            else
                                LOG4CPLUS_DEBUG(logger,
                                    "Connect failed after wait. Try next IP");
                        }
                        else
                        {
                            char buf[256];
                            char *errmsg = strerror_r(err, buf, 256);
                            LOG4CPLUS_DEBUG(logger,
                                "Failed to connect to IP " << ip <<
                                ". Error message: " << errmsg << ". Try next IP");
                        }
                    }
                    else
                    {
                        LOG4CPLUS_DEBUG(logger, "Connected to IP " << ip);
                        break;
                    }
                }
                catch(const range_error &e)
                {
                    LOG4CPLUS_DEBUG(logger, "Unable to connect to host");
                    retVal = false;
                    break;
                }

                // If it gets here closed the previously-opened socket for the next
                // try
                closeSocket();
            }while(1);
        }
        else
        {
            LOG4CPLUS_DEBUG(logger, "Failed to resolve " << host << ":" << port);
            retVal = false;
        }
    }
    catch(system_error &e)
    {
        LOG4CPLUS_ERROR(logger, "System error encountered connecting to remote. " <<
            e.what());
        throw;
    }

    return retVal;
}

} // namespace tlslookieloo
