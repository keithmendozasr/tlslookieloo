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

#include "clientsocket.h"
#include "timeoutexception.h"

using namespace std;

namespace tlslookieloo
{

bool ClientSocket::waitForConnect()
{
    waitForWriting(3);
    int val;
    socklen_t len = sizeof(val);
    auto err = getsockopt(getSocket(), SOL_SOCKET, SO_ERROR, &val, &len);
    if(err != 0)
    {
        char buf[256];
        char *errmsg = strerror_r(err, buf, 256);
        string msg("getsockopt error. Cause: ");
        msg += errmsg;
        LOG4CPLUS_ERROR(logger, msg);
        throw logic_error(msg);
    }

    if(val == 0)
        LOG4CPLUS_INFO(logger, "Connected to " << getSocketIP());
    else
    {
        LOG4CPLUS_INFO(logger, "Failed to connect to " << getSocketIP() <<
            ". Try next IP if available");
        return false;
    }

    return true;
}

void ClientSocket::connect(const unsigned int &port, const string &host)
{
    log4cplus::Logger logger = log4cplus::Logger::getInstance("ClientSocket");
    try
    {
        resolveHostPort(port, host);
    }
    catch(system_error &e)
    {
        string msg("Error encountered connecting to server. Cause: ");
        msg += e.what();
        LOG4CPLUS_ERROR(logger, msg);
        throw;
    }
    catch(runtime_error &e)
    {
        string msg("Host/port resolution failed. Cause: ");
        msg += e.what();
        LOG4CPLUS_ERROR(logger, msg);
        throw;
    }

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
                    LOG4CPLUS_ERROR(logger,
                        "Failed to connect to IP " << ip <<
                        ". Error message: " << errmsg);
                }
            }
            else
            {
                LOG4CPLUS_DEBUG(logger, "Connection successful");
                break;
            }
        }
        catch(system_error &e)
        {
            LOG4CPLUS_ERROR(logger,
                "Error encountered connecting to IP " << ip << ". Cause: " <<
                e.what());
        }
        catch(TimeoutException &e)
        {
            LOG4CPLUS_ERROR(logger,
                "Timed-out attempting to connect to IP " << ip <<
                ". Try next IP");
        }
        closeSocket();
    }while(1);

    LOG4CPLUS_INFO(logger, "Connected to IP " << ip);
}

} // namespace tlslookieloo
