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

#include <stdexcept>
#include <vector>
#include <cstring>

#include "log4cplus/loggingmacros.h"
#include "log4cplus/ndc.h"

#include "target.h"

using namespace std;

namespace tlslookieloo
{

Target::Target(
    const std::string &tgtName, const std::string &serverHost,
    const unsigned int serverPort, const unsigned int clientPort,
    const std::string &clientCert, const std::string &clientKey) :
    tgtName(tgtName),
    serverHost(serverHost),
    clientCert(clientCert),
    clientKey(clientKey),
    serverPort(serverPort),
    clientPort(clientPort),
    wrapper(make_shared<ConcreteWrapper>())
{}

Target::Target(const Target &rhs) :
    logger(log4cplus::Logger::getInstance("Target")),
    tgtName(rhs.tgtName),
    serverHost(rhs.serverHost),
    clientCert(rhs.clientCert),
    clientKey(rhs.clientKey),
    serverPort(rhs.serverPort),
    clientPort(rhs.clientPort),
    wrapper(rhs.wrapper)
{}

Target & Target::operator = (const Target &rhs)
{
    tgtName = rhs.tgtName;
    serverHost = rhs.serverHost;
    clientCert = rhs.clientCert;
    clientKey = rhs.clientKey;
    serverPort = rhs.serverPort;
    clientPort = rhs.clientPort;
    wrapper = rhs.wrapper;

    return *this;
}

Target::Target(Target && rhs) :
    logger(log4cplus::Logger::getInstance("Target")),
    tgtName(std::move(rhs.tgtName)),
    serverHost(std::move(rhs.serverHost)),
    clientCert(std::move(rhs.clientCert)),
    clientKey(std::move(rhs.clientKey)),
    serverPort(std::move(rhs.serverPort)),
    clientPort(std::move(rhs.clientPort)),
    wrapper(std::move(rhs.wrapper))
{}

Target & Target::operator = (Target && rhs)
{
    tgtName = std::move(rhs.tgtName);
    serverHost = std::move(rhs.serverHost);
    clientCert = std::move(rhs.clientCert);
    clientKey = std::move(rhs.clientKey);
    serverPort = std::move(rhs.serverPort);
    clientPort = std::move(rhs.clientPort);
    wrapper = std::move(rhs.wrapper);

    return *this;
}

void Target::start()
{
    log4cplus::NDCContextCreator ndc(tgtName);

    ClientSide clientListener(wrapper);
    clientListener.startListener(clientPort, 2);
    // NOLINTNEXTLINE
    LOG4CPLUS_INFO(logger, "Listening on " << clientPort);

    while(keepRunning)
    {
        LOG4CPLUS_DEBUG(logger, "Wait for clientside connection");
        auto acceptRslt = clientListener.acceptClient();
        if(!acceptRslt)
        {
            LOG4CPLUS_INFO(logger, "Client accepting issue"); // NOLINT
            break;
        }
        else
            LOG4CPLUS_INFO(logger, "Clientside connected");

        handleClient(acceptRslt.value());
    }

    LOG4CPLUS_INFO(logger, "Target " << tgtName << " stopping");
}

bool Target::passClientToServer(ClientSide &client, ServerSide &server)
{
    bool retVal = false;
    char buf[1024];
    auto readLen = client.readData(&buf[0], 1024);
    if(readLen)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_TRACE(logger, "readLen: " << readLen.value());
        if(readLen.value() > 0)
        {
            LOG4CPLUS_INFO(logger, "Data from client: " << // NOLINT
                string(buf, readLen.value()));
            LOG4CPLUS_DEBUG(logger, "Send data to server");
            retVal = server.writeData(&buf[0], readLen.value());
        }
        else
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger, "No data received from remote end");
        }
    }
    else
        LOG4CPLUS_DEBUG(logger, "No data received from clientside");

    return retVal;
}

void Target::handleClient(ClientSide client)
{
    LOG4CPLUS_INFO(logger, "Start monitoring");

    if(!client.startSSL(clientCert, clientKey))
    {
        LOG4CPLUS_INFO(logger, "SSL handshake failed");
        return;
    }

    ServerSide server;
    if(!server.connect(serverPort, serverHost))
    {
        LOG4CPLUS_INFO(logger, "Failed to connect to server " <<
            serverHost << ":" << serverPort);
        return;
    }

    try
    {
        while(keepRunning)
        {
            auto readable = waitForReadable(client, server);
            LOG4CPLUS_TRACE(logger, "Value of readable: " << readable);
            if(readable == CLIENT_READY)
            {
                LOG4CPLUS_DEBUG(logger, "Client ready for reading");
                if(passClientToServer(client, server))
                    LOG4CPLUS_DEBUG(logger, "Message sent from client to server");
                else
                {
                    LOG4CPLUS_INFO(logger, "Client went away"); // NOLINT
                    break;
                }
            }
            else if(readable == TIMEOUT)
            {
                LOG4CPLUS_INFO(logger, "Timed-out waiting for message");
                break;
            }
            else if(readable == SIGNAL)
            {
                LOG4CPLUS_DEBUG(logger,
                    "Received signal while waiting for readable FD");
            }
            else
                throw logic_error("Unexpected readable value");
        } // while(keepReading)
    }
    catch(const system_error &e)
    {
        LOG4CPLUS_ERROR(logger, "Error encountered handling client. Cause: "
            << e.what());
    }

    LOG4CPLUS_INFO(logger, "Exiting");
}

Target::READREADYSTATE Target::waitForReadable(ClientSide &client, ServerSide &server)
{
    READREADYSTATE retVal;

    vector<int> socketList = {
        client.getSocket(),
        server.getSocket()
    };

    fd_set readFd;
    FD_ZERO(&readFd);
    FD_SET(client.getSocket(), &readFd); // NOLINT
    FD_SET(server.getSocket(), &readFd); // NOLINT

    auto maxSocket = max({ client.getSocket(), server.getSocket() });
    LOG4CPLUS_TRACE(logger, "Value of maxSocket: " << maxSocket);

    timeval waitTime; // NOLINT
    LOG4CPLUS_TRACE(logger, "Setting timeout to " << timeout << " seconds");
    waitTime.tv_sec=timeout;
    waitTime.tv_usec=0;

    LOG4CPLUS_TRACE(logger, "Wait for one side to be ready"); // NOLINT
    auto rslt = wrapper->select(maxSocket+1, &readFd, nullptr, nullptr,
        &waitTime);
    LOG4CPLUS_TRACE(logger, "Value of rslt: " << rslt); // NOLINT
    if(rslt == 0)
    {
        LOG4CPLUS_DEBUG(logger, "Read wait time expired"); // NOLINT
        retVal = TIMEOUT;
    }
    else if(rslt == -1)
    {
        auto err = errno;
        LOG4CPLUS_TRACE(logger, "Error code: " << err << ": " // NOLINT
            << strerror(err));
        if(err != 0 && err != EINTR)
        {
            throw system_error(err, std::generic_category(),
                "Error waiting for socket to be ready for reading.");
        }
        else
        {
            LOG4CPLUS_TRACE(logger, "Caught signal"); // NOLINT
            retVal = SIGNAL;
        }
    }
    else
    {
        if(FD_ISSET(client.getSocket(), &readFd)) // NOLINT
        {
            LOG4CPLUS_DEBUG(logger, "Client ready for reading"); // NOLINT
            retVal = CLIENT_READY;
        }
        else if(FD_ISSET(server.getSocket(), &readFd)) // NOLINT
        {
            LOG4CPLUS_DEBUG(logger, "Server ready for reading"); // NOLINT
            retVal = SERVER_READY;
        }
        else
            throw logic_error("Expected FD's not set");
    }

    return retVal;
}

} // namespace
