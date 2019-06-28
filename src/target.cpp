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
    clientPort(clientPort)
{}

Target::Target(const Target &rhs) :
    logger(log4cplus::Logger::getInstance("Target")),
    tgtName(rhs.tgtName),
    serverHost(rhs.serverHost),
    clientCert(rhs.clientCert),
    clientKey(rhs.clientKey),
    serverPort(rhs.serverPort),
    clientPort(rhs.clientPort),
    server(rhs.server),
    client(rhs.client)
{}

Target & Target::operator = (const Target &rhs)
{
    tgtName = rhs.tgtName;
    serverHost = rhs.serverHost;
    clientCert = rhs.clientCert;
    clientKey = rhs.clientKey;
    serverPort = rhs.serverPort;
    clientPort = rhs.clientPort;
    server = rhs.server;
    client = rhs.client;

    return *this;
}

Target::Target(Target && rhs) :
    logger(log4cplus::Logger::getInstance("Target")),
    tgtName(std::move(tgtName)),
    serverHost(std::move(serverHost)),
    clientCert(std::move(clientCert)),
    clientKey(std::move(clientKey)),
    serverPort(std::move(serverPort)),
    clientPort(std::move(clientPort)),
    server(std::move(server)),
    client(std::move(client))
{}

Target & Target::operator = (Target && rhs)
{
    tgtName = std::move(rhs.tgtName);
    serverHost = std::move(rhs.serverHost);
    clientCert = std::move(rhs.clientCert);
    clientKey = std::move(rhs.clientKey);
    serverPort = std::move(rhs.serverPort);
    clientPort = std::move(rhs.clientPort);
    server = std::move(rhs.server);
    client = std::move(rhs.client);

    return *this;
}

void Target::start()
{
    log4cplus::NDCContextCreator ndc(tgtName);

    client.startListener(clientPort, 2);
    // NOLINTNEXTLINE
    LOG4CPLUS_INFO(logger, "Listening on " << clientPort);

    while(keepRunning)
    {
        LOG4CPLUS_DEBUG(logger, "Wait for clientside connection");
        auto acceptVal = client.acceptClient();
        if(!acceptVal)
        {
            LOG4CPLUS_INFO(logger, "Client accepting issue"); // NOLINT
            break;
        }
        else
            LOG4CPLUS_INFO(logger, "Clientside connected");

        handleClient(acceptVal.value());
    }

    LOG4CPLUS_INFO(logger, "Target " << tgtName << " stopping");
}

void Target::handleClient(ClientSide client)
{
    LOG4CPLUS_INFO(logger, "Start monitoring");

    if(!client.startSSL(clientCert, clientKey))
    {
        LOG4CPLUS_INFO(logger, "SSL handshake failed");
        return;
    }

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
                    server.writeData(&buf[0], readLen.value());

                    client.writeData("Bye", 4);
                }
                else
                    // NOLINTNEXTLINE
                    LOG4CPLUS_INFO(logger, "No data received from remote end");
            }
            else
            {
                LOG4CPLUS_INFO(logger, "Client went away"); // NOLINT
                break;
            }
        } // while(keepReading)
    }
    catch(const system_error &e)
    {
        LOG4CPLUS_ERROR(logger, "Error encountered handling client. Cause: "
            << e.what());
    }

    LOG4CPLUS_INFO(logger, "Exiting");
}

} // namespace
