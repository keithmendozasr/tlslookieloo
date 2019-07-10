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
#include <iomanip>

#include "log4cplus/loggingmacros.h"
#include "log4cplus/ndc.h"

#include "target.h"

using namespace std;
using namespace log4cplus;

namespace tlslookieloo
{

Target::Target(
    const string &tgtName, const string &serverHost,
    const unsigned int serverPort, const unsigned int clientPort,
    const string &clientCert, const string &clientKey, const string &msgFileName) :
    tgtName(tgtName),
    serverHost(serverHost),
    clientCert(clientCert),
    clientKey(clientKey),
    msgFileName(msgFileName),
    serverPort(serverPort),
    clientPort(clientPort),
    wrapper(make_shared<ConcreteWrapper>())
{}

Target::Target(const Target &rhs) :
    tgtName(rhs.tgtName),
    serverHost(rhs.serverHost),
    clientCert(rhs.clientCert),
    clientKey(rhs.clientKey),
    msgFileName(rhs.msgFileName),
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
    msgFileName = rhs.msgFileName;
    serverPort = rhs.serverPort;
    clientPort = rhs.clientPort;
    wrapper = rhs.wrapper;

    return *this;
}

Target::Target(Target && rhs) :
    tgtName(std::move(rhs.tgtName)),
    serverHost(std::move(rhs.serverHost)),
    clientCert(std::move(rhs.clientCert)),
    clientKey(std::move(rhs.clientKey)),
    msgFileName(std::move(rhs.msgFileName)),
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
    msgFileName = std::move(rhs.msgFileName);
    serverPort = std::move(rhs.serverPort);
    clientPort = std::move(rhs.clientPort);
    wrapper = std::move(rhs.wrapper);

    return *this;
}

void Target::start()
{
    NDCContextCreator ndc(tgtName);

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

bool Target::messageRelay(SocketInfo &src, SocketInfo &dest, const MSGOWNER owner)
{
    bool retVal = true;
    size_t amtRead;
    size_t bufSize = 1024;
    unique_ptr<char[]> buf(new char[bufSize]);
    bool keepReading = true;
    while(keepReading)
    {
        amtRead = 1024;
        switch(src.readData(buf.get(), amtRead))
        {
        case SocketInfo::OP_STATUS::SUCCESS:
            if(amtRead > 0)
            {
                LOG4CPLUS_TRACE(logger, "Data from src: " << // NOLINT
                    string(buf.get(), amtRead));
                storeMessage(buf.get(), amtRead, owner);
                LOG4CPLUS_DEBUG(logger, "Send data to dest");

                switch(dest.writeData(buf.get(), amtRead))
                {
                case SocketInfo::OP_STATUS::SUCCESS:
                    LOG4CPLUS_DEBUG(logger, "Data sent to destination");
                    break;
                case SocketInfo::OP_STATUS::TIMEOUT:
                    LOG4CPLUS_INFO(logger,
                        "Timed-out attempting to send to destination");
                    retVal = keepReading = false;
                    break;
                case SocketInfo::OP_STATUS::DISCONNECTED:
                    LOG4CPLUS_INFO(logger,
                        "Destination disconnected while data being sent");
                    retVal = keepReading = false;
                    break;
                default:
                    throw logic_error("Unexpected OP_STATUS while sending data to destination");
                }
            }
            else
            {
                // NOLINTNEXTLINE
                LOG4CPLUS_INFO(logger, "No more data to relay");
                keepReading = false;
            }
            break;
        case SocketInfo::OP_STATUS::TIMEOUT:
            LOG4CPLUS_INFO(logger,
                "Timed-out attempting to receive data from source");
            retVal = keepReading = false;
            break;
        case SocketInfo::OP_STATUS::DISCONNECTED:
            LOG4CPLUS_INFO(logger,
                "Source disconnected while getting data");
            retVal = keepReading = false;
            break;
        default:
            throw logic_error("Unexpected OP_STATUS while reading data from source");
        } // select(src.readData())
    } // while(keepReading)

    LOG4CPLUS_DEBUG(logger, "Done sending message between source and destination");
    return retVal;
}

void Target::handleClient(ClientSide client)
{
    LOG4CPLUS_INFO(logger, "Start monitoring");
    client.setTimeout(timeout);

    if(!client.startSSL(clientCert, clientKey))
    {
        LOG4CPLUS_INFO(logger, "SSL handshake failed");
        return;
    }
    else
        LOG4CPLUS_DEBUG(logger, "Client-side handshake complete");

    ServerSide server;
    server.setTimeout(timeout);
    if(!server.connect(serverPort, serverHost))
    {
        LOG4CPLUS_INFO(logger, "Failed to connect to server " <<
            serverHost << ":" << serverPort);
        return;
    }
    else
        LOG4CPLUS_DEBUG(logger, "Connected to server-side");

    msgFile.open(msgFileName);
    if(!msgFile.is_open())
    {
        auto err = errno;
        throw std::system_error(err, std::generic_category(),
            "Failed to open " + msgFileName);
    }
    else
        LOG4CPLUS_DEBUG(logger, msgFileName << " open");

    bool keepHandling = true;
    try
    {
        while(keepRunning && keepHandling)
        {
            auto readable = waitForReadable(client, server);
            LOG4CPLUS_TRACE(logger, "Available readable items: " << readable.size());
            if(readable.size())
            {
                for(auto item : readable)
                {
                    switch(item)
                    {
                    case CLIENT_READY:
                        {
                            NDCContextCreator ctx("ClientToServer");
                            LOG4CPLUS_DEBUG(logger, "Client ready for reading");
                            if(messageRelay(client, server, MSGOWNER::CLIENT))
                                LOG4CPLUS_DEBUG(logger, "Message sent from client to server");
                            else
                            {
                                LOG4CPLUS_DEBUG(logger, "Client-side disconnected");
                                keepHandling = false;
                            }
                        }
                        break;
                    case SERVER_READY:
                        {
                            NDCContextCreator ctx("ServerToClient");
                            LOG4CPLUS_TRACE(logger, "Server ready for reading");
                            if(messageRelay(server, client, MSGOWNER::SERVER))
                                LOG4CPLUS_DEBUG(logger, "Message sent from server to client");
                            else
                            {
                                LOG4CPLUS_INFO(logger, "Server-side disconnected");
                                keepHandling = false;
                            }
                        }
                        break;
                    } // switch(item)
                } // for(auto item : readable)
            } // if(readable.size())
            else
            {
                LOG4CPLUS_INFO(logger, "Neither side ready with message. Ending handling");
                keepHandling = false;
            }
        } // while(keepRunning && keepHandling)
    }
    catch(const system_error &e)
    {
        LOG4CPLUS_ERROR(logger, "Error encountered handling client. Cause: "
            << e.what());
    }

    msgFile.close();
    LOG4CPLUS_INFO(logger, "Exiting");
}

vector<Target::READREADYSTATE> Target::waitForReadable(ClientSide &client, ServerSide &server)
{
    vector<READREADYSTATE> retVal;

    auto clientFd = client.getSocket();
    auto serverFd = server.getSocket();

    LOG4CPLUS_TRACE(logger, "Client FD: " << clientFd);
    LOG4CPLUS_TRACE(logger, "Server FD: " << serverFd);

    fd_set readFd;
    FD_ZERO(&readFd);
    FD_SET(clientFd, &readFd); // NOLINT
    FD_SET(serverFd, &readFd); // NOLINT

    auto maxSocket = max({ clientFd, serverFd });
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
        LOG4CPLUS_DEBUG(logger, "Read wait time expired"); // NOLINT
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
            LOG4CPLUS_DEBUG(logger, "Caught signal"); // NOLINT
    }
    else
    {
        if(FD_ISSET(client.getSocket(), &readFd)) // NOLINT
        {
            LOG4CPLUS_DEBUG(logger, "Client ready for reading"); // NOLINT
            retVal.push_back(CLIENT_READY);
        }

        if(FD_ISSET(server.getSocket(), &readFd)) // NOLINT
        {
            LOG4CPLUS_DEBUG(logger, "Server ready for reading"); // NOLINT
            retVal.push_back(SERVER_READY);
        }
    }

    return retVal;
}

void Target::storeMessage(const char * data, const size_t &len,
    const MSGOWNER &owner)
{
    if(data == nullptr)
        throw logic_error("data is nullptr");

    ostringstream cleandata("===BEGIN ", ios_base::ate);
    switch(owner)
    {
    case MSGOWNER::CLIENT:
        cleandata << "client-->server===";
        break;
    case MSGOWNER::SERVER:
        cleandata << "server-->client===";
        break;
    default:
        logic_error("Unexpected owner value");
    }
    cleandata << "\n";

    for(size_t i=0; i<len; i++)
    {
        if(isprint(static_cast<unsigned char>(data[i])))
            cleandata << data[i];
        else
            cleandata << "<" << std::setw(2) << std::setfill('0') << std::hex
                << static_cast<unsigned int>(data[i]) << ">";
    }
    cleandata << "\n===END===\n";

    LOG4CPLUS_TRACE(logger, "Value of cleandata: " << cleandata.str());
    wrapper->ostream_write(msgFile, cleandata.str().c_str(),
        cleandata.str().size());
}

} // namespace
