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
#include <ctime>
#include <mutex>
#include <optional>

#include "log4cplus/loggingmacros.h"
#include "log4cplus/ndc.h"

#include "target.h"

using namespace std;
using namespace log4cplus;

namespace tlslookieloo
{

Target::Target(const TargetItem &tgtItem) :
    tgtItem(tgtItem),
    wrapper(make_shared<ConcreteWrapper>())
{}

Target::Target(const Target &rhs) :
    tgtItem(rhs.tgtItem),
    wrapper(rhs.wrapper),
    timeout(rhs.timeout)
{}

Target & Target::operator = (const Target &rhs)
{
    tgtItem = rhs.tgtItem;
    wrapper = rhs.wrapper;

    return *this;
}

Target::Target(Target && rhs) :
    tgtItem(std::move(rhs.tgtItem)),
    wrapper(std::move(rhs.wrapper)),
    recordFileStream(std::move(rhs.recordFileStream))
{}

Target & Target::operator = (Target && rhs)
{
    tgtItem = std::move(rhs.tgtItem);
    wrapper = std::move(rhs.wrapper);
    recordFileStream = std::move(rhs.recordFileStream);

    return *this;
}

void Target::start()
{
    NDCContextCreator ndc(tgtItem.name);

    ClientSide clientListener(wrapper);
    clientListener.startListener(tgtItem.clientPort, 2);
    clientListener.initializeSSLContext(tgtItem.clientCert, tgtItem.clientKey);
    if(tgtItem.clientAuthCert)
    {
        LOG4CPLUS_DEBUG(logger, "Expecting SSL client authentication");
        clientListener.loadRefClientCertPubkey(tgtItem.clientAuthCert.value(),
            tgtItem.clientAuthCA.value());
    }
    else
        LOG4CPLUS_TRACE(logger, "SSL client authentication not expected");

    // NOLINTNEXTLINE
    LOG4CPLUS_INFO(logger, "Listening on " << tgtItem.clientPort);

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

    LOG4CPLUS_INFO(logger, "Target " << tgtItem.name << " stopping");
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
                LOG4CPLUS_DEBUG(logger, "No more data to relay");
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

    if(!client.sslHandshake())
    {
        LOG4CPLUS_INFO(logger, "SSL handshake failed");
        return;
    }
    else
        LOG4CPLUS_DEBUG(logger, "Client-side handshake complete");

    ServerSide::ClientCertInfo clientCertInfo = nullopt;
    if(tgtItem.clientAuthCert)
    {   
        LOG4CPLUS_TRACE(logger, "Set client auth cert data");
        clientCertInfo = make_tuple(tgtItem.clientAuthCert.value(),
            (tgtItem.clientAuthKey ? tgtItem.clientAuthKey.value() :
                tgtItem.clientAuthCert.value())
        );
    }
    else
        LOG4CPLUS_TRACE(logger, "Not setting client auth cert data");

    ServerSide server;
    server.setTimeout(timeout);
    if(!server.connect(tgtItem.serverPort, tgtItem.serverHost, clientCertInfo))
    {
        LOG4CPLUS_INFO(logger, "Failed to connect to server " <<
            tgtItem.serverHost << ":" << tgtItem.serverPort);
        return;
    }
    else
        LOG4CPLUS_DEBUG(logger, "Connected to server-side");

    recordFileStream.open(tgtItem.recordFile);
    if(!recordFileStream.is_open())
    {
        auto err = errno;
        throw std::system_error(err, std::generic_category(),
            "Failed to open " + tgtItem.recordFile);
    }
    else
        LOG4CPLUS_DEBUG(logger, tgtItem.recordFile << " open");

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

    recordFileStream.close();
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

    struct std::tm tmObj;
    time_t cTime;
    {
        lock_guard<mutex> lk(tmGuard);
        cTime = time(nullptr);
        memcpy(&tmObj, gmtime(&cTime), sizeof(struct tm));
    }

    // YYYY-mm-dd 00:00:00
    const size_t tmBufSize = 20;
    char tmBuf[tmBufSize];
    strftime(&tmBuf[0], tmBufSize, "%F %T", &tmObj);
    ostringstream cleandata("===", ios_base::ate);
    cleandata << tmBuf << " BEGIN ";
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
        auto c = static_cast<unsigned char>(data[i]);
        if(isprint(c) || isspace(c))
            cleandata << c;
        else
            cleandata << "<" << std::setw(2) << std::setfill('0') << std::hex
                << static_cast<unsigned int>(c) << ">";
    }
    cleandata << "\n===END===\n";

    LOG4CPLUS_TRACE(logger, "Value of cleandata: " << cleandata.str());
    wrapper->ostream_write(recordFileStream, cleandata.str().c_str(),
        cleandata.str().size());
}

} // namespace
