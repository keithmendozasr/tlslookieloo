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

atomic_bool Target::keepRunning = true;

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
    LOG4CPLUS_DEBUG(logger, "Start target handler"); // NOLINT

    try
    {
        timeout = tgtItem.timeout;

        ClientSide clientListener(wrapper);
        clientListener.startListener(tgtItem.clientPort, 2);
        clientListener.initializeSSLContext(tgtItem.clientCert,
            (tgtItem.clientKey ? tgtItem.clientKey.value() : tgtItem.clientCert)
        );
        if(tgtItem.clientAuthCert)
        {
            LOG4CPLUS_DEBUG(logger, "Expecting SSL client authentication"); // NOLINT
            clientListener.loadRefClientCertPubkey(tgtItem.clientAuthCert.value(),
                tgtItem.clientAuthCA.value());
        }
        else
            LOG4CPLUS_TRACE(logger, "SSL client authentication not expected"); // NOLINT

        //NOLINTNEXTLINE
        LOG4CPLUS_INFO(logger, "Listening on " << tgtItem.clientPort);
        while(keepRunning)
        {
            LOG4CPLUS_DEBUG(logger, "Wait for clientside connection"); // NOLINT
            auto acceptRslt = clientListener.acceptClient();
            LOG4CPLUS_INFO(logger, "Clientside connected"); // NOLINT
            handleClient(acceptRslt);
        }
    }
    catch(const system_error &e)
    {
        if(e.code() == make_error_code(errc::interrupted))
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger,
                "Interrupted while waiting for client-side to connect");
        }
        else
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_ERROR(logger,
                "Error ecnountered handling target. Cause: " << e.what());
            throw;
        }
    }
    catch(const runtime_error &e)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "Error encountered handling target. Cause: " <<
            e.what());
        throw;
    }
    catch(const logic_error &e)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "Logic error encountered handling target. Cause: " <<
            e.what());
        throw;
    }

    LOG4CPLUS_INFO(logger, "Target " << tgtItem.name << " stopping"); // NOLINT
}

bool Target::messageRelay(SocketInfo &src, SocketInfo &dest, const MSGOWNER owner)
{
    bool retVal = true;
    size_t bufSize = 4096;
    unique_ptr<char[]> buf(new char[bufSize]);
    bool keepReading = true;
    while(keepReading)
    {
        auto amtRead = bufSize;
        switch(src.readData(buf.get(), amtRead))
        {
        case SocketInfo::OP_STATUS::SUCCESS:
            if(amtRead > 0)
            {
                // NOLINTNEXTLINE
                LOG4CPLUS_TRACE(logger, "Data from src: " <<
                    string(buf.get(), amtRead));
                storeMessage(buf.get(), amtRead, owner);
                LOG4CPLUS_DEBUG(logger, "Send data to dest"); // NOLINT

                switch(dest.writeData(buf.get(), amtRead))
                {
                case SocketInfo::OP_STATUS::SUCCESS:
                    LOG4CPLUS_DEBUG(logger, "Data sent to destination"); // NOLINT
                    break;
                case SocketInfo::OP_STATUS::TIMEOUT:
                    // NOLINTNEXTLINE
                    LOG4CPLUS_INFO(logger,
                        "Timed-out attempting to send to destination");
                    retVal = keepReading = false;
                    break;
                case SocketInfo::OP_STATUS::DISCONNECTED:
                    // NOLINTNEXTLINE
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
                storeMessage(buf.get(), 0, owner);
                keepReading = false;
            }
            break;
        case SocketInfo::OP_STATUS::TIMEOUT:
             // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger,
                "Timed-out attempting to receive data from source");
            retVal = keepReading = false;
            break;
        case SocketInfo::OP_STATUS::DISCONNECTED:
            // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger,
                "Source disconnected while getting data");
            retVal = keepReading = false;
            break;
        default:
            throw logic_error("Unexpected OP_STATUS while reading data from source");
        } // select(src.readData())
    } // while(keepReading)

    LOG4CPLUS_DEBUG(logger, "Done sending message between source and destination"); // NOLINT
    return retVal;
}

void Target::handleClient(ClientSide client)
{
    LOG4CPLUS_INFO(logger, "Start monitoring"); // NOLINT

    ServerSide server;
    if(timeout)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_TRACE(logger, "Setting communication timeout to "
            << timeout.value());
        client.setTimeout(timeout.value());
        server.setTimeout(timeout.value());
    }
    else
        LOG4CPLUS_TRACE(logger, "No timeout set for target"); // NOLINT

    if(!client.sslHandshake())
    {
        LOG4CPLUS_INFO(logger, "SSL handshake failed"); // NOLINT
        return;
    }
    else
        LOG4CPLUS_DEBUG(logger, "Client-side handshake complete"); // NOLINT

    ServerSide::ClientCertInfo clientCertInfo = nullopt;
    if(tgtItem.clientAuthCert)
    {   
        LOG4CPLUS_TRACE(logger, "Set client auth cert data"); // NOLINT
        clientCertInfo = make_tuple(tgtItem.clientAuthCert.value(),
            (tgtItem.clientAuthKey ? tgtItem.clientAuthKey.value() :
                tgtItem.clientAuthCert.value())
        );
    }
    else
        LOG4CPLUS_TRACE(logger, "Not setting client auth cert data"); // NOLINT

    if(!server.connect(tgtItem.serverPort, tgtItem.serverHost, clientCertInfo,
        tgtItem.serverInsecure, tgtItem.serverCAChainFile))
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_INFO(logger, "Failed to connect to server " <<
            tgtItem.serverHost << ":" << tgtItem.serverPort);
        return;
    }
    else
        LOG4CPLUS_DEBUG(logger, "Connected to server-side"); // NOLINT

    recordFileStream.open(tgtItem.recordFile, ios_base::out | ios_base::app);
    if(!recordFileStream.is_open())
    {
        auto err = errno;
        throw std::system_error(err, std::generic_category(),
            "Failed to open " + tgtItem.recordFile);
    }
    else
        LOG4CPLUS_DEBUG(logger, tgtItem.recordFile << " open"); // NOLINT

    try
    {
        bool keepHandling = true;
        while(keepRunning && keepHandling)
        {
            auto readable = waitForReadable(client, server);
            // NOLINTNEXTLINE
            LOG4CPLUS_TRACE(logger, "Available readable items: " <<
                readable.size());
            if(readable.size())
            {
                for(auto item : readable)
                {
                    switch(item)
                    {
                    case CLIENT_READY:
                        {
                            NDCContextCreator ctx("ClientToServer");
                            LOG4CPLUS_DEBUG(logger, "Client ready for reading"); // NOLINT
                            if(messageRelay(client, server, MSGOWNER::CLIENT))
                                // NOLINTNEXTLINE
                                LOG4CPLUS_DEBUG(logger, "Message sent from client to server");
                            else
                            {
                                LOG4CPLUS_DEBUG(logger, "Client-side disconnected"); // NOLINT
                                keepHandling = false;
                            }
                        }
                        break;
                    case SERVER_READY:
                        {
                            NDCContextCreator ctx("ServerToClient");
                            LOG4CPLUS_TRACE(logger, "Server ready for reading"); // NOLINT
                            if(messageRelay(server, client, MSGOWNER::SERVER))
                                // NOLINTNEXTLINE
                                LOG4CPLUS_DEBUG(logger, "Message sent from server to client");
                            else
                            {
                                LOG4CPLUS_INFO(logger, "Server-side disconnected"); // NOLINT
                                keepHandling = false;
                            }
                        }
                        break;
                    } // switch(item)
                } // for(auto item : readable)
            } // if(readable.size())
            else
            {
                // NOLINTNEXTLINE
                LOG4CPLUS_INFO(logger,
                    "Neither side ready with message. Ending handling");
                keepHandling = false;
            }
        } // while(keepRunning && keepHandling)
    }
    catch(const system_error &e)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "Error encountered handling client. Cause: "
            << e.what());
    }

    recordFileStream.close();
    LOG4CPLUS_INFO(logger, "Exiting"); // NOLINT
}

vector<Target::READREADYSTATE> Target::waitForReadable(ClientSide &client, ServerSide &server)
{
    vector<READREADYSTATE> retVal;

    auto clientFd = client.getSocket();
    auto serverFd = server.getSocket();

    LOG4CPLUS_TRACE(logger, "Client FD: " << clientFd); // NOLINT
    LOG4CPLUS_TRACE(logger, "Server FD: " << serverFd); // NOLINT

    fd_set readFd;
    FD_ZERO(&readFd);
    FD_SET(clientFd, &readFd); // NOLINT
    FD_SET(serverFd, &readFd); // NOLINT

    auto maxSocket = max({ clientFd, serverFd });
    LOG4CPLUS_TRACE(logger, "Value of maxSocket: " << maxSocket); // NOLINT

    unique_ptr<struct timeval> waitTime;
    if(timeout)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_TRACE(logger, "Setting timeout to " << timeout.value() << " seconds");
        waitTime = make_unique<struct timeval>();
        waitTime->tv_sec=timeout.value();
        waitTime->tv_usec=0;
    }
    else
        LOG4CPLUS_TRACE(logger, "Not setting wait timeout"); // NOLINT

    LOG4CPLUS_TRACE(logger, "Wait for one side to be ready"); // NOLINT
    auto rslt = wrapper->select(maxSocket+1, &readFd, nullptr, nullptr,
        waitTime.get());
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
    const string msgTail("\n===END===\n");

    if(data == nullptr)
        throw logic_error("data is nullptr");

    ostringstream cleandata(string(), ios_base::ate);
    if(lastMsgOwner != owner)
    {
        if(len == 0)
        {
            LOG4CPLUS_TRACE(logger, "Not recording 0-byte 1st chunck"); // NOLINT
            return;
        }

        if(lastMsgOwner)
        {
            LOG4CPLUS_TRACE(logger, "Close last message block"); // NOLINT
            cleandata << msgTail;
        }

        LOG4CPLUS_TRACE(logger, "Add record header"); // NOLINT
        struct std::tm tmObj; // NOLINT
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

        cleandata << "===" << &tmBuf[0] << " BEGIN ";
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
        lastMsgOwner = owner;
    }
    else if(len == 0)
    {
        LOG4CPLUS_TRACE(logger, "Placing end marker"); // NOLINT
        cleandata << msgTail;
        lastMsgOwner.reset();
    }
    else
        LOG4CPLUS_TRACE(logger, "Data continuation"); // NOLINT

    for(size_t i=0; i<len; i++)
    {
        auto c = static_cast<unsigned char>(data[i]);
        if(c == '\r')
        {
            cleandata << "<0d>";
            if(data[i+1] == '\n')
            {
                cleandata << "<0a>";
                i++;
            }

            cleandata << endl;
        }
        else if(c == '\n')
            cleandata << "<0a>" << endl;
        else if(isprint(c))
            cleandata << c;
        else
        {
            cleandata << "<" << std::setw(2) << std::setfill('0') << std::hex
                << static_cast<unsigned int>(c) << ">";
        }
    }

    LOG4CPLUS_TRACE(logger, "Value of cleandata: " << cleandata.str()); // NOLINT
    wrapper->ostream_write(recordFileStream, cleandata.str().c_str(),
        cleandata.str().size());
}

} // namespace
