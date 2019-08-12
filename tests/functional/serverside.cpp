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

#include <iostream>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <ios>

#include <argp.h>

#include <log4cplus/initializer.h>
#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>
#include <log4cplus/configurator.h>
#include <log4cplus/hierarchy.h>

#include <yaml-cpp/yaml.h>

#include "serverside.h"

using namespace std;
using namespace tlslookieloo;
using namespace log4cplus;

/**
 * Used in argp_parser to hold arg state
 */
struct ArgState // NOLINT
{
    optional<string> logconfig;
    vector<string> args;
    Logger logger;
};

/**
 * Callback function for argp_parser()
 * Argument field are as defined by argp_parser()
 */
static error_t parseArgs(int key, char *arg, struct argp_state *state)
{
    // NOLINTNEXTLINE
    struct ArgState *argState = reinterpret_cast<ArgState *>(state->input);
    LOG4CPLUS_DEBUG(argState->logger, "Value of key: " << hex << key); // NOLINT
    switch(key)
    {
    case 'l':
        argState->logconfig = arg;
        break;
    case ARGP_KEY_ARG:
        if(state->arg_num >= 4)
            // Too many
            argp_usage(state);
        
        // Save the argument
        argState->args.push_back(string(arg)); // NOLINT
        break;
    case ARGP_KEY_END:
        if(state->arg_num < 2)
            // Not enough arguments
            argp_usage(state);

        // Got enough arguments
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

bool waitSocketReadable(const int sockFd)
{
    auto logger = Logger::getRoot();
    bool retVal = false;

    fd_set readFd;
    FD_ZERO(&readFd);
    FD_SET(sockFd, &readFd); // NOLINT

    auto maxSocket = sockFd + 1;

    LOG4CPLUS_TRACE(logger, "Wait for one side to be ready"); // NOLINT
    auto rslt = select(maxSocket+1, &readFd, nullptr, nullptr, nullptr);
    LOG4CPLUS_TRACE(logger, "Value of rslt: " << rslt); // NOLINT
    if(rslt <= 0)
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
    else if(FD_ISSET(sockFd, &readFd)) // NOLINT
    {
        LOG4CPLUS_DEBUG(logger, "Client ready for reading"); // NOLINT
        retVal = true;
    }

    return retVal;
}

int main(int argc, char *argv[])
{
    Initializer initializer;
    BasicConfigurator::doConfigure();

    struct ArgState argState;
    argState.logger = Logger::getRoot();
    Logger &logger = argState.logger;
    logger.setLogLevel(INFO_LOG_LEVEL);

    const struct argp_option options[] = {
        { "logconfig",  'l', "logcfgfile",  0, "Logging configuration file" },
        { 0 } 
    };
    const string argsDoc = "port host [clientCert clientKey]";
    const string progDoc = "Test ServerSide class";
    struct argp argp = {
        &options[0],
        parseArgs,
        argsDoc.c_str(),
        progDoc.c_str()
    };

    if(argp_parse(&argp, argc, argv, 0, nullptr, &argState))
    {
        LOG4CPLUS_ERROR(logger, "Error parsing command-line parameters"); // NOLINT
        return -1;
    }

    if(argState.logconfig)
    {
        LOG4CPLUS_DEBUG(logger, "Loading logconfig file"); // NOLINT
        logger.getHierarchy().resetConfiguration();
        PropertyConfigurator::doConfigure(argState.logconfig.value());
    }

    ServerSide::ClientCertInfo clientCert;
    switch(argState.args.size())
    {
    case 3:
        LOG4CPLUS_INFO(logger, "Set client certificate"); // NOLINT
        clientCert = make_tuple(argState.args[2], argState.args[2]);
        break;
    case 4:
        LOG4CPLUS_INFO(logger, "Set client certificate"); // NOLINT
        clientCert = make_tuple(argState.args[2], argState.args[3]);
        break;
    default:
        break;
    }
    if(clientCert)
    {
        auto data = clientCert.value();
        LOG4CPLUS_TRACE(logger, "Public key file: " << get<0>(data)); // NOLINT
        LOG4CPLUS_TRACE(logger, "Private key file: " << get<1>(data)); // NOLINT
    }
    else
        LOG4CPLUS_TRACE(logger, "Client-side cert not set"); // NOLINT

    ServerSide s;
    if(s.connect(stoi(argState.args[0]), argState.args[1], clientCert))
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_INFO(logger, "Connected to " << argState.args[1] << ":" <<
            argState.args[0]);

        LOG4CPLUS_INFO(logger, "Send data to server"); // NOLINT
        const char msg[] = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
        if(s.writeData(&msg[0], sizeof(msg)) == SocketInfo::OP_STATUS::SUCCESS)
        {
            SocketInfo::OP_STATUS readLen;
            do
            {
                size_t msgSize = 1024;
                unique_ptr<char[]> buf(new char[msgSize]);
                if(waitSocketReadable(s.getSocket()))
                {
                    readLen = s.readData(buf.get(), msgSize);
                    if(readLen == SocketInfo::OP_STATUS::SUCCESS)
                        // NOLINTNEXTLINE
                        LOG4CPLUS_INFO(logger, "Data read: " <<
                            string(buf.get(), msgSize) << "Length: " << msgSize);
                }
                else // Break on signal
                    break;
            }while(readLen == SocketInfo::OP_STATUS::SUCCESS);

            LOG4CPLUS_INFO(logger, "No more data"); // NOLINT
        }
        else
            LOG4CPLUS_ERROR(logger, "Failed to send data to server"); // NOLINT
    }
    else
    {
        LOG4CPLUS_ERROR(logger, "Failed to connect to " << // NOLINT
            argState.args[1] << ":" << argState.args[0]);
    }

    return 0;
}
