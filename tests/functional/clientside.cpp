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

#include <unistd.h>
#include <signal.h>
#include <argp.h>
#include <cstring>
#include <cerrno>

#include <log4cplus/initializer.h>
#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>
#include <log4cplus/configurator.h>
#include <log4cplus/hierarchy.h>

#include "clientside.h"

using namespace std;
using namespace tlslookieloo;
using namespace log4cplus;

/**
 * Used in argp_parser to hold arg state
 */
struct ArgState // NOLINT
{
    optional<string> logconfig;
    char *args[4];
    Logger logger;
    bool withClientCert = false;
    unsigned int expectArgs = 1;
};

/**
 * Callback function for argp_parser()
 * Argument field are as defined by argp_parser()
 */
static error_t parseArgs(int key, char *arg, struct argp_state *state)
{
    struct ArgState *argState = reinterpret_cast<ArgState *>(state->input); // NOLINT
    // NOLINTNEXTLINE
    LOG4CPLUS_DEBUG(argState->logger, "Value of key: " << hex << key);
    switch(key)
    {
    case 'l':
        argState->logconfig = arg;
        break;
    case 'c':
        argState->withClientCert = true;
        argState->expectArgs = 3;
        break;
    case ARGP_KEY_ARG:
        if(state->arg_num > argState->expectArgs)
            // Too many
            argp_usage(state);
        
        // Save the argument
        argState->args[state->arg_num] = arg; // NOLINT
        break;
    case ARGP_KEY_END:
        if(state->arg_num < argState->expectArgs)
            // Not enough arguments
            argp_usage(state);

        // Got enough arguments
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

bool keepRunning = true;

void sigHandler(int sig)
{
	Logger logger = Logger::getRoot();
	LOG4CPLUS_INFO(logger, "Stopping program"); // NOLINT
	keepRunning = false;
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
    struct sigaction sa;
    sa.sa_handler = sigHandler; // NOLINT
    sa.sa_flags = 0; // NOLINT
    sigemptyset(&sa.sa_mask);
    if(sigaction(SIGINT, &sa, nullptr) == -1)
    {
        perror("Set SIGINT signal handler");
        return EXIT_FAILURE;
    }

    if(sigaction(SIGTERM, &sa, nullptr) == -1)
    {
        perror("Set SIGTERM signal handler");
        return EXIT_FAILURE;
    }

    Initializer initializer;
    BasicConfigurator::doConfigure();

    struct ArgState argState;
    argState.logger = Logger::getRoot();
    Logger &logger = argState.logger;
    logger.setLogLevel(INFO_LOG_LEVEL);

    struct argp_option options[] = {
        { "logconfig",  'l', "logcfgfile",  0, "Logging configuration file" },
        { "withclientcert", 'c', nullptr, 0, "Expect client certificate" },
        { 0 } 
    };
    const string argsDoc = "port cert key CA";
    const string progDoc = "Test ClientSide class";
    struct argp argp = { &options[0], parseArgs, argsDoc.c_str(), progDoc.c_str() };

    if(argp_parse(&argp, argc, argv, 0, nullptr, &argState))
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "Error parsing command-line parameters");
        return -1;
    }

    if(argState.logconfig)
    {
        LOG4CPLUS_DEBUG(logger, "Loading logconfig file"); // NOLINT
        logger.getHierarchy().resetConfiguration();
        PropertyConfigurator::doConfigure(argState.logconfig.value());
    }

    try
    {
        ClientSide c;
        c.initializeSSLContext(argState.args[1], argState.args[2]);
        if(argState.withClientCert)
        {
            LOG4CPLUS_INFO(logger, "Enable expecting client cert");
            c.loadRefClientCertPubkey(argState.args[1], argState.args[3]);
        }

        c.startListener(stoi(argState.args[0]), 2);

        // NOLINTNEXTLINE
        LOG4CPLUS_INFO(logger, "Listening on " << argState.args[0]);

        while(keepRunning)
        {
            auto acceptVal = c.acceptClient();
            if(!acceptVal)
            {
                LOG4CPLUS_INFO(logger, "Client accepting issue"); // NOLINT
                break;
            }

            auto client = acceptVal.value();

            // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger, "Got client " << client.getSocketIP() << " with FD: "
                << client.getSocket());
            if(client.sslHandshake())
            {
                while(1)
                {
                    if(waitSocketReadable(client.getSocket()))
                    {
                        size_t bufSize = 1024;
                        unique_ptr<char[]> buf(new char[bufSize]);
                        auto readLen = client.readData(&buf[0], bufSize);
                        if(readLen == SocketInfo::OP_STATUS::SUCCESS)
                        {
                            if(bufSize > 0)
                            {
                                LOG4CPLUS_INFO(logger, "Data from server: " << // NOLINT
                                    string(buf.get(), bufSize));
                                client.writeData("Bye", 4);
                            }
                            else
                                // NOLINTNEXTLINE
                                LOG4CPLUS_INFO(logger, "No data received from remote end");
                        }
                        else
                            break;
                    }
                    else
                        break;
                }

                LOG4CPLUS_INFO(logger, "Client went away"); // NOLINT
            }
            else
                LOG4CPLUS_ERROR(logger, "SSL handshake failed");
        }
    }
    catch(const system_error &e)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "Error encountered testing ClientSide. Cause: " <<
            e.what());
        return 1;
    }

    return 0;
}
