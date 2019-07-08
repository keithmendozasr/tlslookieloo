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
    char *args[3];
    Logger logger;
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
    case ARGP_KEY_ARG:
        if(state->arg_num >= 3)
            // Too many
            argp_usage(state);
        
        // Save the argument
        argState->args[state->arg_num] = arg; // NOLINT
        break;
    case ARGP_KEY_END:
        if(state->arg_num < 3)
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
        { 0 } 
    };
    const string argsDoc = "port cert key";
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
            client.startSSL(argState.args[1], argState.args[2]);

            while(1)
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

            LOG4CPLUS_INFO(logger, "Client went away"); // NOLINT
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
