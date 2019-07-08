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
    char *args[2];
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
        if(state->arg_num >= 2)
            // Too many
            argp_usage(state);
        
        // Save the argument
        argState->args[state->arg_num] = arg; // NOLINT
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
    const string argsDoc = "port host";
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

    ServerSide s;
    if(s.connect(stoi(argState.args[0]), argState.args[1]))
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_INFO(logger, "Connected to " << argState.args[1] << ":" <<
            argState.args[0]);

        LOG4CPLUS_INFO(logger, "Send data to server"); // NOLINT
        const char msg[] = "GET / HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
        s.writeData(&msg[0], sizeof(msg));

        size_t msgSize = 1024;
        unique_ptr<char[]> buf(new char[msgSize]);
        auto readLen = s.readData(buf.get(), msgSize);
        while(readLen == SocketInfo::OP_STATUS::SUCCESS)
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger, "Data read: " << string(buf.get(), msgSize));
            readLen = s.readData(buf.get(), msgSize);
        }

        LOG4CPLUS_INFO(logger, "No more data"); // NOLINT
    }
    else
    {
        LOG4CPLUS_ERROR(logger, "Failed to connect to " << // NOLINT
            argState.args[1] << ":" << argState.args[0]);
    }

    return 0;
}
