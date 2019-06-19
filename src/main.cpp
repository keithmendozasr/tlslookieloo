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
#include <regex>

#include <argp.h>

#include <log4cplus/initializer.h>
#include <log4cplus/logger.h>
#include <log4cplus/loggingmacros.h>
#include <log4cplus/configurator.h>
#include <log4cplus/hierarchy.h>

#include <yaml-cpp/yaml.h>

#include "version.h"
#include "init.h"
#include "serverside.h"

using namespace std;
using namespace tlslookieloo;
using namespace log4cplus;

const char *argp_program_version = tlslookieloo::version().c_str();
const char *argp_program_bug_address = "keith@homepluspower.info";

/**
 * Used in argp_parser to hold arg state
 */
struct ArgState
{
    optional<string> targets, logconfig;
    Logger logger;
};

/**
 * Callback function for argp_parser()
 * Argument field are as defined by argp_parser()
 */
static error_t parseArgs(int key, char *arg, struct argp_state *state)
{
    struct ArgState *argState = reinterpret_cast<ArgState *>(state->input); // NOLINT
    LOG4CPLUS_DEBUG(argState->logger, "Value of key: " << hex << key); // NOLINT
    switch(key)
    {
    case 't':
        argState->targets = arg;
        break;
    case 'l':
        argState->logconfig = arg;
        break;
    case ARGP_KEY_END:
        if(argState->targets)
            LOG4CPLUS_DEBUG(argState->logger, "Required options set"); // NOLINT
        else
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_ERROR(argState->logger,
                "targets command-line option required");
            argp_usage(state);
        }
        [[fallthrough]];
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static void start(const string &targets)
{
    auto logger = Logger::getRoot();
    try
    {
        LOG4CPLUS_DEBUG(logger, "Process targets files"); // NOLINT
        for(auto item : parseTargetsFile(targets))
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger, "Starting " << get<0>(item) << " bridge");

            LOG4CPLUS_TRACE(logger, "Server Port: " << get<2>(item) << // NOLINT
                " Host: " << get<1>(item));
            ServerSide s;
            if(s.connect(get<2>(item), get<1>(item)))
            {
                // NOLINTNEXTLINE
                LOG4CPLUS_INFO(logger, "Connected to " << get<1>(item) << ":"
                    << get<2>(item));
            }
            else
            {
                // NOLINTNEXTLINE
                LOG4CPLUS_INFO(logger, "Failed to connect to "
                    << get<1>(item) << ":" << get<2>(item));
            }
        }
    }
    catch(const YAML::Exception &e)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "Failed to parse targets file, cause: " <<
            e.what() << ". Exiting");
    }
}

int main(int argc, char *argv[])
{
    Initializer initializer;
    BasicConfigurator::doConfigure();

    struct ArgState argState;
    argState.logger = Logger::getRoot();
    Logger &logger = argState.logger;
    logger.setLogLevel(INFO_LOG_LEVEL);

    struct argp_option options[] = {
        { "targets",    't', "tgtfile",     0, "Targets config file" },
        { "logconfig",  'l', "logcfgfile",  0, "Logging configuration file" },
        { 0 } 
    };
    const string argsDoc = "";
    const string progDoc = "Record TLS communication between a server and client";
    struct argp argp = { &options[0], parseArgs, progDoc.c_str(), argsDoc.c_str() };

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

    if(argState.targets)
        start(argState.targets.value());
    else
    {
        LOG4CPLUS_ERROR(logger, "Targets file to use not provided"); // NOLINT
        return -1;
    }

    return 0;
}
