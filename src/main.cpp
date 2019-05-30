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

#include "version.h"

using namespace std;
using namespace tlslookieloo;

const char *argp_program_version = tlslookieloo::version().c_str();
const char *argp_program_bug_address = "keith@homepluspower.info";

/**
 * Used in argp_parser to hold arg state
 */
struct ArgState
{
    optional<string> targets, logconfig;
    log4cplus::Logger logger;
};

/**
 * Callback function for argp_parser()
 * Argument field are as defined by argp_parser()
 */
static error_t parseArgs(int key, char *arg, struct argp_state *state)
{
    struct ArgState *argState = reinterpret_cast<ArgState *>(state->input);
    LOG4CPLUS_DEBUG(argState->logger, "Value of key: " << hex << key);
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
            LOG4CPLUS_DEBUG(argState->logger, "Required options set");
        else
        {
            LOG4CPLUS_ERROR(argState->logger, "targets command-line option required");
            return EINVAL;
        }
        [[fallthrough]];
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    log4cplus::Initializer initializer;
    log4cplus::BasicConfigurator::doConfigure();

    struct ArgState argState;
    argState.logger = log4cplus::Logger::getRoot();

    struct argp_option options[] = {
        { "targets",    't', "tgtfile",     0, "Targets config file" },
        { "logconfig",  'l', "logcfgfile",  0, "Logging configuration file" },
        { 0 } 
    };
    const string argsDoc = "";
    const string progDoc = "Record TLS communication between a server and client";
    struct argp argp = { options, parseArgs, progDoc.c_str(), argsDoc.c_str() };

    argp_parse(&argp, argc, argv, 0, nullptr, &argState);

    if(argState.logconfig)
        log4cplus::PropertyConfigurator::doConfigure(argState.logconfig.value());

    return 0;
}
