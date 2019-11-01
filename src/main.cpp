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

#include <thread>
#include <csignal>

#include <argp.h>

#include <yaml-cpp/yaml.h>

#include "log4cplus/initializer.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "log4cplus/configurator.h"
#include "log4cplus/hierarchy.h"


#include "version.h"
#include "init.h"
#include "serverside.h"
#include "target.h"

using namespace std;
using namespace tlslookieloo;
using namespace log4cplus;

/**
 * Hold info about a running target
 */
struct TargetRunner // NOLINT
{
    std::thread::native_handle_type handle;
    std::thread runner;
};

vector<TargetRunner> targetThreads;

/**
 * Signal handler
 *
 * \arg sig Signal received
 */
void sigHandler(int sig)
{
	Logger logger = Logger::getRoot();
	LOG4CPLUS_INFO(logger, "Stopping program"); // NOLINT

    auto myTid = this_thread::get_id();
    Target::stop();
    for(auto &t : targetThreads)
    {
        auto tid = t.runner.get_id();
        if(tid != myTid)
        {
            LOG4CPLUS_TRACE(logger, "Signaling thread " << tid); // NOLINT
            pthread_kill(t.handle, sig);
        }
        else
            LOG4CPLUS_TRACE(logger, "Not signaling ourself"); // NOLINT
    }
}

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

/**
 * Start handling targets
 */
static void start(const string &targets)
{
    auto logger = Logger::getRoot();
    try
    {
        LOG4CPLUS_DEBUG(logger, "Process targets files"); // NOLINT
        for(auto item : parseTargetsFile(targets))
        {
            // NOLINTNEXTLINE
            LOG4CPLUS_INFO(logger, "Starting " << item.name << " bridge");
            TargetRunner obj;
            obj.runner =std::thread([](TargetItem tgtItem)
                {
                    Target tgt(tgtItem);
                    tgt.start();
                }, item);
            obj.handle = obj.runner.native_handle();
            targetThreads.push_back(std::move(obj));
        }
    }
    catch(const YAML::Exception &e)
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "Failed to parse targets file, cause: " <<
            e.what() << ". Exiting");
    }
    catch(const system_error &e)
    {
        LOG4CPLUS_ERROR(logger, "Error encountered starting bridges"); // NOLINT
        Target::stop();
    }
}

int main(int argc, char *argv[])
{
    Initializer initializer;
    BasicConfigurator::doConfigure();

    struct sigaction sa; // NOLINT
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

    LOG4CPLUS_TRACE(logger, "Waiting for target threads to exit"); // NOLINT
    for(auto &t : targetThreads)
        t.runner.join();
    // So the SocketInfo logging doesn't trigger log4cplus to complain
    targetThreads.clear();
    LOG4CPLUS_INFO(logger, "tlslookieloo exiting"); // NOLINT

    return 0;
}
