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

const char *argp_program_version = tlslookieloo::version().c_str();
const char *argp_program_bug_address = "keith@homepluspower.info";

/**
 * Hold info about a running target
 */
struct TargetRunner
{
    Target target;
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
	LOG4CPLUS_INFO(logger, "Stopping program");

    auto myTid = this_thread::get_id();
    for(auto &t : targetThreads)
    {
        auto tid = t.runner.get_id();
        t.target.stop();
        if(tid != myTid)
        {
            LOG4CPLUS_TRACE(logger, "Signaling thread " << tid);
            pthread_kill(t.runner.native_handle(), sig);
        }
        else
            LOG4CPLUS_TRACE(logger, "Not signaling ourself");
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
        LOG4CPLUS_DEBUG(logger, "Process targets files");
        for(auto item : parseTargetsFile(targets))
        {
            LOG4CPLUS_INFO(logger, "Starting " << item.name << " bridge");
            targetThreads.emplace_back();
            auto &t = targetThreads.back();

            t.target = Target(item);
            t.runner = std::thread([](Target &tgt)
                {
                    tgt.start();
                }, std::ref(t.target)
            );
        }
    }
    catch(const YAML::Exception &e)
    {
        LOG4CPLUS_ERROR(logger, "Failed to parse targets file, cause: " <<
            e.what() << ". Exiting");
    }

    // TODO: Handle system_error that std::thread() may throw
}

int main(int argc, char *argv[])
{
    Initializer initializer;
    BasicConfigurator::doConfigure();

    struct sigaction sa;
    sa.sa_handler = sigHandler;
    sa.sa_flags = 0;
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
        LOG4CPLUS_ERROR(logger, "Error parsing command-line parameters");
        return -1;
    }

    if(argState.logconfig)
    {
        LOG4CPLUS_DEBUG(logger, "Loading logconfig file");
        logger.getHierarchy().resetConfiguration();
        PropertyConfigurator::doConfigure(argState.logconfig.value());
    }

    if(argState.targets)
        start(argState.targets.value());
    else
    {
        LOG4CPLUS_ERROR(logger, "Targets file to use not provided");
        return -1;
    }

    LOG4CPLUS_TRACE(logger, "Waiting for target threads to exit");
    for(auto &t : targetThreads)
        t.runner.join();
    // So the SocketInfo logging doesn't trigger log4cplus to complain
    targetThreads.clear();
    LOG4CPLUS_INFO(logger, "tlslookieloo exiting");

    return 0;
}
