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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <argp.h>

#include <log4cplus/initializer.h>
#include <log4cplus/configurator.h>
#include <log4cplus/logger.h>
#include <log4cplus/hierarchy.h>

#include "config.h"

using namespace std;

namespace tlslookieloo
{
    string tgtFilesPath;
    string certFilesPath;
}

string logConfig;

static error_t parseArgs(int key, char *arg, struct argp_state *state)
{
    switch(key)
    {
    case 't':
        tlslookieloo::tgtFilesPath = arg;
        break;
    case 'l':
        logConfig = arg;
        break;
    case 'c':
        tlslookieloo::certFilesPath = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    log4cplus::Initializer initializer;
    log4cplus::BasicConfigurator::doConfigure();
    auto logger = log4cplus::Logger::getRoot();
    logger.setLogLevel(log4cplus::FATAL_LOG_LEVEL);

    testing::InitGoogleMock(&argc, argv);

    struct argp_option options[] = {
        { "targets", 't', "tgtfile", 0, "Path to test target files" },
        { "logconfig", 'l', "logcfg", 0, "log4cplus configuration file" },
        { "certs", 'c', "certpath", 0, "Path to test certificate files" },
        { 0 }
    };

    struct argp argp = {
        reinterpret_cast<struct argp_option *>(&options[0]), // NOLINT
        parseArgs,
        "",
        "tlslookieloo unit tests" 
    };

    argp_parse(&argp, argc, argv, 0, nullptr, nullptr);

    if(logConfig.size() != 0)
    {
        logger.getHierarchy().resetConfiguration();
        log4cplus::PropertyConfigurator::doConfigure(logConfig);
    }

    return RUN_ALL_TESTS();
}
