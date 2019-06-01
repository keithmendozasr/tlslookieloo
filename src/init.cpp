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

#include <log4cplus/loggingmacros.h>
#include <log4cplus/logger.h>

#include <yaml-cpp/yaml.h>

#include "init.h"

using namespace std;
using namespace log4cplus;
using namespace YAML;

namespace tlslookieloo
{

const vector<Target> parseTargetsFile(const string &file)
{
    vector<Target> retVal;

    auto logger = Logger::getRoot();
    LOG4CPLUS_INFO(logger, "Parsing targets file");
    auto node = LoadFile(file);
    if(!node.IsSequence())
    {
        LOG4CPLUS_ERROR(logger, "targets file " << file <<
            " did not contain a sequence of target definitions");
        throw YAML::Exception(node.Mark(), "File doesn't contain a sequence");
    }

    for(auto item : node)
    {
        if(logger.isEnabledFor(log4cplus::TRACE_LOG_LEVEL))
        {
            LOG4CPLUS_DEBUG(logger, "target node");
            LOG4CPLUS_DEBUG(logger, "name: " <<
                (item["name"] ? item["name"].as<string>() : "Not set"));
            LOG4CPLUS_DEBUG(logger, "client: " <<
                (item["client"] ? item["client"].as<string>() : "Not set"));
            LOG4CPLUS_DEBUG(logger, "server: " <<
                (item["server"] ? item["server"].as<string>() : "Not set"));
        }

        if(!item["name"])
            throw YAML::Exception(item.Mark(), "Name missing");

        if(!item["client"])
            throw YAML::Exception(item.Mark(), "Client missing");

        if(!item["server"])
            throw YAML::Exception(item.Mark(), "Server missing");

        retVal.push_back({ item["name"].as<string>(),
            item["client"].as<string>(),
            item["server"].as<string>()
        });
    }

    return retVal;
}

} //namespace tlslookieloo
