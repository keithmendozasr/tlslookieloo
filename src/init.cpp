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

const vector<TargetItem> parseTargetsFile(const string &file)
{
    vector<TargetItem> retVal;

    auto logger = Logger::getRoot();
    LOG4CPLUS_INFO(logger, "Parsing targets file"); // NOLINT
    auto node = LoadFile(file);
    if(!node.IsSequence())
    {
        // NOLINTNEXTLINE
        LOG4CPLUS_ERROR(logger, "targets file " << file <<
            " did not contain a sequence of target definitions");
        throw YAML::Exception(node.Mark(), "File doesn't contain a sequence");
    }

    for(auto item : node)
    {
        if(logger.isEnabledFor(log4cplus::TRACE_LOG_LEVEL))
        {
            LOG4CPLUS_DEBUG(logger, "target node"); // NOLINT
            LOG4CPLUS_DEBUG(logger, "name: " << // NOLINT
                (item["name"] ? item["name"].as<string>() : "Not set"));
            LOG4CPLUS_DEBUG(logger, "client port: " << // NOLINT
                (item["clientport"] ? item["clientport"].as<string>() : "Not set"));
            LOG4CPLUS_DEBUG(logger, "server: " << // NOLINT
                (item["serverhost"] ? item["serverhost"].as<string>() : "") << ":" <<
                (item["serverport"] ? item["serverport"].as<string>() : "")
            );
        }

        if(!item["name"])
            throw YAML::Exception(item.Mark(), "name field missing");

        if(!item["serverhost"])
            throw YAML::Exception(item.Mark(), "serverhost field missing");

        if(!item["serverport"])
            throw YAML::Exception(item.Mark(), "serverport field missing");

        if(!item["clientport"])
            throw YAML::Exception(item.Mark(), "clientport field missing");

        if(!item["clientcert"])
            throw YAML::Exception(item.Mark(), "clientcert field missing");

        if(!item["recordfile"])
            throw YAML::Exception(item.Mark(), "recordfile field missing");

        optional<string> clientKey;
        if(item["clientkey"])
            clientKey = item["clientkey"].as<string>();

        optional<string> clientAuthCert, clientAuthKey, clientAuthCA;
        if(item["clientauthcert"] || item["clientauthkey"] || item["clientauthca"])
        {
            if(!item["clientauthcert"])
                throw YAML::Exception(item.Mark(), "clientauthcert field missing");
            else
            {
                LOG4CPLUS_DEBUG(logger, "clientauthcert field provided"); // NOLINT
                clientAuthCert = item["clientauthcert"].as<string>();
            }

            if(!item["clientauthca"])
                throw YAML::Exception(item.Mark(), "clientauthca field missing");
            else
            {
                LOG4CPLUS_DEBUG(logger, "clientauthca field provided"); // NOLINT
                clientAuthCA = item["clientauthca"].as<string>();
            }

            if(item["clientauthkey"])
            {
                LOG4CPLUS_DEBUG(logger, "clientauthkey field provided"); // NOLINT
                clientAuthKey = item["clientauthkey"].as<string>();
            }
            else
                LOG4CPLUS_TRACE(logger, "clientauthkey not provided"); // NOLINT
        }

        optional<unsigned int> timeout;
        if(item["timeout"])
            timeout = item["timeout"].as<unsigned int>();

        retVal.push_back({
            item["name"].as<string>(),
            item["serverhost"].as<string>(),
            item["serverport"].as<unsigned int>(),

            (item["serverinsecure"] ? item["serverinsecure"].as<bool>() : false),

            item["clientport"].as<unsigned int>(),
            item["clientcert"].as<string>(),
            item["recordfile"].as<string>(),
            clientKey,
            clientAuthCert,
            clientAuthKey,
            clientAuthCA,
            timeout
        });
    }

    return retVal;
}

} //namespace tlslookieloo
