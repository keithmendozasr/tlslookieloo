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

#pragma once

#include <string>
#include <vector>
#include <tuple>

namespace tlslookieloo
{

typedef std::tuple<
    const std::string,  // name
    const std::string,  // server-side host
    const unsigned int, // server-side port
    const unsigned int, // client-side listen port
    const std::string,  // client-side server cert
    const std::string   // client-side server key
> TargetItem;

/**
 * Parse the targets file
 * \arg file Targets file path
 * \exception YAML::Exception
 */
const std::vector<TargetItem> parseTargetsFile(const std::string &file);

} //namespace tlslookieloo
