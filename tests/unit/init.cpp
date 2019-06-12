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

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include <yaml-cpp/exceptions.h>

#include "config.h"
#include "init.h"

using namespace testing;
using namespace std;

using ::testing::MatchesRegex;

namespace tlslookieloo
{

TEST(parseTargetsFile, goodFile) // NOLINT
{
    auto retVal = parseTargetsFile(tgtFilesPath + "/good_targets.yaml");
    EXPECT_EQ(retVal.size(), 2u);

    {
        Target &item = retVal[0];
        EXPECT_EQ(item.name, "App1");
        EXPECT_EQ(item.client, "9988");
        EXPECT_EQ(item.server, "192.168.56.6:443");
    }

    {
        Target &item = retVal[1];
        EXPECT_EQ(item.name, "App2");
        EXPECT_EQ(item.client, "9980");
        EXPECT_EQ(item.server, "192.168.56.6:2020");
    }
}

TEST(parseTargetsFile, missingname) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/missingname.yaml");
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*Name missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, missingclient) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/missingclient.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*Client missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, missingserver) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/missingserver.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*Server missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, nonsequence) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/notsequence.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*File doesn't contain a sequence$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

} //namespace tlslookieloo
