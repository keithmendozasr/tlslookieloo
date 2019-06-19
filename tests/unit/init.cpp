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

#include <tuple>

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
        auto item = retVal[0];
        EXPECT_EQ(get<0>(item), "App1");
        EXPECT_EQ(get<1>(item), "server");
        EXPECT_EQ(get<2>(item), 8908u);
        EXPECT_EQ(get<3>(item), 9988u);
        EXPECT_EQ(get<4>(item), "test_certs/cert.pem");
        EXPECT_EQ(get<5>(item), "test_certs/key.pem");
    }

    {
        auto item = retVal[1];
        EXPECT_EQ(get<0>(item), "App2");
        EXPECT_EQ(get<1>(item), "servertwo");
        EXPECT_EQ(get<2>(item), 9087u);
        EXPECT_EQ(get<3>(item), 8899u);
        EXPECT_EQ(get<4>(item), "test_certs/certapp2.pem");
        EXPECT_EQ(get<5>(item), "test_certs/keyapp2.pem");
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
        ASSERT_THAT(e.what(), MatchesRegex(".*name field missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, missingclientport) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/missingclientport.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*clientport field missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, missingclientcert) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/missingclientcert.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*clientcert field missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, missingclientkey) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/missingclientkey.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*clientkey field missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, missingserverport) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/missingserverport.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*serverport field missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, missingserverhost) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/missingserverhost.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*serverhost field missing$"));
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
