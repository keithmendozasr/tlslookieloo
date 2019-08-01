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
        EXPECT_EQ(item.name, "App1");
        EXPECT_EQ(item.serverHost, "server");
        EXPECT_EQ(item.serverPort, 8908u);
        EXPECT_EQ(item.clientPort, 9988u);
        EXPECT_EQ(item.clientCert, "test_certs/cert.pem");
        EXPECT_EQ(item.clientKey, "test_certs/key.pem");
        EXPECT_EQ(item.recordFile, "app1.msgs");
    }

    {
        auto item = retVal[1];
        EXPECT_EQ(item.name, "App2");
        EXPECT_EQ(item.serverHost, "servertwo");
        EXPECT_EQ(item.serverPort, 9087u);
        EXPECT_EQ(item.clientPort, 8899u);
        EXPECT_EQ(item.clientCert, "test_certs/certapp2.pem");
        EXPECT_EQ(item.clientKey, "test_certs/keyapp2.pem");
        EXPECT_EQ(item.recordFile, "app2.msgs");
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

TEST(parseTargetsFile, missingrecordfile) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/missingrecordfile.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*recordfile field missing$"));
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

TEST(parseTargetsFile, noclientauth)
{
    EXPECT_NO_THROW({
        auto retVal = parseTargetsFile(tgtFilesPath + "/good_targets.yaml");
        auto item = retVal[0];
        EXPECT_FALSE(item.clientAuthCert);
        EXPECT_FALSE(item.clientAuthKey);
    });
}

TEST(parseTargetsFile, goodclientauth)
{
    EXPECT_NO_THROW({
        auto retVal = parseTargetsFile(tgtFilesPath + "/clientauth.yaml");
        auto item = retVal[0];
        EXPECT_EQ(item.clientAuthCert.value(), "testclientauth.pem");
        EXPECT_EQ(item.clientAuthKey.value(), "testclientauthkey.pem");
    });
}

TEST(parseTargetsFile, missingclientauthcert) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/clientauth_nocert.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*clientauthcert field missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, missingclientauthkey) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/clientauth_nokey.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*clientauthkey field missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

} //namespace tlslookieloo
