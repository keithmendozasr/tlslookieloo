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
    // NOLINTNEXTLINE
    EXPECT_NO_THROW({
        auto retVal = parseTargetsFile(tgtFilesPath + "/good_targets.yaml");
        EXPECT_EQ(retVal.size(), 2u);

        {
            auto item = retVal[0];
            EXPECT_EQ(item.name, "App1");
            EXPECT_EQ(item.serverHost, "server");
            EXPECT_EQ(item.serverPort, 8908u);
            EXPECT_FALSE(item.serverInsecure);
            EXPECT_EQ(item.clientPort, 9988u);
            EXPECT_EQ(item.clientCert, "test_certs/cert.pem");
            EXPECT_EQ(item.recordFile, "app1.msgs");
            EXPECT_FALSE(item.clientKey);
            EXPECT_FALSE(item.clientAuthCert);
            EXPECT_FALSE(item.clientAuthKey);
            EXPECT_FALSE(item.clientAuthCA);
            EXPECT_FALSE(item.timeout);
        }

        {
            auto item = retVal[1];
            EXPECT_EQ(item.name, "App2");
            EXPECT_EQ(item.serverHost, "servertwo");
            EXPECT_FALSE(item.serverInsecure);
            EXPECT_EQ(item.serverPort, 9087u);
            EXPECT_EQ(item.clientPort, 8899u);
            EXPECT_EQ(item.clientCert, "test_certs/certapp2.pem");
            EXPECT_EQ(item.recordFile, "app2.msgs");
            EXPECT_FALSE(item.clientKey);
            EXPECT_FALSE(item.clientAuthCert);
            EXPECT_FALSE(item.clientAuthKey);
            EXPECT_FALSE(item.clientAuthCA);
            EXPECT_FALSE(item.timeout);
        }
    });
}

TEST(parseTargetsFile, serverInsecure) // NOLINT
{
    auto retVal = parseTargetsFile(tgtFilesPath + "/serverinsecure.yaml");
    EXPECT_EQ(retVal.size(), 2u);

    {
        auto item = retVal[0];
        EXPECT_EQ(item.name, "App1");
        EXPECT_EQ(item.serverHost, "server");
        EXPECT_EQ(item.serverPort, 8908u);
        EXPECT_FALSE(item.serverInsecure);
        EXPECT_EQ(item.clientPort, 9988u);
        EXPECT_EQ(item.clientCert, "test_certs/cert.pem");
        EXPECT_EQ(item.recordFile, "app1.msgs");
    }

    {
        auto item = retVal[1];
        EXPECT_EQ(item.name, "App2");
        EXPECT_EQ(item.serverHost, "servertwo");
        EXPECT_TRUE(item.serverInsecure);
        EXPECT_EQ(item.serverPort, 9087u);
        EXPECT_EQ(item.clientPort, 8899u);
        EXPECT_EQ(item.clientCert, "test_certs/certapp2.pem");
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

TEST(parseTargetsFile, withclientkey) // NOLINT
{
    // NOLINTNEXTLINE
    EXPECT_NO_THROW({
        auto retVal = parseTargetsFile(tgtFilesPath + "/withclientkey.yaml");
        auto item = retVal[0];
        EXPECT_EQ(string("test_certs/key.pem"), item.clientKey.value());
    });
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

TEST(parseTargetsFile, noclientauth) // NOLINT
{
    // NOLINTNEXTLINE
    EXPECT_NO_THROW({
        auto retVal = parseTargetsFile(tgtFilesPath + "/good_targets.yaml");
        auto item = retVal[0];
        EXPECT_FALSE(item.clientAuthCert);
        EXPECT_FALSE(item.clientAuthKey);
    });
}

TEST(parseTargetsFile, clientauthfull) // NOLINT
{
    // NOLINTNEXTLINE
    EXPECT_NO_THROW({
        auto retVal = parseTargetsFile(tgtFilesPath + "/clientauth_full.yaml");
        auto item = retVal[0];
        EXPECT_EQ(item.clientAuthCert.value(), "testclientauth.pem");
        EXPECT_EQ(item.clientAuthKey.value(), "testclientauthkey.pem");
        EXPECT_EQ(item.clientAuthCA.value(), "devca.pem");
    });
}

TEST(parseTargetsFile, clientauthminimal) // NOLINT
{
    // NOLINTNEXTLINE
    EXPECT_NO_THROW({
        auto retVal = parseTargetsFile(tgtFilesPath + "/clientauth_minimal.yaml");
        auto item = retVal[0];
        EXPECT_EQ(item.clientAuthCert.value(), "testclientauth.pem");
        EXPECT_EQ(item.clientAuthCA.value(), "devca.pem");
    });
}

TEST(parseTargetsFile, clientauthnocert) // NOLINT
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

    try
    {
        parseTargetsFile(tgtFilesPath + "/clientauth_nocert2.yaml");
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

TEST(parseTargetsFile, clientauthnoca) // NOLINT
{
    try
    {
        parseTargetsFile(tgtFilesPath + "/clientauth_noca.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*clientauthca field missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
    
    try
    {
        parseTargetsFile(tgtFilesPath + "/clientauth_noca2.yaml");
        FAIL() << "Exception not thrown";
    }
    catch(YAML::Exception &e)
    {
        ASSERT_THAT(e.what(), MatchesRegex(".*clientauthca field missing$"));
    }
    catch(...)
    {
        FAIL() << "Incorrect exception";
    }
}

TEST(parseTargetsFile, withtimeout) // NOLINT
{
    // NOLINTNEXTLINE
    EXPECT_NO_THROW({
        auto retVal = parseTargetsFile(tgtFilesPath + "/withtimeout.yaml");
        auto item = retVal[0];
        EXPECT_EQ(100u, item.timeout.value());
    });
}

TEST(parseTargetsFile, withservercachainfile) // NOLINT
{
    // NOLINTNEXTLINE
    EXPECT_NO_THROW({
        auto retVal = parseTargetsFile(tgtFilesPath + "/withservercachainfile.yaml");
        auto item = retVal[0];
        EXPECT_EQ("servercachain.pem", item.serverCAChainFile.value());
    });
}

} //namespace tlslookieloo
