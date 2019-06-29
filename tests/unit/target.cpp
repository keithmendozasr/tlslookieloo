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

#include <cerrno>

#include "log4cplus/ndc.h"

#include "config.h"
#include "mockcapi.h"
#include "target.h"

using namespace testing;
using namespace std;

namespace tlslookieloo
{

class TargetTest : public ::testing::Test
{
protected:
    ClientSide client;
    ServerSide server;

    void SetUp() override
    {
        client.newSSLCtx();
        client.newSSLObj();

        server.newSSLCtx();
        server.newSSLObj();
    }
};

TEST_F(TargetTest, passClientToServerGood) // NOLINT
{
    Target obj;

    const char expectData[] = "abc";
    sslReadFunc =
        [&obj, &expectData](SSL *ssl, void *buf, int num)
        {
            obj.stop();
            memcpy(buf, &expectData[0], 4);
            return 4;
        };

    sslWriteFunc =
        [&expectData](SSL *ssl, const void *buf, int num)
        {
            EXPECT_EQ(4, num);
            EXPECT_STREQ(expectData, reinterpret_cast<const char*>(buf));
            return 4;
        };

    EXPECT_TRUE(obj.passClientToServer(client, server));
}

TEST_F(TargetTest, passClientToServerNoData) // NOLINT
{
    log4cplus::NDCContextCreator logCtx("passClientToServerNoData");

    Target obj;

    setNoReadableData();
    sslWriteFunc =
        [](SSL *ssl, const void *buf, int num)
        {
            ADD_FAILURE() << "Unexpected call to SSL_write()";
            return -1;
        };

    EXPECT_FALSE(obj.passClientToServer(client, server));
}

TEST_F(TargetTest, passClientToServerRemoteDisconnect)
{
    Target obj;

    setRemoteDisconnectWrite();
    EXPECT_FALSE(obj.passClientToServer(client, server));
}

} //namespace tlslookieloo
