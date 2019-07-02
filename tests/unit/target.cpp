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
#include "target.h"
#include "mockwrapper.h"

using namespace testing;
using namespace std;

namespace tlslookieloo
{

MATCHER_P(IsVoidEqStr, str, "")
{
    return string(static_cast<const char*>(arg)) == str;
}

MATCHER_P2(IsFdSet, clientFd, serverFd, "fd is set")
{
    return arg != nullptr && FD_ISSET(clientFd, arg) && FD_ISSET(serverFd, arg);
}

class TargetTest : public ::testing::Test
{
protected:
    shared_ptr<MockWrapper> mock;
    ClientSide client;
    ServerSide server;

    TargetTest() :
        client(mock),
        server(mock)
    {}

    void SetUp() override
    {
        mock = make_shared<MockWrapper>();
        client = ClientSide(mock);
        client.newSSLCtx();
        client.newSSLObj();

        server = ServerSide(mock);
        server.newSSLCtx();
        server.newSSLObj();
    }

    void TearDown() override
    {
        mock = nullptr;
    };
};

TEST_F(TargetTest, passClientToServerGood) // NOLINT
{
    const char expectData[] = "abc";
    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 1024))
        .WillOnce(DoAll(WithArg<1>(Invoke(
            [expectData](void *ptr){
                memcpy(ptr, expectData, 4);
            })),
            Return(4)));

    EXPECT_CALL((*mock), SSL_write(NotNull(), IsVoidEqStr(expectData), 4))
        .WillOnce(Return(4));

    Target obj;
    EXPECT_TRUE(obj.passClientToServer(client, server));
}

TEST_F(TargetTest, passClientToServerNoData) // NOLINT
{
    EXPECT_CALL((*mock), SSL_get_error(_, _))
        .WillOnce(Return(SSL_ERROR_SYSCALL));
    errno = 0;

    EXPECT_CALL((*mock), SSL_read(_, _, _))
        .WillOnce(Return(-1));

    EXPECT_CALL((*mock), SSL_write(_, _, _))
        .Times(0);

    Target obj;
    EXPECT_FALSE(obj.passClientToServer(client, server));
}

TEST_F(TargetTest, passClientToServerRemoteDisconnect) // NOLINT
{
    const char expectData[] = "abc";
    EXPECT_CALL((*mock), SSL_read(_, _, _))
        .WillRepeatedly(DoAll(WithArg<1>(Invoke(
            [expectData](void *ptr){
                memcpy(ptr, expectData, 4);
            })),
            Return(4)));

    EXPECT_CALL((*mock), SSL_get_error(_, _))
        .WillOnce(Return(SSL_ERROR_ZERO_RETURN));
    errno = 0;

    EXPECT_CALL((*mock), SSL_write(_, _, _))
        .WillOnce(Return(-1));

    Target obj;
    EXPECT_FALSE(obj.passClientToServer(client, server));
}

} //namespace tlslookieloo
