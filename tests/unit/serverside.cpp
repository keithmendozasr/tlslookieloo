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

MATCHER_P(IsFdSet, fd, "fd is set")
{
    return arg != nullptr && FD_ISSET(fd, arg);
}

class ServerSideTest : public ::testing::Test
{
protected:
    shared_ptr<MockWrapper> mock;
    ServerSide client;
    int fd = 4;

    ServerSideTest() :
        mock(make_shared<MockWrapper>()),
        client(mock)
    {}

    void SetUp() override
    {
        client.setSocket(fd);
        client.newSSLCtx();
        client.newSSLObj();
    }
};

TEST_F(ServerSideTest, socketReadyGood) // NOLINT
{
    EXPECT_CALL(
        (*mock),
        select(5, IsNull(), IsFdSet(fd), IsNull(), NotNull())
    ).WillOnce(Return(1));

    EXPECT_NO_THROW(EXPECT_TRUE(client.socketReady()));
}

TEST_F(ServerSideTest, socketReadyBadFd) // NOLINT
{
    EXPECT_CALL(
        (*mock),
        select(5, IsNull(), IsFdSet(fd), IsNull(), NotNull())
    ).WillOnce(DoAll(WithArg<2>(Invoke(
        [](fd_set *set){
            FD_ZERO(set);
            FD_SET(7, set);
        })),
        Return(-1)));

    EXPECT_THROW(client.socketReady(), system_error);
}

TEST_F(ServerSideTest, socketReadyTimeout) // NOLINT
{
    EXPECT_CALL(
        (*mock),
        select(5, IsNull(), IsFdSet(fd), IsNull(), NotNull())
    ).WillOnce(Return(0));

    EXPECT_NO_THROW(EXPECT_FALSE(client.socketReady()));
}

} //namespace tlslookieloo
