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

#include "gmock/gmock.h"

#include <cerrno>

#include "log4cplus/ndc.h"

#include "config.h"
#include "target.h"
#include "mockwrapper.h"

using namespace testing;
using namespace std;

namespace tlslookieloo
{

MATCHER_P(IsFdSet, fd, "fd is set") // NOLINT
{
    return arg != nullptr && FD_ISSET(fd, arg); // NOLINT
}

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
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

    virtual void SetUp() override
    {
        client.setSocket(fd);
        client.newSSLCtx();
        client.newSSLObj();
        client.socketIP = "unit_test";
    }

    virtual ~ServerSideTest(){}
};

TEST_F(ServerSideTest, waitForConnectgetsockoptError) // NOLINT
{
    setDefaultselect(mock);

    EXPECT_CALL((*mock),
        getsockopt(4, SOL_SOCKET, SO_ERROR, NotNull(), Pointee(sizeof(int))))
        .WillOnce(Return(EACCES));

    EXPECT_THROW(client.waitForConnect(), system_error); // NOLINT
}

TEST_F(ServerSideTest, waitForConnectConnFail) // NOLINT
{
    setDefaultselect(mock);

    EXPECT_CALL((*mock),
        getsockopt(4, SOL_SOCKET, SO_ERROR, NotNull(), Pointee(sizeof(int))))
        .WillOnce(WithArg<3>(
            [](void *opt)->int
            {
                int *val = reinterpret_cast<int *>(opt); // NOLINT
                *val = ETIMEDOUT;
                return 0;
            }
        ));

    EXPECT_FALSE(client.waitForConnect());
}

TEST_F(ServerSideTest, waitForConnectTimeout) // NOLINT
{
    EXPECT_CALL((*mock), select(_, _, _, _, _))
        .WillOnce(Return(0));

    // NOLINTNEXTLINE
    EXPECT_NO_THROW(
        EXPECT_FALSE(client.waitForConnect())
    );
}

TEST_F(ServerSideTest, waitForConnectGood) // NOLINT
{
    setDefaultselect(mock);
    EXPECT_CALL((*mock),
        getsockopt(4, SOL_SOCKET, SO_ERROR, NotNull(), Pointee(sizeof(int))))
        .WillOnce(WithArg<3>(
            [](void *opt)->int
            {
                int *val = reinterpret_cast<int *>(opt); // NOLINT
                *val = 0;
                return 0;
            }
        ));

    // NOLINTNEXTLINE
    EXPECT_NO_THROW(
        EXPECT_TRUE(client.waitForConnect())
    );
}

TEST_F(ServerSideTest, socketReadyGood) // NOLINT
{
    EXPECT_CALL(
        (*mock),
        select(5, IsNull(), IsFdSet(fd), IsNull(), NotNull())
    ).WillOnce(Return(1));

    EXPECT_NO_THROW(EXPECT_TRUE(client.socketReady())); // NOLINT
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

    EXPECT_THROW(client.socketReady(), system_error); // NOLINT
}

TEST_F(ServerSideTest, socketReadyTimeout) // NOLINT
{
    EXPECT_CALL(
        (*mock),
        select(5, IsNull(), IsFdSet(fd), IsNull(), NotNull())
    ).WillOnce(Return(0));

    EXPECT_NO_THROW(EXPECT_FALSE(client.socketReady())); // NOLINT
}

} //namespace tlslookieloo
