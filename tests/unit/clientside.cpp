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

class ClientSideTest : public ::testing::Test
{
protected:
    shared_ptr<MockWrapper> mock;
    ClientSide client;
    int fd = 4;

    ClientSideTest() :
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

TEST_F(ClientSideTest, waitSocketReadableGood) // NOLINT
{
    EXPECT_CALL(
        (*mock),
        select(5, IsFdSet(fd), IsNull(), IsNull(), IsNull())
    ).WillOnce(Return(1));
    
    EXPECT_NO_THROW(client.waitSocketReadable());
}

TEST_F(ClientSideTest, waitSocketReadableError) // NOLINT
{
    EXPECT_CALL(
        (*mock),
        select(5, IsFdSet(fd), IsNull(), IsNull(), IsNull())
    ).WillOnce(Return(-1));
    
    EXPECT_THROW(client.waitSocketReadable(), system_error);
}

} //namespace tlslookieloo
