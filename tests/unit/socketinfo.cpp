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
#include <system_error>

#include "socketinfo.h"

using namespace testing;
using namespace std;

using ::testing::MatchesRegex;

namespace tlslookieloo
{

std::function<int(int, fd_set *, fd_set *, fd_set *, struct timeval *)>
    selectFunc;

extern "C"
{

int select(int nfds, fd_set *readFds, fd_set *writeFds, fd_set *exceptFds,
    struct timeval *timeout)
{
    return selectFunc(nfds, readFds, writeFds, exceptFds, timeout);
}

}

TEST(SocketInfo, waitForReadingReady) // NOLINT
{
    SocketInfo s;
    s.setSocket(4);

    selectFunc =
        [](int, fd_set *readFds, fd_set *, fd_set *, struct timeval *)->int{
            EXPECT_TRUE(FD_ISSET(4, readFds));
            FD_ZERO(readFds);
            FD_SET(4, readFds);

            return 1;
        };

    EXPECT_TRUE(s.waitForReading());
}

TEST(SocketInfo, waitForReadingTimeout) // NOLINT
{
    SocketInfo s;
    s.setSocket(4);

    selectFunc =
        [](int, fd_set *readFds, fd_set *, fd_set *, struct timeval *)->int {
            EXPECT_TRUE(FD_ISSET(4, readFds));
            return 0;
        };

    EXPECT_FALSE(s.waitForReading());
}

TEST(SocketInfo, waitForReadingSetTimeout) // NOLINT
{
    SocketInfo s;
    s.setSocket(10);
    s.setTimeout(100);

    selectFunc =
        [](int, fd_set *, fd_set *, fd_set *, struct timeval *timeout)->int {
            EXPECT_NE(timeout, nullptr);
            if(timeout)
                EXPECT_EQ(100, timeout->tv_sec);
            else
                ADD_FAILURE() << "timeout param is nullptr";
            return 1;
        };

    s.waitForReading();
}

TEST(SocketInfo, waitForReadingInterrupted) // NOLINT
{
    SocketInfo s;
    s.setSocket(5);

    selectFunc =
        [](int, fd_set *readFds, fd_set *, fd_set *, struct timeval *)->int{
            EXPECT_TRUE(FD_ISSET(5, readFds));
            errno = 0;
            return -1;
        };

    EXPECT_FALSE(s.waitForReading());
}

TEST(SocketInfo, waitForReadingError) // NOLINT
{
    SocketInfo s;
    s.setSocket(5);

    selectFunc =
        [](int, fd_set *readFds, fd_set *, fd_set *, struct timeval *)->int{
            errno = EBADF;
            return -1;
        };

    EXPECT_THROW(s.waitForReading(), system_error);
}

TEST(SocketInfo, waitForReadingNoTimeout) // NOLINT
{
    SocketInfo s;
    s.setSocket(3);

    selectFunc =
        [](int, fd_set *readFds, fd_set *, fd_set *, struct timeval *timeout)->int{
            EXPECT_EQ(timeout, nullptr);
            return 1;
        };

    EXPECT_TRUE(s.waitForReading(false));
}

TEST(SocketInfo, waitForWritingReady) // NOLINT
{
    SocketInfo s;
    s.setSocket(4);

    selectFunc =
        [](int, fd_set *readFds, fd_set *writeFds, fd_set *exceptFds, struct timeval *timeout)->int{
            EXPECT_EQ(readFds, nullptr);
            EXPECT_EQ(exceptFds, nullptr);
            EXPECT_TRUE(FD_ISSET(4, writeFds));
            FD_ZERO(writeFds);
            FD_SET(4, writeFds);

            return 1;
        };

    EXPECT_TRUE(s.waitForWriting());
}

TEST(SocketInfo, waitForWritingTimeout) // NOLINT
{
    SocketInfo s;
    s.setSocket(4);

    selectFunc =
        [](int, fd_set *, fd_set *writeFds, fd_set *, struct timeval *)->int{
            EXPECT_TRUE(FD_ISSET(4, writeFds));
            return 0;
        };

    EXPECT_FALSE(s.waitForWriting());
}

TEST(SocketInfo, waitForWritingSetTimeout) // NOLINT
{
    SocketInfo s;
    s.setSocket(10);
    s.setTimeout(100);

    selectFunc =
        [](int, fd_set *, fd_set *, fd_set *, struct timeval *timeout)->int {
            EXPECT_NE(timeout, nullptr);
            if(timeout)
                EXPECT_EQ(100, timeout->tv_sec);
            else
                ADD_FAILURE() << "timeout param is nullptr";
            return 1;
        };

    s.waitForWriting();
}

TEST(SocketInfo, waitForWritingInterrupted) // NOLINT
{
    SocketInfo s;
    s.setSocket(5);

    selectFunc =
        [](int, fd_set *, fd_set *writeFds, fd_set *, struct timeval *)->int{
            EXPECT_TRUE(FD_ISSET(5, writeFds));
            errno = 0;
            return -1;
        };

    EXPECT_FALSE(s.waitForWriting());
}

TEST(SocketInfo, waitForWritingError) // NOLINT
{
    SocketInfo s;
    s.setSocket(5);

    selectFunc =
        [](int, fd_set *, fd_set *, fd_set *, struct timeval *)->int{
            errno = EBADF;
            return -1;
        };

    EXPECT_THROW(s.waitForWriting(), system_error);
}

TEST(SocketInfo, waitForWritingNoTimeout) // NOLINT
{
    SocketInfo s;
    s.setSocket(3);

    selectFunc =
        [](int, fd_set *, fd_set *, fd_set *, struct timeval *timeout)->int{
            EXPECT_EQ(timeout, nullptr);
            return 1;
        };

    EXPECT_TRUE(s.waitForWriting(false));
}

} //namespace tlslookieloo
