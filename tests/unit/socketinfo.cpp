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

#include "mockcapi.h"
#include "socketinfo.h"

using namespace testing;
using namespace std;

namespace tlslookieloo
{

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

    EXPECT_THROW(s.waitForReading(), system_error); // NOLINT
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

    EXPECT_THROW(s.waitForWriting(), system_error); // NOLINT
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

TEST(SocketInfo, handleRetryWantReadOK) // NOLINT
{
    SocketInfo s;
    s.setSocket(4);
    s.newSSLCtx();
    s.newSSLObj();

    SSLErrCode = SSL_ERROR_WANT_READ;
    selectFunc =
        [](int, fd_set *, fd_set *, fd_set *, struct timeval *) { return 1; };
    EXPECT_TRUE(s.handleRetry(-1));
}

TEST(SocketInfo, handleRetryWantReadFail) // NOLINT
{
    SocketInfo s;
    s.setSocket(4);
    s.newSSLCtx();
    s.newSSLObj();

    SSLErrCode = SSL_ERROR_WANT_READ;
    selectFunc =
        [](int, fd_set *, fd_set *, fd_set *, struct timeval *) { return 0; };
    EXPECT_FALSE(s.handleRetry(-1));
}

TEST(SocketInfo, handleRetryWantWriteOK) // NOLINT
{
    SocketInfo s;
    s.setSocket(4);
    s.newSSLCtx();
    s.newSSLObj();

    SSLErrCode = SSL_ERROR_WANT_WRITE;
    selectFunc =
        [](int, fd_set *, fd_set *, fd_set *, struct timeval *) { return 1; };
    EXPECT_TRUE(s.handleRetry(-1));
}

TEST(SocketInfo, handleRetryWantWriteFail) // NOLINT
{
    SocketInfo s;
    s.setSocket(4);
    s.newSSLCtx();
    s.newSSLObj();

    SSLErrCode = SSL_ERROR_WANT_WRITE;
    selectFunc =
        [](int, fd_set *, fd_set *, fd_set *, struct timeval *) { return 0; };
    EXPECT_FALSE(s.handleRetry(-1));
}

TEST(SocketInfo, handleRetryRemoteDisconnect) // NOLINT
{
    SocketInfo s;
    s.setSocket(4);
    s.newSSLCtx();
    s.newSSLObj();

    SSLErrCode = SSL_ERROR_ZERO_RETURN;
    EXPECT_FALSE(s.handleRetry(-1));
}

TEST(SocketInfo, readDataExact) // NOLINT
{
    SocketInfo s;
    s.newSSLCtx();
    s.newSSLObj();

    char buf[3];
    sslReadFunc =
        [](SSL *ssl, void *buf, int num)
        {
            EXPECT_NE(ssl, nullptr);
            EXPECT_NE(buf, nullptr);
            EXPECT_EQ(num, 3);
            
            char *tmp = reinterpret_cast<char *>(buf); // NOLINT
            tmp[0] = 'a'; // NOLINT
            tmp[1] = 'b'; // NOLINT
            tmp[2] = 'c'; // NOLINT

            return 3;
        };
    auto rslt = s.readData(&buf[0], 3);
    EXPECT_TRUE(rslt);
    EXPECT_EQ(rslt.value(), 3ul);
    EXPECT_EQ(string(&buf[0], 3), string("abc"));
}

TEST(SocketInfo, readDataShort) // NOLINT
{
    SocketInfo s;
    s.newSSLCtx();
    s.newSSLObj();

    char buf[30];
    sslReadFunc =
        [](SSL *ssl, void *buf, int num)
        {
            EXPECT_NE(ssl, nullptr);
            EXPECT_NE(buf, nullptr);
            EXPECT_EQ(num, 30);
            
            char *tmp = reinterpret_cast<char *>(buf); // NOLINT
            tmp[0] = 'a'; // NOLINT
            tmp[1] = 'b'; // NOLINT
            tmp[2] = 'c'; // NOLINT
            tmp[3] = 'd'; // NOLINT
            tmp[4] = 'e'; // NOLINT
            tmp[5] = '\0'; // NOLINT

            return 6;
        };
    auto rslt = s.readData(&buf[0], 30);
    EXPECT_TRUE(rslt);
    EXPECT_EQ(rslt.value(), 6ul);
    EXPECT_STREQ(&buf[0], "abcde");
}

TEST(SocketInfo, readDataNoData) // NOLINT
{
    SocketInfo s;
    s.newSSLCtx();
    s.newSSLObj();

    SSLErrCode = SSL_ERROR_SYSCALL;
    errno = 0;
    char buf[1];
    sslReadFunc =
        [](SSL *ssl, void *buf, int num)
        {
            return -1;
        };
    auto rslt = s.readData(&buf[0], 1);
    EXPECT_FALSE(rslt);
}

TEST(SocketInfo, writeDataExact) // NOLINT
{
    SocketInfo s;
    s.newSSLCtx();
    s.newSSLObj();

    sslWriteFunc =
        [](SSL *ssl, const void *buf, int num)
        {
            EXPECT_NE(ssl, nullptr);
            EXPECT_NE(buf, nullptr);
            EXPECT_EQ(num, 3);

            // NOLINTNEXTLINE
            EXPECT_EQ(
                string(reinterpret_cast<const char *>(buf), num),
                "abc");

            return 3;
        };

    char buf[] = { 'a', 'b', 'c' };
    auto rslt = s.writeData(&buf[0], 3);
    EXPECT_EQ(rslt, 3ul);
}

TEST(SocketInfo, writeDataShort) // NOLINT
{
    SocketInfo s;
    s.newSSLCtx();
    s.newSSLObj();

    sslWriteFunc =
        [](SSL *ssl, const void *buf, int num)
        {
            EXPECT_NE(ssl, nullptr);
            EXPECT_NE(buf, nullptr);
            EXPECT_EQ(num, 7);

            // NOLINTNEXTLINE
            EXPECT_EQ(
                string(reinterpret_cast<const char *>(buf), num),
                "abcdefg"
            );

            return 2;
        };

    char buf[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
    auto rslt = s.writeData(&buf[0], 7);
    EXPECT_EQ(rslt, 2ul);
}

TEST(SocketInfo, writeDataRemoteDisconnect) // NOLINT
{
    SocketInfo s;
    s.newSSLCtx();
    s.newSSLObj();

    SSLErrCode = SSL_ERROR_ZERO_RETURN;
    errno = 0;
    sslWriteFunc =
        [](SSL *, const void *, int)
        {
            return -1;
        };

    char buf[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
    auto rslt = s.writeData(&buf[0], 7);
    EXPECT_EQ(rslt, 0ul);
}

} //namespace tlslookieloo
