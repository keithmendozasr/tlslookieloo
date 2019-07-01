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
#include "gtest/gtest.h"

#include <cerrno>
#include <system_error>

#include "mockcapi.h"
#include "mockwrapper.h"
#include "socketinfo.h"

using namespace testing;
using namespace std;

namespace tlslookieloo
{

MATCHER_P(IsFdSet, fd, "fd is set")
{
    return arg != nullptr && FD_ISSET(fd, arg);
}

TEST(SocketInfo, waitForReadingReady) // NOLINT
{
    const int fd = 4;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(1));

    SocketInfo s(mock);
    s.setSocket(fd);

    EXPECT_TRUE(s.waitForReading());
}

TEST(SocketInfo, waitForReadingTimeout) // NOLINT
{
    const int fd = 4;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(0));

    SocketInfo s(mock);
    s.setSocket(fd);
    EXPECT_FALSE(s.waitForReading());
}

TEST(SocketInfo, waitForReadingSetTimeout) // NOLINT
{
    const int fd = 10;
    const long timeout = 100;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            AllOf(NotNull(), Field(&timeval::tv_sec, timeout))))
        .WillOnce(Return(0));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.setTimeout(timeout);
    EXPECT_FALSE(s.waitForReading());
}

TEST(SocketInfo, waitForReadingInterrupted) // NOLINT
{
    {
        const int fd = 5;
        auto mock = make_shared<MockWrapper>();
        errno = EINTR;
        EXPECT_CALL(
            (*mock),
            select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(-1));

        SocketInfo s(mock);
        s.setSocket(fd);
        EXPECT_FALSE(s.waitForReading());
    }

    {
        const int fd = 5;
        auto mock = make_shared<MockWrapper>();
        errno = 0;
        EXPECT_CALL(
            (*mock),
            select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(-1));

        SocketInfo s(mock);
        s.setSocket(fd);
        EXPECT_FALSE(s.waitForReading());
    }
}

TEST(SocketInfo, waitForReadingError) // NOLINT
{
    const int fd = 5;
    auto mock = make_shared<MockWrapper>();
    errno = EBADF;
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(-1));

    SocketInfo s(mock);
    s.setSocket(fd);
    EXPECT_THROW(s.waitForReading(), system_error); // NOLINT
    errno = 0;
}

TEST(SocketInfo, waitForReadingNoTimeout) // NOLINT
{
    const int fd = 4;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            IsNull()))
        .WillOnce(Return(1));

    SocketInfo s(mock);
    s.setSocket(fd);
    EXPECT_TRUE(s.waitForReading(false));
}

TEST(SocketInfo, waitForWritingReady) // NOLINT
{
    const int fd = 4;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(1));

    SocketInfo s(mock);
    s.setSocket(fd);
    EXPECT_TRUE(s.waitForWriting());
}

TEST(SocketInfo, waitForWritingTimeout) // NOLINT
{
    const int fd = 4;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(0));

    SocketInfo s(mock);
    s.setSocket(fd);
    EXPECT_FALSE(s.waitForWriting());
}

TEST(SocketInfo, waitForWritingSetTimeout) // NOLINT
{
    const int fd = 10;
    const long timeout = 100;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            AllOf(NotNull(), Field(&timeval::tv_sec, timeout))))
        .WillOnce(Return(0));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.setTimeout(timeout);
    EXPECT_FALSE(s.waitForReading());
}

TEST(SocketInfo, waitForWritingInterrupted) // NOLINT
{
    {
        const int fd = 5;
        auto mock = make_shared<MockWrapper>();
        errno = EINTR;
        EXPECT_CALL(
            (*mock),
            select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(-1));

        SocketInfo s(mock);
        s.setSocket(fd);
        EXPECT_FALSE(s.waitForWriting());
    }

    {
        const int fd = 5;
        auto mock = make_shared<MockWrapper>();
        errno = 0;
        EXPECT_CALL(
            (*mock),
            select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(-1));

        SocketInfo s(mock);
        s.setSocket(fd);
        EXPECT_FALSE(s.waitForWriting());
    }
}

TEST(SocketInfo, waitForWritingError) // NOLINT
{
    const int fd = 5;
    auto mock = make_shared<MockWrapper>();
    errno = EBADF;
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(-1));

    SocketInfo s(mock);
    s.setSocket(fd);
    EXPECT_THROW(s.waitForWriting(), system_error); // NOLINT
    errno = 0;
}

TEST(SocketInfo, waitForWritingNoTimeout) // NOLINT
{
    const int fd = 5;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
            IsNull()))
        .WillOnce(Return(1));

    SocketInfo s(mock);
    s.setSocket(fd);
    EXPECT_TRUE(s.waitForWriting(false));
}

TEST(SocketInfo, handleRetryWantReadOK) // NOLINT
{
    const int fd = 5;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(1));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.newSSLCtx();
    s.newSSLObj();
    EXPECT_TRUE(s.handleRetry(-1));
}

TEST(SocketInfo, handleRetryWantReadFail) // NOLINT
{
    const int fd = 41;
    auto mock = make_shared<MockWrapper>();
    errno = EBADF;
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(-1));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.newSSLCtx();
    s.newSSLObj();
    EXPECT_THROW(s.handleRetry(-1), system_error);
    errno = 0;
}

TEST(SocketInfo, handleRetryWantReadTimeout) // NOLINT
{
    const int fd = 41;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(0));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.newSSLCtx();
    s.newSSLObj();
    EXPECT_FALSE(s.handleRetry(-1));
}

TEST(SocketInfo, handleRetryWantWriteOK) // NOLINT
{
    const int fd = 4;
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(1));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_WANT_WRITE));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.newSSLCtx();
    s.newSSLObj();
    EXPECT_TRUE(s.handleRetry(-1));
}

TEST(SocketInfo, handleRetryWantWriteFail) // NOLINT
{
    const int fd = 4;
    auto mock = make_shared<MockWrapper>();
    errno = EBADF;
    EXPECT_CALL(
        (*mock),
        select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(-1));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_WANT_WRITE));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.newSSLCtx();
    s.newSSLObj();
    EXPECT_THROW(s.handleRetry(-1), system_error);
    errno = 0;
}

TEST(SocketInfo, handleRetryRemoteDisconnect) // NOLINT
{
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_ZERO_RETURN));

    SocketInfo s(mock);
    s.setSocket(4);
    s.newSSLCtx();
    s.newSSLObj();

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
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_SYSCALL));
    errno = 0;

    SocketInfo s(mock);
    s.newSSLCtx();
    s.newSSLObj();

    sslReadFunc =
        [](SSL *, void *, int)
        {
            return -1;
        };
    char buf[1];
    sslReadFunc =
        [](SSL *, void *buf, int num)
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
    auto mock = make_shared<MockWrapper>();
    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_ZERO_RETURN));
    errno = 0;

    SocketInfo s(mock);
    s.newSSLCtx();
    s.newSSLObj();

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
