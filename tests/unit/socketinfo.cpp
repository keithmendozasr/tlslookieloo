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
#include <string>

#include "mockwrapper.h"
#include "socketinfo.h"

using namespace testing;
using namespace std;

namespace tlslookieloo
{

class SocketInfoTest : public ::testing::Test
{
protected:
    shared_ptr<MockWrapper> mock = make_shared<MockWrapper>();
};

MATCHER_P(IsFdSet, fd, "fd is set")
{
    return arg != nullptr && FD_ISSET(fd, arg);
}

MATCHER_P2(IsVoidEqStr, str, len, "")
{
    return string(static_cast<const char*>(arg), len) == str;
}

TEST_F(SocketInfoTest, handleRetryReady) // NOLINT
{
    {
        const int fd = 4;
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_READ));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(1));

        SocketInfo s(mock);
        s.setSocket(fd);
        s.newSSLCtx();
        s.newSSLObj();

        EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, s.handleRetry(-1, true));
    }

    {
        const int fd = 4;
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_WRITE));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(1));

        SocketInfo s(mock);
        s.setSocket(fd);
        s.newSSLCtx();
        s.newSSLObj();

        EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, s.handleRetry(-1, true));
    }
}

TEST_F(SocketInfoTest, handleRetryTimeout) // NOLINT
{
    const int fd = 4;
    EXPECT_CALL((*mock), SSL_get_error(_, -1))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(0));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.newSSLCtx();
    s.newSSLObj();

    EXPECT_EQ(SocketInfo::OP_STATUS::TIMEOUT, s.handleRetry(-1));
}

TEST_F(SocketInfoTest, handleRetrySetTimeout) // NOLINT
{
    const int fd = 10;
    const long timeout = 100;
    EXPECT_CALL((*mock), SSL_get_error(_, -1))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            AllOf(NotNull(), Field(&timeval::tv_sec, timeout))))
        .WillOnce(Return(0));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.newSSLCtx();
    s.newSSLObj();
    s.setTimeout(timeout);

    EXPECT_EQ(SocketInfo::OP_STATUS::TIMEOUT, s.handleRetry(-1));
}

TEST_F(SocketInfoTest, handleRetryInterrupted) // NOLINT
{
    {
        const int fd = 5;
        errno = EINTR;
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_READ));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(-1));

        SocketInfo s(mock);
        s.newSSLCtx();
        s.newSSLObj();
        s.setSocket(fd);

        EXPECT_EQ(SocketInfo::OP_STATUS::INTERRUPTED, s.handleRetry(-1));
    }

    {
        const int fd = 5;
        errno = 0;
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_WRITE));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(-1));

        SocketInfo s(mock);
        s.setSocket(fd);
        s.newSSLCtx();
        s.newSSLObj();

        EXPECT_EQ(SocketInfo::OP_STATUS::INTERRUPTED, s.handleRetry(-1));
    }
}

TEST_F(SocketInfoTest, handleRetryError) // NOLINT
{
    const int fd = 5;
    errno = EBADF;
    EXPECT_CALL((*mock), SSL_get_error(_, -1))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(-1));

    SocketInfo s(mock);
    s.setSocket(fd);
    s.newSSLCtx();
    s.newSSLObj();

    EXPECT_THROW(s.handleRetry(-1), system_error); // NOLINT
    errno = 0;
}

TEST_F(SocketInfoTest, handleRetryNoTimeout) // NOLINT
{
    const int fd = 4;
    EXPECT_CALL((*mock), SSL_get_error(_, -1))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            IsNull()))
        .WillOnce(Return(1));

    SocketInfo s(mock);
    s.newSSLCtx();
    s.newSSLObj();
    s.setSocket(fd);

    EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, s.handleRetry(-1, false));
}

TEST_F(SocketInfoTest, handleRetryRemoteDisconnect) // NOLINT
{
    {
        const int fd = 4;
        EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
            .WillOnce(Return(SSL_ERROR_ZERO_RETURN));

        SocketInfo s(mock);
        s.setSocket(fd);
        s.newSSLCtx();
        s.newSSLObj();

        EXPECT_EQ(SocketInfo::OP_STATUS::DISCONNECTED, s.handleRetry(-1));
    }

    {
        const int fd = 4;
        EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
            .WillOnce(Return(SSL_ERROR_SYSCALL));
        errno = 0;

        SocketInfo s(mock);
        s.setSocket(fd);
        s.newSSLCtx();
        s.newSSLObj();

        EXPECT_EQ(SocketInfo::OP_STATUS::DISCONNECTED, s.handleRetry(-1));
    }
}

TEST_F(SocketInfoTest, readDataExact) // NOLINT
{
    ON_CALL((*mock), select(_, _, _, _, _))
        .WillByDefault(Return(1));

    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 4))
        .WillOnce(DoAll(WithArg<1>(Invoke(
            [](void *ptr){
                memcpy(ptr, "abc", 4);
            })),
            Return(4)));

    SocketInfo s(mock);
    s.newSSLCtx();
    s.newSSLObj();

    char buf[4];
    auto rslt = s.readData(&buf[0], 4);
    EXPECT_TRUE(rslt);
    EXPECT_EQ(rslt.value(), 4ul);
    EXPECT_STREQ(buf, "abc");
}

TEST_F(SocketInfoTest, readDataShort) // NOLINT
{
    ON_CALL((*mock), select(_, _, _, _, _))
        .WillByDefault(Return(1));

    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 30))
        .WillOnce(DoAll(WithArg<1>(Invoke(
            [](void *ptr){
                memcpy(ptr, "abcde", 6);
            })),
            Return(6)));

    SocketInfo s(mock);
    s.newSSLCtx();
    s.newSSLObj();

    char buf[30];
    auto rslt = s.readData(&buf[0], 30);
    EXPECT_TRUE(rslt);
    EXPECT_EQ(rslt.value(), 6ul);
    EXPECT_STREQ(&buf[0], "abcde");
}

TEST_F(SocketInfoTest, readDataNoData) // NOLINT
{
    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_SYSCALL));
    errno = 0;

    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 1))
        .WillOnce(Return(-1));

    SocketInfo s(mock);
    s.newSSLCtx();
    s.newSSLObj();

    char buf[1];
    auto rslt = s.readData(&buf[0], 1);
    EXPECT_FALSE(rslt);
}

TEST_F(SocketInfoTest, writeDataExact) // NOLINT
{
    EXPECT_CALL((*mock), SSL_write(NotNull(), IsVoidEqStr("abc", 3), 4))
        .WillOnce(Return(4));

    SocketInfo s(mock);
    s.newSSLCtx();
    s.newSSLObj();

    char buf[] = "abc";
    auto rslt = s.writeData(&buf[0], 4);
    EXPECT_EQ(rslt, 4ul);
}

TEST_F(SocketInfoTest, writeDataShort) // NOLINT
{
    EXPECT_CALL((*mock), SSL_write(NotNull(), IsVoidEqStr("abcdefg", 7), 7))
        .WillOnce(Return(2));

    SocketInfo s(mock);
    s.newSSLCtx();
    s.newSSLObj();

    char buf[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
    auto rslt = s.writeData(&buf[0], 7);
    EXPECT_EQ(rslt, 2ul);
}

TEST_F(SocketInfoTest, writeDataRemoteDisconnect) // NOLINT
{
    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_ZERO_RETURN));
    errno = 0;

    EXPECT_CALL((*mock), SSL_write(NotNull(), IsVoidEqStr("abcdefg", 7), 7))
        .WillOnce(Return(-1));

    SocketInfo s(mock);
    s.setSocket(4);
    s.newSSLCtx();
    s.newSSLObj();
    char buf[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
    auto rslt = s.writeData(&buf[0], 7);
    EXPECT_EQ(rslt, 0ul);
}

} //namespace tlslookieloo
