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
    int fd = 4;
    SocketInfo s;

    SocketInfoTest() :
        s(mock)
    {}

    void SetUp() override
    {
        s.setSocket(fd);
        s.newSSLCtx();
        s.newSSLObj();
    }
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
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_READ));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(1));

        EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, s.handleRetry(-1, true));
    }

    {
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_WRITE));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(1));

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

    EXPECT_EQ(SocketInfo::OP_STATUS::TIMEOUT, s.handleRetry(-1));
}

TEST_F(SocketInfoTest, handleRetrySetTimeout) // NOLINT
{
    const long timeout = 100;

    EXPECT_CALL((*mock), SSL_get_error(_, -1))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            AllOf(NotNull(), Field(&timeval::tv_sec, timeout))))
        .WillOnce(Return(0));

    s.setTimeout(timeout);

    EXPECT_EQ(SocketInfo::OP_STATUS::TIMEOUT, s.handleRetry(-1));
}

TEST_F(SocketInfoTest, handleRetryInterrupted) // NOLINT
{
    {
        errno = EINTR;
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_READ));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(-1));

        EXPECT_EQ(SocketInfo::OP_STATUS::INTERRUPTED, s.handleRetry(-1));
    }

    {
        errno = 0;
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_WRITE));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
                NotNull()))
            .WillOnce(Return(-1));

        EXPECT_EQ(SocketInfo::OP_STATUS::INTERRUPTED, s.handleRetry(-1));
    }
}

TEST_F(SocketInfoTest, handleRetryError) // NOLINT
{
    errno = EBADF;
    EXPECT_CALL((*mock), SSL_get_error(_, -1))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            NotNull()))
        .WillOnce(Return(-1));

    EXPECT_THROW(s.handleRetry(-1), system_error); // NOLINT
    errno = 0;
}

TEST_F(SocketInfoTest, handleRetryNoTimeout) // NOLINT
{
    EXPECT_CALL((*mock), SSL_get_error(_, -1))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
            IsNull()))
        .WillOnce(Return(1));

    EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, s.handleRetry(-1, false));
}

TEST_F(SocketInfoTest, handleRetryRemoteDisconnect) // NOLINT
{
    {
        EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
            .WillOnce(Return(SSL_ERROR_ZERO_RETURN));

        EXPECT_EQ(SocketInfo::OP_STATUS::DISCONNECTED, s.handleRetry(-1));
    }

    {
        EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
            .WillOnce(Return(SSL_ERROR_SYSCALL));
        errno = 0;

        EXPECT_EQ(SocketInfo::OP_STATUS::DISCONNECTED, s.handleRetry(-1));
    }
}

TEST_F(SocketInfoTest, handleRetryNoError) // NOLINT
{
    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_NONE));

    EXPECT_THROW(s.handleRetry(0), logic_error);
}

TEST_F(SocketInfoTest, readDataExact) // NOLINT
{
    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 4))
        .WillOnce(DoAll(WithArg<1>(Invoke(
            [](void *ptr){
                memcpy(ptr, "abc", 4);
            })),
            Return(4)));

    size_t dataSize = 4;
    char * buf = new char[dataSize];

    auto rslt = s.readData(&buf[0], dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, rslt);
    EXPECT_EQ(4ul, dataSize);
    EXPECT_STREQ("abc", &buf[0]);
    delete[] buf;
}

TEST_F(SocketInfoTest, readDataShort) // NOLINT
{
    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 30))
        .WillOnce(DoAll(WithArg<1>(Invoke(
            [](void *ptr){
                memcpy(ptr, "abcde", 6);
            })),
            Return(6)));

    size_t dataSize = 30;
    char * buf = new char[dataSize];
    auto rslt = s.readData(&buf[0], dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, rslt);
    EXPECT_EQ(6ul, dataSize);
    EXPECT_STREQ("abcde", &buf[0]);
    delete[] buf;
}

TEST_F(SocketInfoTest, readDataProtocolOnly) // NOLINT
{
    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 4))
        .WillOnce(Return(0));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), 0))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    size_t dataSize = 4;
    char * buf = new char[dataSize];

    auto rslt = s.readData(&buf[0], dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, rslt);
    EXPECT_EQ(0ul, dataSize);
    delete[] buf;
}

TEST_F(SocketInfoTest, readDataTimeout) // NOLINT
{
    InSequence i;

    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 1))
        .WillOnce(Return(-1));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .Times(2)
        .WillRepeatedly(Return(SSL_ERROR_WANT_WRITE));

    EXPECT_CALL(
        (*mock),
        select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)), NotNull())
    ).WillOnce(Return(0));

    size_t dataSize = 1;
    char * buf = new char[dataSize];
    auto rslt = s.readData(buf, dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::TIMEOUT, rslt);
    delete[] buf;
}

TEST_F(SocketInfoTest, readDataDisconnect)
{
    InSequence i;

    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 1))
        .WillOnce(Return(-1));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), -1))
        .Times(2)
        .WillRepeatedly(Return(SSL_ERROR_ZERO_RETURN));

    size_t dataSize = 1;
    char * buf = new char[dataSize];
    auto rslt = s.readData(buf, dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::DISCONNECTED, rslt);
    delete[] buf;
}

TEST_F(SocketInfoTest, writeDataExact) // NOLINT
{
    EXPECT_CALL((*mock), SSL_write(NotNull(), IsVoidEqStr("abc", 3), 4))
        .WillOnce(Return(4));

    char buf[] = "abc";
    auto rslt = s.writeData(&buf[0], 4);
    EXPECT_EQ(rslt, SocketInfo::OP_STATUS::SUCCESS);
}

TEST_F(SocketInfoTest, writeDataShort) // NOLINT
{
    InSequence sequence;
    EXPECT_CALL((*mock), SSL_write(NotNull(), IsVoidEqStr("abcdefg", 7), 7))
        .WillOnce(Return(0));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), 0))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    EXPECT_CALL(
        (*mock),
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)), NotNull())
    ).WillOnce(Return(1));

    EXPECT_CALL((*mock), SSL_write(NotNull(), IsVoidEqStr("abcdefg", 7), 7))
        .WillOnce(Return(7));

    char buf[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
    auto rslt = s.writeData(&buf[0], 7);
    EXPECT_EQ(rslt, SocketInfo::OP_STATUS::SUCCESS);
}

TEST_F(SocketInfoTest, writeDataRemoteDisconnect) // NOLINT
{
    EXPECT_CALL((*mock), SSL_get_error(NotNull(), _))
        .WillOnce(Return(SSL_ERROR_ZERO_RETURN));
    errno = 0;

    EXPECT_CALL((*mock), SSL_write(NotNull(), IsVoidEqStr("abcdefg", 7), 7))
        .WillOnce(Return(-1));

    char buf[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g' };
    auto rslt = s.writeData(&buf[0], 7);
    EXPECT_EQ(rslt, SocketInfo::OP_STATUS::DISCONNECTED);
}

} //namespace tlslookieloo
