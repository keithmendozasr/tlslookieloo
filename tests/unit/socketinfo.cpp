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

class SocketInfoTestObj : public SocketInfo
{
public:
    SocketInfoTestObj(shared_ptr<MockWrapper> w) : SocketInfo(w)
    {}

    const bool resolveHostPort(const unsigned int &port)
    {
        return SocketInfo::resolveHostPort(port);
    }

    const bool resolveHostPort(const unsigned int &port, const std::string &host)
    {
        return SocketInfo::resolveHostPort(port, host);
    }

    SocketInfoTestObj operator = (const SocketInfoTestObj) = delete;
    SocketInfoTestObj operator = (SocketInfoTestObj &&) = delete;

    const struct addrinfo *getNextServ()
    {
        return nextServ;
    }

    void initNextSocket()
    {
        SocketInfo::initNextSocket();
    }

    const OP_STATUS handleRetry(const int &rslt)
    {
        return SocketInfo::handleRetry(rslt);
    }
};

class SocketInfoTest : public ::testing::Test
{
protected:
    shared_ptr<MockWrapper> mock = make_shared<MockWrapper>();
    int fd = 4;
    SocketInfoTestObj s;

    SocketInfoTest() :
        s(mock)
    {}

    SocketInfoTest(const SocketInfoTest &) = delete;
    SocketInfoTest(SocketInfoTest &&) = delete;

    virtual ~SocketInfoTest(){}

    virtual void SetUp() override
    {
        s.setSocket(fd);
        s.newSSLCtx();
        s.newSSLObj();
    }
};

MATCHER_P(IsFdSet, fd, "fd is set") // NOLINT
{
    return arg != nullptr && FD_ISSET(fd, arg); // NOLINT
}

MATCHER_P2(IsVoidEqStr, str, len, "") // NOLINT
{
    return string(static_cast<const char*>(arg), len) == str;
}

MATCHER(CheckHints, "Correct hints") // NOLINT
{
    return arg->ai_family == AF_UNSPEC && arg->ai_socktype == SOCK_STREAM &&
        arg->ai_flags == AI_PASSIVE;
}

TEST_F(SocketInfoTest, resolveHostPortInstanceInitialized) // NOLINT
{
    setDefaultgetaddrinfo(mock);
    EXPECT_NO_THROW(s.resolveHostPort(9000));
    EXPECT_THROW(s.resolveHostPort(9000, ""), logic_error); // NOLINT
}

TEST_F(SocketInfoTest, resolveHostPortNoHost) // NOLINT
{
    struct addrinfo *addrInfoObj;
    EXPECT_CALL((*mock), getaddrinfo(IsNull(), StrEq("9900"), CheckHints(), _))
        .WillOnce(Invoke(
            [&addrInfoObj](const char *node, const char *svc,
                const struct addrinfo *hints, struct addrinfo **res)->int
            {
                auto rv = ::getaddrinfo(node, svc, hints, &addrInfoObj);
                *res = addrInfoObj;
                return rv;
            }
        ));

    EXPECT_TRUE(s.resolveHostPort(9900, ""));
    EXPECT_EQ(s.getNextServ(), addrInfoObj);
}

TEST_F(SocketInfoTest, resolveHostPortHostProvided) // NOLINT
{
    struct addrinfo *addrInfoObj;
    EXPECT_CALL((*mock), getaddrinfo(StrEq("localhost"), StrEq("9900"), CheckHints(), _))
        .WillOnce(Invoke(
            [&addrInfoObj](const char *node, const char *svc,
                const struct addrinfo *hints, struct addrinfo **res)->int
            {
                auto rv = ::getaddrinfo(node, svc, hints, &addrInfoObj);
                *res = addrInfoObj;
                return rv;
            }
        ));

    EXPECT_TRUE(s.resolveHostPort(9900, "localhost"));
}

TEST_F(SocketInfoTest, initNextSocketUnresolved) // NOLINT
{
    EXPECT_THROW(s.initNextSocket(), logic_error); // NOLINT
}

TEST_F(SocketInfoTest, initNextSocketAllTried) // NOLINT
{
    struct addrinfo *addrInfoObj;
    ON_CALL((*mock), getaddrinfo(_, _, _, _))
        .WillByDefault(Invoke(
            [&addrInfoObj](const char *node, const char *svc,
                const addrinfo *hints, struct addrinfo **res)->int
            {
                ::getaddrinfo(node, svc, hints, &addrInfoObj);
                auto otherAddrs = addrInfoObj->ai_next;
                if(otherAddrs != nullptr)
                    freeaddrinfo(otherAddrs);

                addrInfoObj->ai_next = nullptr;
                *res = addrInfoObj;
                return 0;
            }
        ));

    ON_CALL((*mock), socket(_, _, _))
        .WillByDefault(Return(5));

    EXPECT_NO_THROW({
        s.resolveHostPort(9000, "localhost");
        s.initNextSocket();
    });
    EXPECT_THROW(s.initNextSocket(), range_error); // NOLINT
}

TEST_F(SocketInfoTest, initNextSocketSocketFail) // NOLINT
{
    ON_CALL((*mock), getaddrinfo(_, _, _, _))
        .WillByDefault(Invoke(::getaddrinfo));

    EXPECT_CALL((*mock), socket(_, _, _))
        .WillOnce(Return(-1));

    ASSERT_NO_THROW(s.resolveHostPort(9900, "localhost")); // NOLINT
    EXPECT_THROW(s.initNextSocket(), runtime_error); // NOLINT
}

TEST_F(SocketInfoTest, initNextSocketGood) // NOLINT
{
    struct addrinfo *expectData;
    ON_CALL((*mock), getaddrinfo(_, _, _, _))
        .WillByDefault(DoAll(
            WithArgs<2,3>(
                [&expectData](const struct addrinfo *hints,
                    struct addrinfo **res)
                {
                    if(! ::getaddrinfo("localhost", "9000", hints, &expectData))
                        *res = expectData;
                }
            ),
            Return(0)
        ));

    EXPECT_CALL((*mock), socket(_, _, _))
        .WillOnce(Return(4));

    ASSERT_NO_THROW(s.resolveHostPort(9900, "localhost")); // NOLINT
    EXPECT_NO_THROW(s.initNextSocket()); // NOLINT
    EXPECT_EQ(s.getNextServ(), expectData->ai_next);
}

TEST_F(SocketInfoTest, handleRetryReady) // NOLINT
{
    {
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_READ));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)),
                IsNull()))
            .WillOnce(Return(1));

        EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, s.handleRetry(-1));
    }

    {
        EXPECT_CALL((*mock), SSL_get_error(_, -1))
            .WillOnce(Return(SSL_ERROR_WANT_WRITE));

        EXPECT_CALL(
            (*mock),
            select(Ge(fd), Not(IsFdSet(fd)), IsFdSet(fd), Not(IsFdSet(fd)),
                IsNull()))
            .WillOnce(Return(1));

        EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, s.handleRetry(-1));
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

    s.setTimeout(10);
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
                IsNull()))
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
                IsNull()))
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
            IsNull()))
        .WillOnce(Return(-1));

    EXPECT_THROW(s.handleRetry(-1), system_error); // NOLINT
    errno = 0;
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

    EXPECT_THROW(s.handleRetry(0), logic_error); // NOLINT
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
    unique_ptr<char[]> buf(new char[dataSize]);

    auto rslt = s.readData(&buf[0], dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, rslt);
    EXPECT_EQ(4ul, dataSize);
    EXPECT_STREQ("abc", &buf[0]);
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
    unique_ptr<char[]> buf(new char[dataSize]);
    auto rslt = s.readData(&buf[0], dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, rslt);
    EXPECT_EQ(6ul, dataSize);
    EXPECT_STREQ("abcde", &buf[0]);
}

TEST_F(SocketInfoTest, readDataProtocolOnly) // NOLINT
{
    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 4))
        .WillOnce(Return(0));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), 0))
        .WillOnce(Return(SSL_ERROR_WANT_READ));

    size_t dataSize = 4;
    unique_ptr<char[]> buf(new char[dataSize]);

    auto rslt = s.readData(&buf[0], dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::SUCCESS, rslt);
    EXPECT_EQ(0ul, dataSize);
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

    s.setTimeout(10);
    size_t dataSize = 1;
    unique_ptr<char[]>buf(new char[dataSize]);
    auto rslt = s.readData(&buf[0], dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::TIMEOUT, rslt);
}

TEST_F(SocketInfoTest, readDataDisconnect) // NOLINT
{
    InSequence i;

    EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), 1))
        .WillOnce(Return(-1));

    EXPECT_CALL((*mock), SSL_get_error(NotNull(), -1))
        .Times(2)
        .WillRepeatedly(Return(SSL_ERROR_ZERO_RETURN));

    size_t dataSize = 1;
    unique_ptr<char[]> buf(new char[dataSize]);
    auto rslt = s.readData(&buf[0], dataSize);
    EXPECT_EQ(SocketInfo::OP_STATUS::DISCONNECTED, rslt);
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
        select(Ge(fd), IsFdSet(fd), Not(IsFdSet(fd)), Not(IsFdSet(fd)), IsNull())
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
