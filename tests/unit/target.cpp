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

#include <iostream>
#include <cerrno>

#include "log4cplus/ndc.h"

#include "config.h"
#include "target.h"
#include "mockwrapper.h"

using namespace testing;
using namespace std;

namespace tlslookieloo
{

class TargetTestObj : public Target
{
public:
    TargetTestObj(shared_ptr<MockWrapper> mock) : Target(mock)
    {}

    std::vector<READREADYSTATE> waitForReadable(ClientSide &client, ServerSide &server)
    {
        return Target::waitForReadable(client, server);
    }

    void storeMessage(const char *data, const size_t &len, const MSGOWNER & owner)
    {
        return Target::storeMessage(data, len, owner);
    }

    bool messageRelay(SocketInfo &src, SocketInfo &dest,
        const Target::MSGOWNER owner)
    {
        return Target::messageRelay(src, dest, owner);
    }
    void setTimeout(const unsigned int &val)
    {
        Target::setTimeout(val);
    }

    Target::READREADYSTATE CLIENT_READY_VAL = Target::READREADYSTATE::CLIENT_READY;
    Target::READREADYSTATE SERVER_READY_VAL = Target::READREADYSTATE::SERVER_READY;

    Target::MSGOWNER OWNER_CLIENT = Target::MSGOWNER::CLIENT;
    Target::MSGOWNER OWNER_SERVER = Target::MSGOWNER::SERVER;
};

MATCHER_P(IsVoidEqStr, str, "") // NOLINT
{
    return string(static_cast<const char*>(arg)) == str;
}

MATCHER_P2(IsFdSet, clientFd, serverFd, "fd is set") // NOLINT
{
    // NOLINTNEXTLINE
    return arg != nullptr && FD_ISSET(clientFd, arg) && FD_ISSET(serverFd, arg);
}

class TargetTest : public ::testing::Test
{
protected:
    shared_ptr<MockWrapper> mock = nullptr;
    ClientSide client;
    ServerSide server;
    TargetTestObj t;

    TargetTest() :
        mock(make_shared<MockWrapper>()),
        client(mock),
        server(mock),
        t(mock)
    {}

    void SetUp() override
    {
        client.setSocket(4);
        client.newSSLCtx();
        client.newSSLObj();

        server.setSocket(5);
        server.newSSLCtx();
        server.newSSLObj();
    }

    const string msgBanner =
        "===[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] "
        "[0-9][0-9]:[0-9][0-9]:[0-9][0-9] BEGIN ";

    const string msgTail = "\n===END===\n";

    void setSocketFds()
    {
        client.setSocket(4);
        server.setSocket(5);
    }
};

TEST_F(TargetTest, waitForReadableTimeout) // NOLINT
{
    const long timeout = 5;
    setSocketFds();

    EXPECT_CALL(
        (*mock),
        select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
            AllOf(NotNull(), Field(&timeval::tv_sec, timeout))))
        .WillOnce(Return(0));
    
    t.setTimeout(timeout);
    EXPECT_EQ(0u, t.waitForReadable(client, server).size());
}

TEST_F(TargetTest, waitForReadableClient) // NOLINT
{
    setSocketFds();

    EXPECT_CALL(
        (*mock),
        select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
            IsNull()))
        .WillOnce(DoAll(WithArg<1>(Invoke(
            [](fd_set *ptr){
                FD_ZERO(ptr);
                FD_SET(4, ptr);
            })),
            Return(1)));
    
    auto testVal = t.waitForReadable(client, server);
    EXPECT_EQ(1u, testVal.size());
    EXPECT_EQ(t.CLIENT_READY_VAL, testVal[0]);
}

TEST_F(TargetTest, waitForReadableServer) // NOLINT
{
    setSocketFds();

    EXPECT_CALL(
        (*mock),
        select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
            IsNull()))
        .WillOnce(DoAll(WithArg<1>(Invoke(
            [](fd_set *ptr){
                FD_ZERO(ptr);
                FD_SET(5, ptr);
            })),
            Return(1)));
    
    auto testVal = t.waitForReadable(client, server);
    EXPECT_EQ(1u, testVal.size());
    EXPECT_EQ(t.SERVER_READY_VAL, testVal[0]);
}

TEST_F(TargetTest, waitForReadableInterrupted) // NOLINT
{
    {
        setSocketFds();

        EXPECT_CALL(
            (*mock),
            select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
                IsNull()))
            .WillOnce(Return(-1));
        errno = 0;

        EXPECT_EQ(0u, t.waitForReadable(client, server).size());
    }

    {
        const unsigned long timeout = 42;
        setSocketFds();

        EXPECT_CALL(
            (*mock),
            select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
                AllOf(NotNull(), Field(&timeval::tv_sec, timeout))))
            .WillOnce(Return(-1));
        errno = EINTR;

        t.setTimeout(timeout);
        EXPECT_EQ(0u, t.waitForReadable(client, server).size());
    }
}

TEST_F(TargetTest, waitForReadableError) // NOLINT
{
    setSocketFds();

    EXPECT_CALL(
        (*mock),
        select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
            IsNull()))
        .WillOnce(Return(-1));
    errno = EBADF;

    EXPECT_THROW(t.waitForReadable(client, server), system_error); // NOLINT
}

TEST_F(TargetTest, storeMessageClient) // NOLINT
{
    EXPECT_CALL((*mock), ostream_write(
        _, MatchesRegex(
                msgBanner +
                "client-->server===.Testing<00>"), _))
        .Times(1);

    auto payload = "Testing";
    EXPECT_NO_THROW( // NOLINT
        t.storeMessage(payload, sizeof(payload), t.OWNER_CLIENT));
}

TEST_F(TargetTest, storeMessageServer) // NOLINT
{
    string expectMsg("===END===\n");
    EXPECT_CALL((*mock), ostream_write(
        _, MatchesRegex(msgBanner +
                "server-->client===.Testing<00>"), _))
        .Times(1);

    auto payload = "Testing";
    EXPECT_NO_THROW( // NOLINT
        t.storeMessage(payload, sizeof(payload), t.OWNER_SERVER));
}

TEST_F(TargetTest, storeMessageBinary) // NOLINT
{
    EXPECT_CALL((*mock), ostream_write(
        _, MatchesRegex(msgBanner +
                "server-->client===.<00><7f><0b>"), _))
        .Times(1);

    char payload[] = { 0x00, 0x7f, 0x0b };
    EXPECT_NO_THROW( // NOLINT
        t.storeMessage(payload, sizeof(payload), t.OWNER_SERVER));
}

TEST_F(TargetTest, storeMessageNewlines) // NOLINT
{
    // NOTE: Alternating source is to make it easier to test the different
    // newline values
    InSequence seq;
    EXPECT_CALL((*mock), ostream_write(
        _, MatchesRegex(msgBanner +
            "server-->client===.Hello<0d>."), _))
        .Times(1);

    EXPECT_CALL((*mock), ostream_write(
        _, MatchesRegex(msgTail + msgBanner +
            "client-->server===.Hello<0a>."), _))
        .Times(1);

    EXPECT_CALL((*mock), ostream_write(
        _, MatchesRegex(msgTail + msgBanner +
            "server-->client===.Hello<0d><0a>."), _))
        .Times(1);

    const char crPayload[] = "Hello\r";
    EXPECT_NO_THROW( // NOLINT
        t.storeMessage(crPayload, sizeof(crPayload)-1, t.OWNER_SERVER));

    const char lfPayload[] = "Hello\n";
    EXPECT_NO_THROW( // NOLINT
        t.storeMessage(lfPayload, sizeof(lfPayload)-1, t.OWNER_CLIENT));

    const char crlfPayload[] = "Hello\r\n";
    EXPECT_NO_THROW( // NOLINT
        t.storeMessage(crlfPayload, sizeof(crlfPayload)-1, t.OWNER_SERVER));
}

TEST_F(TargetTest, storeMessageNullPtr) // NOLINT
{
    EXPECT_CALL((*mock),
        ostream_write(_, _, _))
        .Times(0);

    EXPECT_THROW( // NOLINT
        t.storeMessage(nullptr, 1, t.OWNER_CLIENT),
        logic_error);
}

TEST_F(TargetTest, storeSingleChunkMessage) // NOLINT
{
    {
        InSequence s;

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex(msgBanner + "server-->client===\nabcdef"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, StrEq(msgTail), _))
            .Times(1);
    }

    EXPECT_NO_THROW({
        auto owner = t.OWNER_SERVER;
        t.storeMessage("abcdef", 6, owner);
        t.storeMessage("", 0, owner);
    });
}

TEST_F(TargetTest, storeChunkedMessage) // NOLINT
{
    {
        InSequence s;

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex(msgBanner + "server-->client===\nabcdef"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex("ghijklm<0a>\n"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex("<0a>\nqrstuv<0a>\n"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, StrEq(msgTail), _))
            .Times(1);
    }

    EXPECT_NO_THROW({
        auto owner = t.OWNER_SERVER;
        t.storeMessage("abcdef", 6, owner);
        t.storeMessage("ghijklm\n", 8, owner);
        t.storeMessage("\nqrstuv\n", 8, owner);
        t.storeMessage("", 0, owner);
    });
}

TEST_F(TargetTest, storeAlternatingMessage) // NOLINT
{
    {
        InSequence s;

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex(msgBanner + "server-->client===\nFrom the server"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex(
                msgTail + msgBanner + "client-->server===\nFrom the client"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex(
                msgTail + msgBanner + "server-->client===\nFrom the server again"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex(
                msgTail + msgBanner + "client-->server===\nFrom the client again"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex(msgTail), _))
            .Times(1);
    }

    EXPECT_NO_THROW({
        t.storeMessage("From the server", strlen("From the server"),
            t.OWNER_SERVER);
        t.storeMessage("From the client", strlen("From the client"),
            t.OWNER_CLIENT);
        t.storeMessage("From the server again", strlen("From the server again"),
            t.OWNER_SERVER);
        t.storeMessage("From the client again", strlen("From the client again"),
            t.OWNER_CLIENT);
        t.storeMessage("", 0, t.OWNER_CLIENT);
    });
}

TEST_F(TargetTest, messageRelayGood) // NOLINT
{
    {
        InSequence s;
        const char expectData[] = "abc";
        const size_t expectedBuf = 4096;
        EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), expectedBuf))
            .WillOnce(DoAll(WithArg<1>(Invoke(
                [expectData](void *ptr){
                    memcpy(ptr, &expectData[0], sizeof(expectData));
                })),
                Return(sizeof(expectData))));

        // NOLINTNEXTLINE
        EXPECT_CALL((*mock), SSL_write(NotNull(), IsVoidEqStr(expectData), sizeof(expectData)))
            .WillOnce(Return(sizeof(expectData)));

        EXPECT_CALL((*mock), SSL_read(NotNull(), NotNull(), expectedBuf))
            .WillOnce(Return(0));

        EXPECT_CALL((*mock), SSL_get_error(NotNull(), 0))
            .WillOnce(Return(SSL_ERROR_WANT_READ));
    }

    EXPECT_TRUE(t.messageRelay(client, server, t.OWNER_CLIENT));
}

TEST_F(TargetTest, messageRelayRemoteDisconnect) // NOLINT
{
    const char expectData[] = "abc";
    EXPECT_CALL((*mock), SSL_read(_, _, _))
        .WillRepeatedly(DoAll(WithArg<1>(Invoke(
            [expectData](void *ptr){
                memcpy(ptr, &expectData[0], 4);
            })),
            Return(4)));

    EXPECT_CALL((*mock), SSL_get_error(_, _))
        .WillOnce(Return(SSL_ERROR_ZERO_RETURN));
    errno = 0;

    EXPECT_CALL((*mock), SSL_write(_, _, _))
        .WillOnce(Return(-1));
    
    EXPECT_FALSE(t.messageRelay(client, server, t.OWNER_CLIENT));
}

} //namespace tlslookieloo
