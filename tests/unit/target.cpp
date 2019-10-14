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

    TargetTest() :
        mock(make_shared<MockWrapper>()),
        client(mock),
        server(mock)
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
};

TEST_F(TargetTest, waitForReadableTimeout) // NOLINT
{
    const long timeout = 5;
    client.setSocket(4);
    server.setSocket(5);

    EXPECT_CALL(
        (*mock),
        select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
            AllOf(NotNull(), Field(&timeval::tv_sec, timeout))))
        .WillOnce(Return(0));
    
    Target t(mock);
    t.timeout = timeout;
    EXPECT_EQ(0u, t.waitForReadable(client, server).size());
}

TEST_F(TargetTest, waitForReadableClient) // NOLINT
{
    client.setSocket(4);
    server.setSocket(5);

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
    
    Target t(mock);
    auto testVal = t.waitForReadable(client, server);
    EXPECT_EQ(1u, testVal.size());
    EXPECT_EQ(Target::READREADYSTATE::CLIENT_READY, testVal[0]);
}

TEST_F(TargetTest, waitForReadableServer) // NOLINT
{
    client.setSocket(4);
    server.setSocket(5);

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
    
    Target t(mock);
    auto testVal = t.waitForReadable(client, server);
    EXPECT_EQ(1u, testVal.size());
    EXPECT_EQ(Target::READREADYSTATE::SERVER_READY, testVal[0]);
}

TEST_F(TargetTest, waitForReadableInterrupted) // NOLINT
{
    {
        client.setSocket(4);
        server.setSocket(5);

        EXPECT_CALL(
            (*mock),
            select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
                IsNull()))
            .WillOnce(Return(-1));
        errno = 0;

        Target t(mock);
        EXPECT_EQ(0u, t.waitForReadable(client, server).size());
    }

    {
        const unsigned long timeout = 42;
        client.setSocket(4);
        server.setSocket(5);

        EXPECT_CALL(
            (*mock),
            select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
                AllOf(NotNull(), Field(&timeval::tv_sec, timeout))))
            .WillOnce(Return(-1));
        errno = EINTR;

        Target t(mock);
        t.timeout = timeout;
        EXPECT_EQ(0u, t.waitForReadable(client, server).size());
    }
}

TEST_F(TargetTest, waitForReadableError) // NOLINT
{
    client.setSocket(4);
    server.setSocket(5);

    EXPECT_CALL(
        (*mock),
        select(6, IsFdSet(4, 5), Not(IsFdSet(4, 5)), Not(IsFdSet(4, 5)),
            IsNull()))
        .WillOnce(Return(-1));
    errno = EBADF;

    Target t(mock);
    EXPECT_THROW(t.waitForReadable(client, server), system_error); // NOLINT
}

TEST_F(TargetTest, storeMessageClient) // NOLINT
{
    EXPECT_CALL((*mock), ostream_write(
        _, MatchesRegex(
                msgBanner +
                "client-->server===.Testing<00>"), _))
        .Times(1);

    Target t(mock);
    auto payload = "Testing";
    EXPECT_NO_THROW( // NOLINT
        t.storeMessage(payload, sizeof(payload), t.MSGOWNER::CLIENT));
}

TEST_F(TargetTest, storeMessageServer) // NOLINT
{
    string expectMsg("===END===\n");
    EXPECT_CALL((*mock), ostream_write(
        _, MatchesRegex(msgBanner +
                "server-->client===.Testing<00>"), _))
        .Times(1);

    Target t(mock);
    auto payload = "Testing";
    EXPECT_NO_THROW( // NOLINT
        t.storeMessage(payload, sizeof(payload), t.MSGOWNER::SERVER));
}

TEST_F(TargetTest, storeMessageBinary) // NOLINT
{
    string expectMsg("===BEGIN server-->client===\n<00><7f><10>\n===END===\n");
    EXPECT_CALL((*mock), ostream_write(
        _, MatchesRegex(msgBanner +
                "server-->client===.<00><7f><10>"), _))
        .Times(1);

    Target t(mock);
    char payload[] = { 0x0, 0x7f, 0x10 };
    EXPECT_NO_THROW( // NOLINT
        t.storeMessage(payload, sizeof(payload), t.MSGOWNER::SERVER));
}

TEST_F(TargetTest, storeMessageNullPtr) // NOLINT
{
    EXPECT_CALL((*mock),
        ostream_write(_, _, _))
        .Times(0);

    Target t(mock);
    EXPECT_THROW( // NOLINT
        t.storeMessage(nullptr, 1, t.MSGOWNER::CLIENT),
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

    Target t(mock);
    EXPECT_NO_THROW({
        auto owner = Target::MSGOWNER::SERVER;
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
            _, MatchesRegex("ghijklm\n"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, MatchesRegex("\nqrstuv\n"), _))
            .Times(1);

        EXPECT_CALL((*mock), ostream_write(
            _, StrEq(msgTail), _))
            .Times(1);
    }

    Target t(mock);
    EXPECT_NO_THROW({
        auto owner = Target::MSGOWNER::SERVER;
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

    Target t(mock);
    EXPECT_NO_THROW({
        t.storeMessage("From the server", strlen("From the server"),
            Target::MSGOWNER::SERVER);
        t.storeMessage("From the client", strlen("From the client"),
            Target::MSGOWNER::CLIENT);
        t.storeMessage("From the server again", strlen("From the server again"),
            Target::MSGOWNER::SERVER);
        t.storeMessage("From the client again", strlen("From the client again"),
            Target::MSGOWNER::CLIENT);
        t.storeMessage("", 0, Target::MSGOWNER::CLIENT);
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

    Target obj;
    EXPECT_TRUE(obj.messageRelay(client, server, Target::MSGOWNER::CLIENT));
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

    Target obj;
    EXPECT_FALSE(obj.messageRelay(client, server, Target::MSGOWNER::CLIENT));
}

} //namespace tlslookieloo
