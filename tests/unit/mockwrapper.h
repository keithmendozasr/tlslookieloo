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
#pragma once

#include <memory>

#include <netdb.h>

#include "gmock/gmock.h"

#include "wrapper.h"

namespace tlslookieloo
{

class MockWrapper : public Wrapper
{
public:
    MOCK_METHOD(int, select, (int nfds, fd_set *readfds, fd_set *writefds,
        fd_set *exceptfds, struct timeval *timeout), (override));
    MOCK_METHOD(int, SSL_get_error, (const SSL *, int), (override));
    MOCK_METHOD(int, SSL_read, (SSL *, void *, int), (override));
    MOCK_METHOD(int, SSL_write, (SSL *, const void *, int), (override));
    MOCK_METHOD(void, ostream_write,
        (std::ostream &, const char * const, const size_t &), (override));
    MOCK_METHOD(int, getaddrinfo, (const char *, const char *,
        const struct addrinfo *, struct addrinfo **), (override));
    MOCK_METHOD(int, socket, (int, int, int), (override));
    MOCK_METHOD(int, setsockopt, (int, int, int, const void *, socklen_t), (override));
    MOCK_METHOD(int, bind, (int, const struct sockaddr *, socklen_t), (override));
    MOCK_METHOD(int, listen, (int, int), (override));
    MOCK_METHOD(int, accept, (int, struct sockaddr *, socklen_t *), (override));
    MOCK_METHOD(int, fcntl, (int, int, int), (override));
    MOCK_METHOD(int, getsockopt, (int, int, int, void *, socklen_t *), (override));
    MOCK_METHOD(int, connect, (int, const struct sockaddr *, socklen_t), (override));

    std::unique_ptr<struct addrinfo, decltype(&freeaddrinfo)> defaultAddrInfo;

    explicit MockWrapper() :
        defaultAddrInfo(nullptr, &freeaddrinfo)
    {}

    MockWrapper(const MockWrapper &) = delete;
    MockWrapper & operator = (const MockWrapper &) = delete;

    virtual ~MockWrapper(){}
};

void setDefaultgetaddrinfo(std::shared_ptr<MockWrapper> mock);
void setDefaultsocket(std::shared_ptr<MockWrapper> mock);
void setDefaultsetsockopt(std::shared_ptr<MockWrapper> mock);
void setDefaultbind(std::shared_ptr<MockWrapper> mock);
void setDefaultlisten(std::shared_ptr<MockWrapper> mock);
void setDefaultselect(std::shared_ptr<MockWrapper> mock);
void setDefaultaccept(std::shared_ptr<MockWrapper> mock);
void setDefaultfcntl(std::shared_ptr<MockWrapper> mock);

}
