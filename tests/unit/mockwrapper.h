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
    MOCK_METHOD5(select, int(int nfds, fd_set *readfds, fd_set *writefds,
        fd_set *exceptfds, struct timeval *timeout));
    MOCK_METHOD2(SSL_get_error, int(const SSL *, int));
    MOCK_METHOD3(SSL_read, int(SSL *, void *, int));
    MOCK_METHOD3(SSL_write, int(SSL *, const void *, int));
    MOCK_METHOD3(ostream_write, void(std::ostream &, const char * const, const size_t &));
    MOCK_METHOD4(getaddrinfo, int(const char *, const char *,
        const struct addrinfo *, struct addrinfo **));
    MOCK_METHOD3(socket, int(int, int, int));
    MOCK_METHOD5(setsockopt, int(int, int, int, const void *, socklen_t));
    MOCK_METHOD3(bind, int(int, const struct sockaddr *, socklen_t));
    MOCK_METHOD2(listen, int(int, int));
};

void setDefaultgetaddrinfo(std::shared_ptr<MockWrapper> mock);
void setDefaultsocket(std::shared_ptr<MockWrapper> mock);
void setDefaultsetsockopt(std::shared_ptr<MockWrapper> mock);
void setDefaultbind(std::shared_ptr<MockWrapper> mock);
void setDefaultlisten(std::shared_ptr<MockWrapper> mock);

}
