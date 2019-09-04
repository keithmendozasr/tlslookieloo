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

#include <functional>

#include <unistd.h>
#include <fcntl.h>

#include "mockwrapper.h"

using namespace std;
using namespace testing;

namespace tlslookieloo
{

void setDefaultgetaddrinfo(shared_ptr<MockWrapper> mock)
{
    auto fn = bind(::getaddrinfo, nullptr, "9900", placeholders::_1,
        placeholders::_2);

    ON_CALL((*mock), getaddrinfo(testing::_, testing::_, testing::_, testing::_))
        .WillByDefault(testing::WithArgs<2, 3>(fn));
}

void setDefaultsetsockopt(shared_ptr<MockWrapper> mock)
{
    ON_CALL((*mock), setsockopt(_, _, _, _, _))
        .WillByDefault(Return(0));
}

void setDefaultsocket(shared_ptr<MockWrapper> mock)
{
    ON_CALL((*mock), socket(_, _, _))
        .WillByDefault(Return(4));
}

void setDefaultbind(shared_ptr<MockWrapper> mock)
{
    ON_CALL((*mock), bind(_, _, _))
        .WillByDefault(Return(0));
}

void setDefaultlisten(shared_ptr<MockWrapper> mock)
{
    ON_CALL((*mock), listen(4, 1))
        .WillByDefault(Return(0));
}

void setDefaultselect(shared_ptr<MockWrapper> mock)
{
    ON_CALL((*mock), select(_, _, _, _, _))
        .WillByDefault(Return(1));
}

void setDefaultaccept(shared_ptr<MockWrapper> mock)
{
    if(!mock->defaultAddrInfo)
    {
        struct addrinfo hints; // NOLINT

        memset(&hints, 0, sizeof hints); // NOLINT
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_PASSIVE; // use my IP

        struct addrinfo *tmp;

        // NOTE: Do not do ignore return value in production
        ::getaddrinfo(nullptr, "9000", &hints, &tmp);
        mock->defaultAddrInfo =
            unique_ptr<struct addrinfo, decltype(&freeaddrinfo)>(tmp, &freeaddrinfo);
    }

    ON_CALL((*mock), accept(_, _, _))
        .WillByDefault(DoAll(
            WithArgs<1,2>(
                [&mock](struct sockaddr *addr, socklen_t *addrlen)
                {
                    if(addr != nullptr)
                    {
                        *addrlen = mock->defaultAddrInfo->ai_addrlen;
                        memcpy(addr, mock->defaultAddrInfo->ai_addr, *addrlen);
                    }
                }
            ),
            Return(5)
        ));
}

void setDefaultfcntl(shared_ptr<MockWrapper> mock)
{
    InSequence seq;
    ON_CALL((*mock), fcntl(5, F_GETFL, 0))
        .WillByDefault(Return(0));

    ON_CALL((*mock), fcntl(5, F_SETFL, O_NONBLOCK))
        .WillByDefault(Return(0));
}
}
