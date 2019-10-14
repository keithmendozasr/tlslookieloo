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
#include <arpa/inet.h>

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
    ON_CALL((*mock), accept(4, NotNull(), Pointee(sizeof(struct sockaddr_storage))))
        .WillByDefault(DoAll(
            WithArgs<1,2>(
                [](struct sockaddr *addr, socklen_t *addrlen)
                {
                    *addrlen = sizeof(struct sockaddr_in);
                    struct sockaddr_in *tmp =
                        reinterpret_cast<struct sockaddr_in *>(addr); // NOLINT
                    tmp->sin_family = AF_INET;
                    tmp->sin_port = htons(1234);
                    inet_pton(AF_INET, "127.0.0.1", &(tmp->sin_addr));
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
