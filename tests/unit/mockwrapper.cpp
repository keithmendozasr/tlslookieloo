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

#include "mockwrapper.h"

using namespace std;
using namespace testing;

namespace tlslookieloo
{

void setDefaultgetaddrinfo(std::shared_ptr<MockWrapper> mock)
{
    auto fn = bind(::getaddrinfo, nullptr, "9900", placeholders::_1,
        placeholders::_2);

    ON_CALL((*mock), getaddrinfo(testing::_, testing::_, testing::_, testing::_))
        .WillByDefault(testing::WithArgs<2, 3>(fn));
}

void setDefaultsetsockopt(std::shared_ptr<MockWrapper> mock)
{
    ON_CALL((*mock), setsockopt(_, _, _, _, _))
        .WillByDefault(Return(0));
}

void setDefaultsocket(std::shared_ptr<MockWrapper> mock)
{
    ON_CALL((*mock), socket(_, _, _))
        .WillByDefault(Return(4));
}

void setDefaultbind(std::shared_ptr<MockWrapper> mock)
{
    ON_CALL((*mock), bind(_, _, _))
        .WillByDefault(Return(0));
}

void setDefaultlisten(std::shared_ptr<MockWrapper> mock)
{
    ON_CALL((*mock), listen(4, 1))
        .WillByDefault(Return(0));
}

}
