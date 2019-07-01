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

#include "mockcapi.h"

using namespace std;

namespace tlslookieloo
{
function<int(SSL *, void *, int)> sslReadFunc;

function<int(SSL *, const void *, int)> sslWriteFunc;

extern "C"
{

int SSL_read(SSL *ssl, void *buf, int num)
{
    return sslReadFunc(ssl, buf, num);
}

int SSL_write(SSL *ssl, const void *buf, int num)
{
    return sslWriteFunc(ssl, buf, num);
}

} // extern "C"

} // namespace
