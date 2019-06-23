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

#include <functional>

#include <openssl/ssl.h>

namespace tlslookieloo
{

extern std::function<int(int, fd_set *, fd_set *, fd_set *, struct timeval *)>
    selectFunc;

extern std::function<int(SSL *, void *, int)> sslReadFunc;

extern int SSLErrCode;

extern std::function<int(SSL *, const void *, int)> sslWriteFunc;

} // namespace