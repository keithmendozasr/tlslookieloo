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

#include <netdb.h>

#include <openssl/ssl.h>

namespace tlslookieloo
{

/**
 * Abstract class to wrap C API functions.
 *
 * The purpose of this class is to make unit testing easy to deal with.
 * The function name matches the API function its wrapping
 */
class Wrapper
{
public:
    Wrapper() = default;
    Wrapper(const Wrapper &) = default;
    Wrapper(Wrapper &&) = default;
    Wrapper &operator =(const Wrapper &) = default;
    Wrapper &operator =(Wrapper &&) = default;
    virtual ~Wrapper(){};

    /**
     * Wrap POSIX select()
     */
    virtual int select(int nfds, fd_set *readfds, fd_set *writefds,
        fd_set *exceptfds, struct timeval *timeout) = 0;

    /**
     * Wrap SSL_get_error()
     */
    virtual int SSL_get_error(const SSL *, int) = 0;

    /**
     * Wrap SSL_read()
     */
    virtual int SSL_read(SSL *, void *, int) = 0;

    /**
     * Wrap SSL_write()
     */
    virtual int SSL_write(SSL *, const void *, int) = 0;

    /**
     * Wrap basic_ostream::write()
     * \arg ostream basic_ostream instance to actually write to
     * \arg data Raw data to write
     * \arg len Length of data
     */
    virtual void ostream_write(std::ostream & ostream,
        const char * data, const size_t &len) = 0;

    /**
     * Wrap getaddrinfo()
     */
    virtual int getaddrinfo(const char *, const char *, const struct addrinfo*,
        struct addrinfo **) = 0;

    /**
     * Wrap socket()
     */
    virtual int socket(int, int, int) = 0;
};

} // namespace
