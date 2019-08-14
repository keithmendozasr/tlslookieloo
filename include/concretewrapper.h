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

#include <ostream>

#include "wrapper.h"

namespace tlslookieloo
{

/**
 * Default implementation of Wrapper class
 */
class ConcreteWrapper : public Wrapper
{
public:
    ConcreteWrapper() = default;
    ConcreteWrapper(const ConcreteWrapper &) = default;
    ConcreteWrapper(ConcreteWrapper &&) = default;
    ConcreteWrapper &operator= (const ConcreteWrapper &) = default;
    ConcreteWrapper &operator= (ConcreteWrapper &&) = default;
    virtual ~ConcreteWrapper(){} ;

    virtual int select(int, fd_set *, fd_set *, fd_set *, struct timeval *) override;
    
    virtual int SSL_get_error(const SSL *, int) override;

    virtual int SSL_read(SSL *, void *, int) override;

    virtual int SSL_write(SSL *, const void *, int) override;

    virtual void ostream_write(std::ostream & ostream,
        const char * data, const size_t &len) override;

    virtual int getaddrinfo(const char *node, const char *service,
        const struct addrinfo* hints, struct addrinfo **res) override;
};

} // namespace
