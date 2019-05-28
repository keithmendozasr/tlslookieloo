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

#include <string>
#include <exception>

namespace tlslookieloo
{

/**
 * Exception when socket timeout occurs
 */
class TimeoutException : public std::exception
{
public:
    /**
     * Constructor override from std::exception
     */
    explicit TimeoutException(const std::string &what) noexcept : msg(what)
    {}

    /**
     * Copy constructor
     */
    TimeoutException(const TimeoutException &cpy) noexcept : msg(cpy.msg)
    {}

    /**
     * Assignment operator overload
     */
    TimeoutException & operator = (const TimeoutException &cpy) noexcept
    {
        msg = cpy.msg;
        return *this;
    }

    virtual const char * what() const noexcept
    {
        return msg.c_str();
    }

    virtual ~TimeoutException() throw()
    {}

private:
    std::string msg;
};

} //namespace tlslookieloo
