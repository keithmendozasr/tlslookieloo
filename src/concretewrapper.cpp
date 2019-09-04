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

#include <ostream>

#include <unistd.h>
#include <fcntl.h>

#include <sys/select.h>
#include <openssl/ssl.h>

#include "concretewrapper.h"

namespace tlslookieloo
{

int ConcreteWrapper::select(int nfds, fd_set *readfds, fd_set *writefds,
    fd_set *exceptfds, struct timeval *timeout)
{
    return ::select(nfds, readfds, writefds, exceptfds, timeout);
}

int ConcreteWrapper::SSL_get_error(const SSL *ssl, int ret)
{
    return ::SSL_get_error(ssl, ret);
}

int ConcreteWrapper::SSL_read(SSL *ssl, void *buf, int num)
{
    return ::SSL_read(ssl, buf, num);
}

int ConcreteWrapper::SSL_write(SSL *ssl, const void *buf, int num)
{
    return ::SSL_write(ssl, buf, num);
}

void ConcreteWrapper::ostream_write(std::ostream & ostream,
    const char * data, const size_t &len)
{
    ostream.write(data, len);
}

int ConcreteWrapper::getaddrinfo(const char *node, const char *service,
    const struct addrinfo* hints, struct addrinfo **res)
{
    return ::getaddrinfo(node, service, hints, res);
}

int ConcreteWrapper::socket(int domain, int type, int protocol)
{
    return ::socket(domain, type, protocol);
}

int ConcreteWrapper::setsockopt(int sockfd, int level, int optname,
    const void *optval, socklen_t optlen)
{
    return ::setsockopt(sockfd, level, optname, optval, optlen);
}

int ConcreteWrapper::bind(int sockfd, const struct sockaddr *addr,
    socklen_t addrlen)
{
    return ::bind(sockfd, addr, addrlen);
}

int ConcreteWrapper::listen(int sockfd, int backlog)
{
    return ::listen(sockfd, backlog);
}

int ConcreteWrapper::accept(int sockfd, struct sockaddr *addr,
    socklen_t *addrlen)
{
    return ::accept(sockfd, addr, addrlen);
}

int ConcreteWrapper::fcntl(int sockfd, int cmd, int val)
{
    // NOLINTNEXTLINE
    return ::fcntl(sockfd, cmd, val);
}

int ConcreteWrapper::getsockopt(int sockfd, int level, int optname,
    void *optval, socklen_t *optlen)
{
    return ::getsockopt(sockfd, level, optname, optval, optlen);
}

} // namespace
