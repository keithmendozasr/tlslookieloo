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

#include "gmock/gmock.h"

#include <cerrno>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "log4cplus/ndc.h"

#include "config.h"
#include "target.h"
#include "mockwrapper.h"

using namespace testing;
using namespace std;

namespace tlslookieloo
{

MATCHER_P(IsFdSet, fd, "fd is set") // NOLINT
{
    return arg != nullptr && FD_ISSET(fd, arg); // NOLINT
}

MATCHER_P(IsVoidPtrIntEq, val, "void pointer points to int with expected value") // NOLINT
{
    return arg != nullptr &&
        *(reinterpret_cast<const int *>(arg)) == val; // NOLINT
}

// NOLINTNEXTLINE(cppcoreguidelines-special-member-functions)
class ClientSideTest : public ::testing::Test
{
protected:
    shared_ptr<MockWrapper> mock;
    ClientSide client;
    int fd = 4;

    ClientSideTest() :
        mock(make_shared<MockWrapper>()),
        client(mock)
    {}

    virtual ~ClientSideTest(){};

    virtual void SetUp() override
    {
        client.setSocket(fd);
        client.newSSLCtx();
        client.newSSLObj();
    }

    virtual unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> getExpectedPubKey()
    {
        const char expectPubKey[] = R"foo(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwDoRldXkyzxmDYgi307p
9i14+wVknfLlBOih23jVE9ab4UATSFGaZk6iduj1SixUmq3eSrlZm3BRv3PkwqU4
ZIYaMHXowWHxE/ZmPmuT8jFc0HqgrgJaSzZe39O6F5pSsDA0Z/KQ7Zgw34Hzpfk/
vQPycdQWNpvk+zGYSgNFn5jqSXOll7qe+/1pQF0lm8/3ry194zXV95lAvcpoTh2n
pTIdC+7uN2Zl0kM/zGhKWrx4aMuzBl5/9WLBbeJql9iCWRqqRzZbUeUPfmO8+n6s
KumG5sfkQavbNxCimQgSF2mKPzsMEI5wYCttytPYwd3WVFLeKi6jWWY7etOGRKk8
KXD34/8B8o1fKJr2UdqfBefIjCsrGCdykAm6m8PVgbCZeOO17y+VmbQn1PVdIVJP
TTwmDUZGorUVxM0rtHj38fZhKQI+MkqhMSD9ZI8g1+nwjG/Pegf1llU6lRx+/Myl
pyrpYfQs5MLgJWPTh84f4P/bwaU70ABd/pXVsUlqWYI7FgzyJRuRXwoksOWVOFmY
841IuYtyNMPUZZKWpOpzHlpbX2fskn/9qQ+bGPloVe0BCuPFkWA0+aqI4QPnexr1
6+iEY1c1REjLSSmZqW0/UAMD0uDWadKFI6o1AmxMEkVOEcW2ddA+fyvztw6TBqKY
3tmii175uHC39k4oFowndQ0CAwEAAQ==
-----END PUBLIC KEY----- 
)foo";

        unique_ptr<BIO, decltype(&BIO_free)> b(
            BIO_new_mem_buf(&expectPubKey[0], strlen(&expectPubKey[0])),
            &BIO_free);
        EXPECT_TRUE(b);

        unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> evpKey(
            PEM_read_bio_PUBKEY(b.get(), nullptr, 0, nullptr), &EVP_PKEY_free);

        return evpKey;
    }

};

TEST_F(ClientSideTest, startListenerResolveFail) // NOLINT
{
    ON_CALL((*mock), getaddrinfo(_, _, _, _))
        .WillByDefault(Return(1));

   EXPECT_THROW(client.startListener(1024, 1), logic_error); // NOLINT
}

TEST_F(ClientSideTest, startListenerSockOptError) // NOLINT
{
    setDefaultgetaddrinfo(mock);
    setDefaultsocket(mock);

    EXPECT_CALL((*mock), setsockopt(4, SOL_SOCKET, SO_REUSEADDR, IsVoidPtrIntEq(1), sizeof(int)))
        .WillOnce(Invoke(
            [](int, int, int, const void *, socklen_t)->int{
                errno = ENOTSOCK;
                return -1;
            }
        ));
    EXPECT_THROW(client.startListener(1024, 1), system_error); // NOLINT
}

TEST_F(ClientSideTest, startListenerBindError) // NOLINT
{
    setDefaultgetaddrinfo(mock);
    setDefaultsetsockopt(mock);
    setDefaultsocket(mock);

    EXPECT_CALL((*mock), bind(4, _, _))
        .WillOnce(Invoke(
            [](int, const struct sockaddr *, socklen_t)->int{
                errno = EADDRINUSE;
                return -1;
            }
        ));

    EXPECT_THROW(client.startListener(1024, 1), system_error); // NOLINT
}

TEST_F(ClientSideTest, startListenerListenError) // NOLINT
{
    setDefaultgetaddrinfo(mock);
    setDefaultsocket(mock);
    setDefaultsocket(mock);
    setDefaultbind(mock);

    EXPECT_CALL((*mock), listen(4, 1))
        .WillOnce(Invoke(
            [](int, int)->int{
                errno = ENOTSOCK;
                return -1;
            }
        ));

    EXPECT_THROW(client.startListener(1024, 1), system_error); // NOLINT
}

TEST_F(ClientSideTest, startListenerGood) // NOLINT
{
    setDefaultgetaddrinfo(mock);
    setDefaultsocket(mock);
    setDefaultsocket(mock);
    setDefaultbind(mock);

    EXPECT_NO_THROW(client.startListener(1024, 1)); // NOLINT
}

TEST_F(ClientSideTest, waitSocketReadableGood) // NOLINT
{
    EXPECT_CALL(
        (*mock),
        select(5, IsFdSet(fd), IsNull(), IsNull(), IsNull())
    ).WillOnce(Return(1));
    
    EXPECT_NO_THROW(client.waitSocketReadable()); // NOLINT
}

TEST_F(ClientSideTest, waitSocketReadableError) // NOLINT
{
    EXPECT_CALL(
        (*mock),
        select(5, IsFdSet(fd), IsNull(), IsNull(), IsNull())
    ).WillOnce(Return(-1));
    
    EXPECT_THROW(client.waitSocketReadable(), system_error); // NOLINT
}

TEST_F(ClientSideTest, loadCertFileGood) // NOLINT
{
    const char expectPubKey[] = R"foo(-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwDoRldXkyzxmDYgi307p
9i14+wVknfLlBOih23jVE9ab4UATSFGaZk6iduj1SixUmq3eSrlZm3BRv3PkwqU4
ZIYaMHXowWHxE/ZmPmuT8jFc0HqgrgJaSzZe39O6F5pSsDA0Z/KQ7Zgw34Hzpfk/
vQPycdQWNpvk+zGYSgNFn5jqSXOll7qe+/1pQF0lm8/3ry194zXV95lAvcpoTh2n
pTIdC+7uN2Zl0kM/zGhKWrx4aMuzBl5/9WLBbeJql9iCWRqqRzZbUeUPfmO8+n6s
KumG5sfkQavbNxCimQgSF2mKPzsMEI5wYCttytPYwd3WVFLeKi6jWWY7etOGRKk8
KXD34/8B8o1fKJr2UdqfBefIjCsrGCdykAm6m8PVgbCZeOO17y+VmbQn1PVdIVJP
TTwmDUZGorUVxM0rtHj38fZhKQI+MkqhMSD9ZI8g1+nwjG/Pegf1llU6lRx+/Myl
pyrpYfQs5MLgJWPTh84f4P/bwaU70ABd/pXVsUlqWYI7FgzyJRuRXwoksOWVOFmY
841IuYtyNMPUZZKWpOpzHlpbX2fskn/9qQ+bGPloVe0BCuPFkWA0+aqI4QPnexr1
6+iEY1c1REjLSSmZqW0/UAMD0uDWadKFI6o1AmxMEkVOEcW2ddA+fyvztw6TBqKY
3tmii175uHC39k4oFowndQ0CAwEAAQ==
-----END PUBLIC KEY----- 
)foo";

	unique_ptr<BIO, decltype(&BIO_free)> b(
        BIO_new_mem_buf(&expectPubKey[0], strlen(&expectPubKey[0])), &BIO_free);
    ASSERT_TRUE(b) << "Failed to create BIO for expected public key";

    unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> evpKey(
        PEM_read_bio_PUBKEY(b.get(), nullptr, 0, nullptr), &EVP_PKEY_free);
    ASSERT_TRUE(evpKey)
        << ERR_error_string(ERR_get_error(), nullptr) << "\nValue of pubkey: \n\""
        << expectPubKey << "\"";

    typedef unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> EVP_PKEY_MEM;
    EXPECT_NO_THROW({ // NOLINT
        auto testCert = client.loadCertFile(certFilesPath + "/tlslookieloo_unittest.pem");
        EVP_PKEY_MEM testKey(
            X509_get_pubkey(testCert.get()),
            &EVP_PKEY_free
        );
        EXPECT_TRUE(EVP_PKEY_cmp(evpKey.get(), testKey.get()));
    });
}

TEST_F(ClientSideTest, loadCertFileOpenFailed) // NOLINT
{
    const string fileName = certFilesPath + "/nonexistentfile.pem";
    try
    {
        client.loadCertFile(fileName);
        FAIL() << "Expected to throw exception";
    }
    catch (const runtime_error &e)
    {
        ASSERT_THAT(e.what(),
            MatchesRegex("Failed to open cert file " + fileName + ".*"));
    }
    catch(...)
    {
        FAIL() << "Wrong exception thrown";
    }
}

TEST_F(ClientSideTest, loadCertFileWrongFormat) // NOLINT
{
    try
    {
        client.loadCertFile(certFilesPath + "/loadwrongcertformat.pem");
        FAIL() << "Expected to throw exception";
    }
    catch (const runtime_error &e)
    {
        ASSERT_THAT(e.what(),
            MatchesRegex(R"s(Error encountered reading pubkey\..*)s"));
    }
    catch(...)
    {
        FAIL() << "Wrong exception thrown";
    }
}

TEST_F(ClientSideTest, loadRefClientCertPubkey) // NOLINT
{
    EXPECT_NO_THROW( // NOLINT
        client.loadRefClientCertPubkey(
            certFilesPath + "/tlslookieloo_unittest.pem",
            certFilesPath + "/devca.pem"
        )
    );

    EXPECT_TRUE(EVP_PKEY_cmp(
        client.refClientPubKey.get(), getExpectedPubKey().get()));

    auto clientCAList = SSL_CTX_get_client_CA_list(client.getSSLCtxPtr());
    EXPECT_EQ(1, sk_X509_NAME_num(clientCAList));
    unique_ptr<char[]> testName(X509_NAME_oneline(
        sk_X509_NAME_value(
            const_cast<const STACK_OF(X509_NAME) *>(clientCAList), // NOLINT
            0
        ), nullptr, 0)
    );

    EXPECT_STREQ("/C=US/ST=California/L=Tustin/O=homepluspower.info/OU=Research"
        "/CN=homepluspower.info/emailAddress=keith@homepluspower.info",
        testName.get());
}

} //namespace tlslookieloo
