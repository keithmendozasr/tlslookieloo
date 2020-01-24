# Copyright 2019-present tlslookieloo authors
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required (VERSION 3.12)
include(FindPkgConfig)

project (tlslookieloo
    VERSION 1.0.0
    HOMEPAGE_URL "https://github.com/keithmendozasr/tlslookieloo")
enable_testing()
configure_file(include/version.h.in ${CMAKE_BINARY_DIR}/include/version.h)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Werror -pedantic)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb3 -O0")

find_package(OpenSSL 1.1.1 REQUIRED)
find_package(yaml-cpp 0.6 REQUIRED)

include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

# Build log4cplus library as an external project. A previous attempt to add it
# as a subdirectory caused ctest to also run log4cplus' test; but, for some
# reason its unit test executable didn't get built.
include(ExternalProject)
ExternalProject_Add(log4cplus
    PREFIX "${CMAKE_BINARY_DIR}/log4cplus"
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/log4cplus"
    BINARY_DIR "${CMAKE_BINARY_DIR}/log4cplus"
    INSTALL_DIR "${CMAKE_BINARY_DIR}/log4cplus/install_dir"
    CMAKE_ARGS "-DBUILD_SHARED_LIBS:BOOL=OFF" "-DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/log4cplus/install_dir"
    BUILD_COMMAND "cmake" "--build" "." "--target" "log4cplusS"
    INSTALL_COMMAND ""
)
add_library(log4cplusStatic STATIC IMPORTED)
add_dependencies(log4cplusStatic log4cplus)
set_target_properties(log4cplusStatic PROPERTIES
    IMPORTED_LOCATION "${CMAKE_BINARY_DIR}/log4cplus/src/liblog4cplusS.a")
include_directories(
    ${CMAKE_SOURCE_DIR}/log4cplus/include
    ${CMAKE_BINARY_DIR}/log4cplus/include
)

add_subdirectory(googletest ${CMAKE_BINARY_DIR}/googletest EXCLUDE_FROM_ALL)
add_subdirectory(src)
add_subdirectory(tests)

set(CPACK_GENERATOR "TGZ" "DEB")
set(CPACK_PACKAGE_CONTACT "Keith Mendoza <keith@homepluspower.info>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Utility to view stream message between server and client")
set(CPACK_PACKAGE_DESCRIPTION 
    "tlslookieloo is a utility to help troubleshoot network-related issues \
between a server and client. A client will connect to tlslookieloo, who in \
turn, will connect to the target server. tlslookieloo will then \
store/display the unencrypted message between the two.")
set(CPACK_DEBIAN_PACKAGE_SECTION "misc")
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
include(CPack)
