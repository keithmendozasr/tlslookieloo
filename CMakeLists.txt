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

cmake_minimum_required (VERSION 3.7)
include(FindPkgConfig)

project (tlslookieloo VERSION 0.0.1.0)
enable_testing()
configure_file(include/version.h.in ${CMAKE_BINARY_DIR}/include/version.h)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Werror -pedantic)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb3 -O0")

include(ExternalProject)
ExternalProject_Add(googletest
    SOURCE_DIR "${CMAKE_SOURCE_DIR}/googletest"
    BINARY_DIR "${CMAKE_BINARY_DIR}/googletest"
    INSTALL_COMMAND ""
)

find_package(OpenSSL 1.1.0 REQUIRED)

include_directories(
    include
    ${CMAKE_BINARY_DIR}/include
    googletest/googletest/include
)

add_subdirectory(tests)
add_subdirectory(src)
