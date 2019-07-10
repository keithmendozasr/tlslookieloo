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

link_directories(${CMAKE_BINARY_DIR}/googletest/lib)
add_executable(unittests main.cpp
    ${CMAKE_SOURCE_DIR}/src/concretewrapper.cpp
    ${CMAKE_SOURCE_DIR}/src/init.cpp init.cpp
    ${CMAKE_SOURCE_DIR}/src/socketinfo.cpp socketinfo.cpp
    ${CMAKE_SOURCE_DIR}/src/clientside.cpp clientside.cpp
    ${CMAKE_SOURCE_DIR}/src/serverside.cpp
    ${CMAKE_SOURCE_DIR}/src/target.cpp target.cpp
)
target_include_directories(unittests
    PRIVATE ${CMAKE_SOURCE_DIR}/tests/unit
    PRIVATE ${CMAKE_SOURCE_DIR}/googletest/googletest/include
    PRIVATE ${CMAKE_SOURCE_DIR}/googletest/googlemock/include
)

target_link_libraries(unittests gtest gmock pthread
    ${CMAKE_BINARY_DIR}/log4cplus/lib/liblog4cplus.a
    yaml-cpp ssl crypto
)

add_test(parseTargetsFile unittests -t${CMAKE_SOURCE_DIR}/tests/unit/targets_files --gtest_filter=parseTargetsFile.*)
add_test(SocketInfoTest unittests --gtest_filter=SocketInfoTest.*)
add_test(ClientSideTest unittests --gtest_filter=ClientSideTest.*)
add_test(Target unittests --gtest_filter=TargetTest.* -c${CMAKE_SOURCE_DIR}/tests/unit/test_cert)
