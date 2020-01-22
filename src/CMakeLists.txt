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

add_executable(tlslookieloo main.cpp concretewrapper.cpp socketinfo.cpp
    serverside.cpp init.cpp clientside.cpp target.cpp
)

add_dependencies(tlslookieloo log4cplus)
target_link_libraries(tlslookieloo log4cplusStatic pthread yaml-cpp ssl crypto)

install(TARGETS tlslookieloo
    RUNTIME DESTINATION bin
)
