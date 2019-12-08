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

configure_file(commonvars.py.in commonvars.py)

configure_file(payloads/basic_operations.yaml payloads/basic_operations.yaml)
configure_file(payloads/basic_operations_client_cert.yaml payloads/basic_operations_client_cert.yaml)
configure_file(payloads/missing_client_auth_file.yaml payloads/missing_client_auth_file.yaml)
configure_file(payloads/multi_targets.yaml payloads/multi_targets.yaml)

configure_file(payloads/largetext.txt payloads/largetext.txt COPYONLY)
configure_file(payloads/largetext.txt payloads/badsyntax.yaml COPYONLY)

add_test(basic_operations
         robot --variablefile ${CMAKE_CURRENT_BINARY_DIR}/commonvars.py
         ${CMAKE_CURRENT_SOURCE_DIR}/basic_operations.robot
)

add_test(startup_errors
         robot --variablefile ${CMAKE_CURRENT_BINARY_DIR}/commonvars.py
         ${CMAKE_CURRENT_SOURCE_DIR}/startup_errors.robot
)

add_test(multi_targets
         robot --variablefile ${CMAKE_CURRENT_BINARY_DIR}/commonvars.py
         ${CMAKE_CURRENT_SOURCE_DIR}/multi_targets.robot
)