*** Settings ***
Library     String
Resource    functional.resource

Test Setup  Reset Data Dir
Test Teardown   Run Keyword And Ignore Error    Terminate All Processes

*** Variables ***
${msgs_file} =  data/basic_operations.msgs

*** Keywords ***
Validate Single Message File Content
    [Arguments]     ${data_file}    ${server_expect}    ${client_expect}

    Should Exist    ${data_file}
    ${file_data} =  Get File    ${data_file}
    ${num_lines} =  Get Line Count  ${file_data}
    Should Be Equal     ${6}    ${num_lines}

	${line} =   Get Line    ${file_data}    0
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    1
    Should Be Equal As Strings  ${line}     ${server_expect}

    ${line} =   Get Line    ${file_data}    2
    Should Be Equal As Strings  ${line}     ${END_TAG}

	${line} =   Get Line    ${file_data}    3
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    4
    Should Be Equal As Strings  ${line}     ${client_expect}

    ${line} =   Get Line    ${file_data}    5
    Should Be Equal As Strings  ${line}     ${END_TAG}

Start Test System
    [Arguments]     ${server_port}  ${client_conn}  ${tlslookieloo_config}
    ${server}   ${server_obj} =     Start Server    ${server_port}  ${SERVER_CERT}  ${SERVER_KEY}
    ${sut} =    Start tlslookieloo  ${tlslookieloo_config}
    ${client}   ${client_obj} =     Start Client    ${client_conn}

    [Return]    ${server}   ${server_obj}   ${sut}  ${client}   ${client_obj}

*** Test Cases ***
Single Message Text
    [Timeout]   25s
    ${server}   ${server_obj}   ${sut}  ${client}   ${client_obj} =     Start Test System   9901    localhost:9900  ${PAYLOAD_DIR}/basic_operations.yaml

    ${server_msg} =     Set Variable    Hello from server
    ${msg} =    Encode String To Bytes  ${server_msg}   ASCII
    ${retval} =     Call Method     ${server_obj.stdin}     write   ${msg}
    Log     server write returned: ${retval}
    Call Method     ${server_obj.stdin}     flush

    ${rslt} =   Call Method     ${client_obj.stdout}    read    ${17}
    Log     Message from server: ${rslt}

    ${client_msg} =     Set Variable    Hello from client
    ${msg} =    Encode String To Bytes  ${client_msg}   ASCII
    ${retval} =     Call Method     ${client_obj.stdin}     write   ${msg}
    Log     write returned: ${retval}
    Call Method     ${client_obj.stdin}     flush

    ${rslt} =   Call Method     ${server_obj.stdout}    read    ${11}
    Log     Message from client: ${rslt}

    Stop tlslookieloo   ${sut}

    Validate Single Message File Content    ${msgs_file}    ${server_msg}   ${client_msg}

Single Message Binary
    [Timeout]   25s
    ${server}   ${server_obj}   ${sut}  ${client}   ${client_obj} =     Start Test System   9901    localhost:9900  ${PAYLOAD_DIR}/basic_operations.yaml

    ${server_msg} =     Convert To Bytes    \x00\x00\x00\x0bHello there
    ${client_msg} =    Convert To Bytes    \x00\x00\x00\x01Y

    ${retval} =     Call Method     ${server_obj.stdin}     write   ${server_msg}
    Log     server written returned: ${retval}
    Call Method     ${server_obj.stdin}     flush

    ${rslt} =   Call Method     ${client_obj.stdout}    read    ${15}
    Log     Message from server: ${rslt}
    Should Be Equal    ${rslt}     ${server_msg}

    ${retval} =     Call Method     ${client_obj.stdin}     write   ${client_msg}
    Log     write returned ${retval}
    Call Method     ${client_obj.stdin}     flush

    ${rslt} =   Call Method     ${server_obj.stdout}    read    ${5}
    Log     Message from client: ${rslt}
    Should Be Equal    ${rslt}     ${client_msg}

    Stop tlslookieloo   ${sut}

    Validate Single Message File Content  ${msgs_file}  <00><00><00><0b>Hello there     <00><00><00><01>Y

Multiple Message Same Source
    [Timeout]   25s
    ${server}   ${server_obj}   ${sut}  ${client}   ${client_obj} =     Start Test System   9901    localhost:9900  ${PAYLOAD_DIR}/basic_operations.yaml

    Send Message String     ${client_obj}   ${server_obj}   Client Part 1\n
    Send Message String     ${client_obj}   ${server_obj}   Client Part 2
    Send Message String     ${client_obj}   ${server_obj}   \ Client Part 3

    Send Message String     ${server_obj}   ${client_obj}   Server Part 1\n
    Send Message String     ${server_obj}   ${client_obj}   Server Part 2
    Send Message String     ${server_obj}   ${client_obj}   \ Server Part 3

    Stop tlslookieloo   ${sut}

    Should Exist    ${msgs_file}
    ${file_data} =  Get File    ${msgs_file}
    ${num_lines} =  Get Line Count  ${file_data}
    Should Be Equal     ${20}   ${num_lines}

	${line} =   Get Line    ${file_data}    0
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    1
    Should Be Equal As Strings  ${line}     Client Part 1<0a>

    ${line} =   Get Line    ${file_data}    2
    Should Be Empty     ${line}

    ${line} =   Get Line    ${file_data}    3
    Should Be Equal As Strings  ${line}     ${END_TAG}

	${line} =   Get Line    ${file_data}    4
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    5
    Should Be Equal As Strings  ${line}     Client Part 2

    ${line} =   Get Line    ${file_data}    6
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    7
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    8
    Should Be Equal As Strings  ${line}     \ Client Part 3

    ${line} =   Get Line    ${file_data}    9
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    10
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    11
    Should Be Equal As Strings  ${line}     Server Part 1<0a>

    ${line} =   Get Line    ${file_data}    12
    Should Be Empty     ${line}

    ${line} =   Get Line    ${file_data}    13
    Should Be Equal As Strings  ${line}     ${END_TAG}

	${line} =   Get Line    ${file_data}    14
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    15
    Should Be Equal As Strings  ${line}     Server Part 2

    ${line} =   Get Line    ${file_data}    16
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    17
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    18
    Should Be Equal As Strings  ${line}     \ Server Part 3

    ${line} =   Get Line    ${file_data}    19
    Should Be Equal As Strings  ${line}     ${END_TAG}

Large Payload
    [Timeout]   25s
    ${payload_file} =   Get File    ${PAYLOAD_DIR}/largetext.txt

    ${server}   ${server_obj}   ${sut}  ${client}   ${client_obj} =     Start Test System   9901    localhost:9900  ${PAYLOAD_DIR}/basic_operations.yaml
    Send Message String     ${client_obj}   ${server_obj}   ${payload_file}
    Send Message String     ${server_obj}   ${client_obj}   ${payload_file}

    Terminate All Processes

    Should Exist    ${msgs_file}
    ${file_data} =  Get File    ${msgs_file}

    ${line} =   Get Line    ${file_data}    0
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    1
    Should Be Equal As Strings  ${payload_file}     ${line}

    ${line} =   Get Line    ${file_data}    2
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    3
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    4
    Should Be Equal As Strings  ${payload_file}     ${line}

    ${line} =   Get Line    ${file_data}    5
    Should Be Equal As Strings  ${line}     ${END_TAG}

Client Cert Required And Provided
    [Timeout]   25s
    ${server} =     Start Process   ${openssl}  s_server    -ign_eof    -quiet  -cert   ${SERVER_CERT}  -key    ${SERVER_KEY}  -CAfile  ${CA_FILE}  -port   +9901
    Sleep   1
    ${rslt} =   Is Process Running  ${server}
    Run Keyword If  ${rslt} == ${False}     Log Process Failed Start    ${server}   s_server
    ${server_obj} =     Get Process Object  ${server}

    ${sut} =    Start tlslookieloo  ${PAYLOAD_DIR}/basic_operations_client_cert.yaml

    ${client} =     Start Process   ${openssl}  s_client  -ign_eof  -quiet  -CAfile     ${CA_FILE}  -cert   ${CERT_PATH}/tlslookieloo_client.pem    -key    ${CERT_PATH}/tlslookieloo_client_priv.pem  -connect     localhost:9900
    Sleep   1
    ${rslt} =   Is Process Running  ${client}
    Run Keyword If  ${rslt} == ${False}     Log Process Failed Start    ${client}   s_client
    ${client_obj} =     Get Process Object  ${client}

    Send Message String     ${client_obj}   ${server_obj}   Hello from client
    Send Message String     ${server_obj}   ${client_obj}   Server acknowledge

    Stop tlslookieloo   ${sut}

    Should Exist    ${msgs_file}
    ${file_data} =  Get File    ${msgs_file}
    ${num_lines} =  Get Line Count  ${file_data}
    Should Be Equal As Integers     ${6}    ${num_lines}

    ${line} =   Get Line    ${file_data}    1
    Should Be Equal As Strings  ${line}     Hello from client

    ${line} =   Get Line    ${file_data}    4
    Should Be Equal As Strings  ${line}     Server acknowledge

Client Cert Required But Not Provided
    [Timeout]   25s
    ${sut} =    Start tlslookieloo  ${PAYLOAD_DIR}/basic_operations_client_cert.yaml

    ${client} =     Start Process   ${openssl}  s_client  -ign_eof  -CAfile     ${CA_FILE}  -connect    localhost:9900
    Sleep   1
    Process Should Be Stopped   handle=${client}
    ${rslt} =   Wait For Process    handle=${client}    timeout=1s  on_timeout=terminate

    ${rslt} =   Terminate Process   ${sut}
    Log  ${rslt.stdout}
    ${expect_lines} =   Get Lines Containing String     ${rslt.stdout}      WARN - Client didn't send a certificate
    ${line_cnt} =   Get Line Count  ${expect_lines}
    Should Be Equal As Integers  ${line_cnt}     ${0}

Client Cert Required But Wrong Cert Provided
    [Timeout]   25s
    ${sut} =    Start tlslookieloo  ${PAYLOAD_DIR}/basic_operations_client_cert.yaml

    ${client} =     Start Process   ${openssl}  s_client  -ign_eof  -quiet  -CAfile     ${CA_FILE}  -cert   ${CERT_PATH}/tlslookieloo_server.pem    -key    ${CERT_PATH}/tlslookieloo_server_priv.pem  -connect     localhost:9900
    Sleep   1
    Process Should Be Stopped   handle=${client}
    ${rslt} =   Wait For Process    handle=${client}    timeout=1s  on_timeout=terminate
    Log     Client console: ${rslt.stdout}\nstderr: ${rslt.stderr}

    ${rslt} =   Terminate Process   ${sut}
    Log  ${rslt.stdout}
    ${expect_lines} =   Get Lines Containing String     ${rslt.stdout}  INFO - Client-provided certificate public key doesn't match expected public key
    ${line_cnt} =   Get Line Count  ${expect_lines}
    Should Be Equal As Integers  ${line_cnt}     ${0}
