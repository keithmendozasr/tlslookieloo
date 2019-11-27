*** Settings ***
Library     String
Resource    functional.resource

Test Setup  Reset Data Dir
Test Teardown   Run Keyword And Ignore Error    Terminate All Processes

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

*** Test Cases ***
Single Message Text
    [Timeout]   25s
    ${server}   ${server_obj}   ${sut}  ${client}   ${client_obj} =     Start Test System   9901    localhost:9900  ${PAYLOAD_DIR}/single_target_test_1.yaml

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

    Validate Single Message File Content    data/single_target_test1.msgs   ${server_msg}   ${client_msg}

Single Message Binary
    [Timeout]   25s
    ${server}   ${server_obj}   ${sut}  ${client}   ${client_obj} =     Start Test System   9901    localhost:9900  ${PAYLOAD_DIR}/single_target_test_1.yaml

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

    Validate Single Message File Content  data/single_target_test1.msgs   <00><00><00><0b>Hello there     <00><00><00><01>Y

Multiple Message Same Source
    [Timeout]   25s
    ${server}   ${server_obj}   ${sut}  ${client}   ${client_obj} =     Start Test System   9901    localhost:9900  ${PAYLOAD_DIR}/single_target_test_1.yaml

    Send Message String     ${client_obj}   ${server_obj}   Client Part 1\n
    Send Message String     ${client_obj}   ${server_obj}   Client Part 2
    Send Message String     ${client_obj}   ${server_obj}   \ Client Part 3

    Send Message String     ${server_obj}   ${client_obj}   Server Part 1\n
    Send Message String     ${server_obj}   ${client_obj}   Server Part 2
    Send Message String     ${server_obj}   ${client_obj}   \ Server Part 3

    Stop tlslookieloo   ${sut}

    ${data_file} =  Set Variable    data/single_target_test1.msgs
    Should Exist    ${data_file}
    ${file_data} =  Get File    ${data_file}
    ${num_lines} =  Get Line Count  ${file_data}
    Should Be Equal     ${20}    ${num_lines}

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

    ${server}   ${server_obj}   ${sut}  ${client}   ${client_obj} =     Start Test System   9901    localhost:9900  ${PAYLOAD_DIR}/single_target_test_1.yaml
    Send Message String     ${client_obj}   ${server_obj}   ${payload_file}
    Send Message String     ${server_obj}   ${client_obj}   ${payload_file}

    Terminate All Processes

    ${data_file} =  Set Variable    data/single_target_test1.msgs
    Should Exist    ${data_file}
    ${file_data} =  Get File    ${data_file}

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