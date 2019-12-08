*** Settings ***
Library     String
Resource    functional.resource

Test Setup  Reset Data Dir
Test Teardown   Run Keyword And Ignore Error    Post Test Cleanup

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
    [Arguments]     ${tlslookieloo_config}

    ${server_one}   ${server_one_obj} =     Start Server    9901  ${SERVER_CERT}  ${SERVER_KEY}
    ${server_two}   ${server_two_obj} =     Start Server    9911  ${SECOND_SERVER_CERT}  ${SECOND_SERVER_KEY}
    
    ${sut} =    Start tlslookieloo  ${tlslookieloo_config}

    ${client_one}   ${client_one_obj} =     Start Client    localhost:9900
    ${client_two}   ${client_two_obj} =     Start Client    localhost:9910

    [Return]    ${server_one}   ${server__one_obj}  ${server_two}   ${server_two_obj}   ${sut}  ${client_one}   ${client_one_obj}   ${client_two}   ${client_two_obj}

*** Test Cases ***
Single Message Text
    [Timeout]   25s
    ${server_one}   ${server_one_obj}  ${server_two}   ${server_two_obj}   ${sut}  ${client_one}   ${client_one_obj}    ${client_two}   ${client_two_obj} =     Start Test System   ${PAYLOAD_DIR}/multi_targets.yaml

    ${server_one_msg} =     Set Variable    Hello from server one
    ${msg} =    Encode String To Bytes  ${server_one_msg}   ASCII
    ${retval} =     Call Method     ${server_one_obj.stdin}     write   ${msg}
    Log     server write returned: ${retval}
    Call Method     ${server_one_obj.stdin}     flush

    ${rslt} =   Call Method     ${client_one_obj.stdout}    read    ${17}
    Log     Message from server one: ${rslt}

    ${client_one_msg} =     Set Variable    Hello from client one
    ${msg} =    Encode String To Bytes  ${client_one_msg}   ASCII
    ${retval} =     Call Method     ${client_one_obj.stdin}     write   ${msg}
    Log     write returned: ${retval}
    Call Method     ${client_one_obj.stdin}     flush

    ${rslt} =   Call Method     ${server_one_obj.stdout}    read    ${11}
    Log     Message from client one: ${rslt}

    ${server_two_msg} =     Set Variable    Hello from server one
    ${msg} =    Encode String To Bytes  ${server_two_msg}   ASCII
    ${retval} =     Call Method     ${server_two_obj.stdin}     write   ${msg}
    Log     server write returned: ${retval}
    Call Method     ${server_two_obj.stdin}     flush

    ${rslt} =   Call Method     ${client_two_obj.stdout}    read    ${17}
    Log     Message from server one: ${rslt}

    ${client_two_msg} =     Set Variable    Hello from client one
    ${msg} =    Encode String To Bytes  ${client_two_msg}   ASCII
    ${retval} =     Call Method     ${client_two_obj.stdin}     write   ${msg}
    Log     write returned: ${retval}
    Call Method     ${client_two_obj.stdin}     flush

    ${rslt} =   Call Method     ${server_two_obj.stdout}    read    ${11}
    Log     Message from client one: ${rslt}

    Stop tlslookieloo   ${sut}
    # Terminate All Processes

    Validate Single Message File Content    data/app1.msgs   ${server_one_msg}   ${client_one_msg}
    Validate Single Message File Content    data/app2.msgs   ${server_two_msg}   ${client_two_msg}

Single Message Binary
    [Timeout]   25s
    ${server_one}   ${server_one_obj}  ${server_two}   ${server_two_obj}   ${sut}  ${client_one}   ${client_one_obj}    ${client_two}   ${client_two_obj} =     Start Test System   ${PAYLOAD_DIR}/multi_targets.yaml

    ${server_one_msg} =     Convert To Bytes    \x00\x00\x00\x0bHello there Client 1
    ${retval} =     Call Method     ${server_one_obj.stdin}     write   ${server_one_msg}
    Log     server written returned: ${retval}
    Call Method     ${server_one_obj.stdin}     flush
    ${rslt} =   Call Method     ${client_one_obj.stdout}    read    ${24}
    Log     Message from server: ${rslt}
    Should Be Equal    ${rslt}     ${server_one_msg}

    ${server_two_msg} =     Convert To Bytes    \x00\x00\x00\x0bHello there Client 2
    ${retval} =     Call Method     ${server_two_obj.stdin}     write   ${server_two_msg}
    Log     server written returned: ${retval}
    Call Method     ${server_two_obj.stdin}     flush
    ${rslt} =   Call Method     ${client_two_obj.stdout}    read    ${24}
    Log     Message from server: ${rslt}
    Should Be Equal    ${rslt}     ${server_two_msg}

    ${client_two_msg} =    Convert To Bytes    \x00\x00\x00\x01Z
    ${retval} =     Call Method     ${client_two_obj.stdin}     write   ${client_two_msg}
    Log     write returned ${retval}
    Call Method     ${client_two_obj.stdin}     flush
    ${rslt} =   Call Method     ${server_two_obj.stdout}    read    ${5}
    Log     Message from client: ${rslt}
    Should Be Equal    ${rslt}     ${client_two_msg}

    ${client_one_msg} =    Convert To Bytes    \x00\x00\x00\x01Y
    ${retval} =     Call Method     ${client_one_obj.stdin}     write   ${client_one_msg}
    Log     write returned ${retval}
    Call Method     ${client_one_obj.stdin}     flush
    ${rslt} =   Call Method     ${server_one_obj.stdout}    read    ${5}
    Log     Message from client: ${rslt}
    Should Be Equal    ${rslt}     ${client_one_msg}

    Stop tlslookieloo   ${sut}

    Validate Single Message File Content  data/app1.msgs   <00><00><00><0b>Hello there Client 1    <00><00><00><01>Y
    Validate Single Message File Content  data/app2.msgs   <00><00><00><0b>Hello there Client 2    <00><00><00><01>Z

Multiple Message Same Source
    [Timeout]   25s
    ${server_one}   ${server_one_obj}  ${server_two}   ${server_two_obj}   ${sut}  ${client_one}   ${client_one_obj}    ${client_two}   ${client_two_obj} =     Start Test System   ${PAYLOAD_DIR}/multi_targets.yaml

    Send Message String     ${client_one_obj}   ${server_one_obj}   Client One Part 1\n
    Send Message String     ${client_one_obj}   ${server_one_obj}   Client One Part 2
    Send Message String     ${client_one_obj}   ${server_one_obj}   \ Client One Part 3

    Send Message String     ${client_two_obj}   ${server_two_obj}   Client Two Part 1\n
    Send Message String     ${client_two_obj}   ${server_two_obj}   Client Two Part 2
    Send Message String     ${client_two_obj}   ${server_two_obj}   \ Client Two Part 3
    
    Send Message String     ${server_one_obj}   ${client_one_obj}   Server One Part 1\n
    Send Message String     ${server_one_obj}   ${client_one_obj}   Server One Part 2
    Send Message String     ${server_one_obj}   ${client_one_obj}   \ Server One Part 3

    Send Message String     ${server_two_obj}   ${client_two_obj}   Server Two Part 1\n
    Send Message String     ${server_two_obj}   ${client_two_obj}   Server Two Part 2
    Send Message String     ${server_two_obj}   ${client_two_obj}   \ Server Two Part 3

    Sleep   1s
    Stop tlslookieloo   ${sut}

    ${data_file} =  Set Variable    data/app1.msgs
    Should Exist    ${data_file}
    ${file_data} =  Get File    ${data_file}
    ${num_lines} =  Get Line Count  ${file_data}
    Should Be Equal     ${20}    ${num_lines}

	${line} =   Get Line    ${file_data}    0
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    1
    Should Be Equal As Strings  ${line}     Client One Part 1<0a>

    ${line} =   Get Line    ${file_data}    2
    Should Be Empty     ${line}

    ${line} =   Get Line    ${file_data}    3
    Should Be Equal As Strings  ${line}     ${END_TAG}

	${line} =   Get Line    ${file_data}    4
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    5
    Should Be Equal As Strings  ${line}     Client One Part 2

    ${line} =   Get Line    ${file_data}    6
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    7
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    8
    Should Be Equal As Strings  ${line}     \ Client One Part 3

    ${line} =   Get Line    ${file_data}    9
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    10
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    11
    Should Be Equal As Strings  ${line}     Server One Part 1<0a>

    ${line} =   Get Line    ${file_data}    12
    Should Be Empty     ${line}

    ${line} =   Get Line    ${file_data}    13
    Should Be Equal As Strings  ${line}     ${END_TAG}

	${line} =   Get Line    ${file_data}    14
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    15
    Should Be Equal As Strings  ${line}     Server One Part 2

    ${line} =   Get Line    ${file_data}    16
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    17
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    18
    Should Be Equal As Strings  ${line}     \ Server One Part 3

    ${line} =   Get Line    ${file_data}    19
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${data_file} =  Set Variable    data/app2.msgs
    Should Exist    ${data_file}
    ${file_data} =  Get File    ${data_file}
    ${num_lines} =  Get Line Count  ${file_data}
    Should Be Equal     ${20}    ${num_lines}

	${line} =   Get Line    ${file_data}    0
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    1
    Should Be Equal As Strings  ${line}     Client Two Part 1<0a>

    ${line} =   Get Line    ${file_data}    2
    Should Be Empty     ${line}

    ${line} =   Get Line    ${file_data}    3
    Should Be Equal As Strings  ${line}     ${END_TAG}

	${line} =   Get Line    ${file_data}    4
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    5
    Should Be Equal As Strings  ${line}     Client Two Part 2

    ${line} =   Get Line    ${file_data}    6
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    7
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    8
    Should Be Equal As Strings  ${line}     \ Client Two Part 3

    ${line} =   Get Line    ${file_data}    9
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    10
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    11
    Should Be Equal As Strings  ${line}     Server Two Part 1<0a>

    ${line} =   Get Line    ${file_data}    12
    Should Be Empty     ${line}

    ${line} =   Get Line    ${file_data}    13
    Should Be Equal As Strings  ${line}     ${END_TAG}

	${line} =   Get Line    ${file_data}    14
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    15
    Should Be Equal As Strings  ${line}     Server Two Part 2

    ${line} =   Get Line    ${file_data}    16
    Should Be Equal As Strings  ${line}     ${END_TAG}

    ${line} =   Get Line    ${file_data}    17
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    18
    Should Be Equal As Strings  ${line}     \ Server Two Part 3

    ${line} =   Get Line    ${file_data}    19
    Should Be Equal As Strings  ${line}     ${END_TAG}
