*** Settings ***
Library     String
Resource    functional.resource

Test Setup  Reset Data Dir
Test Teardown   Run Keyword And Ignore Error    Terminate All Processes

*** Test Cases ***
Single Message Text
    [Timeout]   25s
    ${server}   ${server_obj} =     Start Server    9901    ${SERVER_CERT}  ${SERVER_KEY}
    ${sut} =    Start tlslookieloo  ${PAYLOAD_DIR}/single_target_test_1.yaml
    ${client}   ${client_obj} =     Start Client    localhost:9900

    ${msg} =    Encode String To Bytes  Hello from server   ASCII
    ${retval} =     Call Method     ${server_obj.stdin}     write   ${msg}
    Log     server write returned: ${retval}
    Call Method     ${server_obj.stdin}     flush

    ${rslt} =   Call Method     ${client_obj.stdout}    read    ${17}
    Log     Message from server: ${rslt}

    ${msg} =    Encode String To Bytes  Hello from client   ASCII
    ${retval} =     Call Method     ${client_obj.stdin}     write   ${msg}
    Log     write returned: ${retval}
    Call Method     ${client_obj.stdin}     flush

    ${rslt} =   Call Method     ${server_obj.stdout}    read    ${11}
    Log     Message from client: ${rslt}

    ${rslt} =   Terminate Process   ${sut}
    Log     tlslookieloo exit code: ${rslt.rc}
    Log     tlslookieloo stdout: ${rslt.stdout}
    Log     tlslookieloo stderr: ${rslt.stderr}

    ${data_file} =  Set Variable    data/single_target_test1.msgs
    Should Exist    ${data_file}
    ${file_data} =  Get File    ${data_file}
    ${num_lines} =  Get Line Count  ${file_data}
    Should Be Equal     ${6}    ${num_lines}

	${line} =   Get Line    ${file_data}    0
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    1
    Should Be Equal As Strings  ${line}     Hello from server

    ${line} =   Get Line    ${file_data}    2
    Should Be Equal As Strings  ${line}     ${END_TAG}

	${line} =   Get Line    ${file_data}    3
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    4
    Should Be Equal As Strings  ${line}     Hello from client

    ${line} =   Get Line    ${file_data}    5
    Should Be Equal As Strings  ${line}     ${END_TAG}

Single Message Binary
    [Timeout]   25s
    ${server}   ${server_obj} =     Start Server    9901    ${SERVER_CERT}  ${SERVER_KEY}
    ${sut} =    Start tlslookieloo  ${PAYLOAD_DIR}/single_target_test_1.yaml
    ${client}   ${client_obj} =     Start Client    localhost:9900

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

    ${rslt} =   Terminate Process   ${sut}
    Log     tlslookieloo exit code: ${rslt.rc}
    Log     tlslookieloo stdout: ${rslt.stdout}
    Log     tlslookieloo stderr: ${rslt.stderr}

    ${data_file} =  Set Variable    data/single_target_test1.msgs
    Should Exist    ${data_file}
    ${file_data} =   Get File     ${data_file}
    Log     File data content
    Log     ${file_data}

	${line} =   Get Line    ${file_data}    0
    Should Match Regexp     ${line}     ${STOC_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    1
    Should Be Equal As Strings   ${line}     <00><00><00><0b>Hello there

    ${line} =   Get Line    ${file_data}    2
    Should Be Equal As Strings  ${line}     ${END_TAG}

	${line} =   Get Line    ${file_data}    3
    Should Match Regexp     ${line}     ${CTOS_HEADER_LINE}

    ${line} =   Get Line    ${file_data}    4
    Should Be Equal As Strings   ${line}     <00><00><00><01>Y

    ${line} =   Get Line    ${file_data}    5
    Should Be Equal As Strings  ${line}     ${END_TAG}
