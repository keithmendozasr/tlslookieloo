*** Settings ***
Library     String
Resource    functional.resource

Suite Setup     Check Data Clear
Test Teardown   Run Keyword And Ignore Error    Terminate All Processes

*** Test Cases ***
Single Message
    [Timeout]       25s
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
