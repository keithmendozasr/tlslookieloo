*** Settings ***
Library     Process
Library     String
Library     OperatingSystem

Resource    functional.resource

Test Setup  Remove Directory    data    recursive=${True}
Test Teardown   Terminate All Processes

*** Test Cases ***
Bad Logger config
    ${sut} =    Start Process   ${TLSLOOKIELOO}     -t  ${PAYLOAD_DIR}/basic_operations.yaml     -l  badlog.prop   alias=testprocess
    Sleep   1s
    ${rslt} =   Terminate Process   ${sut}
    
    Log     tlslookieloo stdout:
    Log     ${rslt.stdout}

    Log     tlslookieloo stderr:
    Log     ${rslt.stderr}

    ${line} =   Get Line  ${rslt.stderr}    0
    Should Contain  ${line}  log4cplus:ERROR could not open file badlog.prop

    Should Be Equal As Integers     ${rslt.rc}  ${0}

Target File Not Specified
    ${sut} =    Start Process   ${TLSLOOKIELOO}     alias=testprocess
    ${rslt} =   Wait For Process    ${sut}  timeout=2s  on_timeout=continue
    Process Should Be Stopped   ${sut}

    Log     tlslookieloo stdout:
    Log     ${rslt.stdout}

    Log     tlslookieloo stderr:
    Log     ${rslt.stderr}
    Should Be Equal As Integers  ${rslt.rc}  ${3}

Incorrect Target File
    ${sut} =    Start Process   ${TLSLOOKIELOO}     -t  missing_file.yaml   alias=testprocess
    ${rslt} =   Wait For Process    ${sut}  timeout=2s  on_timeout=continue
    Process Should Be Stopped   ${sut}

    Log     tlslookieloo stdout:
    Log     ${rslt.stdout}

    Log     tlslookieloo stderr:
    Log     ${rslt.stderr}
    Should Be Equal As Integers  ${rslt.rc}  ${4}

Target File Bad Syntax
    ${sut} =    Start Process   ${TLSLOOKIELOO}     -t  ${PAYLOAD_DIR}/badsyntax.yaml   alias=testprocess
    ${rslt} =   Wait For Process    ${sut}  timeout=2s  on_timeout=continue
    Process Should Be Stopped   ${sut}

    Log     tlslookieloo stdout:
    Log     ${rslt.stdout}

    Log     tlslookieloo stderr:
    Log     ${rslt.stderr}
    Should Be Equal As Integers  ${rslt.rc}  ${4}

Handler Failed Start
    ${sut} =    Start Process   ${TLSLOOKIELOO}     -t  ${PAYLOAD_DIR}/missing_client_auth_file.yaml
    Sleep   1s
    Process Should Be Stopped   ${sut}
    ${rslt} =   Wait For Process    ${sut}

    Log     tlslookieloo stdout:
    Log     ${rslt.stdout}

    Should Be Equal As Integers     ${rslt.rc}  ${5}

Client Side Port In Use
    ${temp} =   Start server    9900    ${SERVER_CERT}  ${SERVER_KEY}
    ${sut} =    Start Process   ${TLSLOOKIELOO}     -t  ${PAYLOAD_DIR}/basic_operations.yaml
    Sleep   1s
    Process Should Be Stopped   ${sut}
    ${rslt} =   Wait For Process    ${sut}

    Log     tlslookieloo stdout:
    Log     ${rslt.stdout}

    Log     tlslookieloo stderr:
    Log     ${rslt.stderr}

    Should Be Equal As Integers     ${rslt.rc}  ${5}

    ${expect_lines} =   Get Lines Containing String     ${rslt.stdout}  ERROR - System error encountered starting listener. Failed to bind: Address already in use
    ${line_cnt} =   Get Line Count  ${expect_lines}
    Should Be Equal As Integers  ${line_cnt}     ${1}