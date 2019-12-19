*** Settings ***
Library     Process
Library     OperatingSystem

*** Variables ***
${openssl} =    openssl

*** Keyword ***
Log Process Failed Start
    [Arguments]     ${handle}   ${procname}
    Terminate Process   ${handle}
    ${rslt} =   Get Process Result  ${handle}
    Log     ${procname} failed to start exit Code: ${rslt.rc} Console output: ${rslt.stdout}\n${rslt.stderr}    ERROR
    Fail

Start tlslookieloo
    [Arguments]    ${target_file}
    ${sut} =    Start Process   ${TLSLOOKIELOO}     -t  ${target_file}  -l  logger.properties   alias=testprocess
    Sleep   500ms
    ${rslt} =   Is Process Running  handle=${sut}
    Run Keyword If  ${rslt} == ${False}     Log Process Failed Start    ${sut}  tlslookieloo
    [Return]    ${sut}

Stop tlslookieloo
    [Arguments]     ${sut}
    Send Signal To Process  SIGINT  ${sut}
    ${rslt} =   Wait For Process    ${sut}  timeout=2   on_timeout=kill
    Log     tlslookieloo exit code: ${rslt.rc}
    Log     tlslookieloo stdout: ${rslt.stdout}
    Log     tlslookieloo stderr: ${rslt.stderr}

Start server
    [Arguments]     ${listen_port}  ${cert}     ${key}
    ${server} =     Start Process   ${openssl}  s_server    -ign_eof    -quiet  -cert   ${cert}     -key    ${key}  -port   +${listen_port}
    Sleep   1
    ${rslt} =   Is Process Running  ${server}
    Run Keyword If  ${rslt} == ${False}     Log Process Failed Start    ${server}   s_server
    ${server_obj} =     Get Process Object  ${server}
    [Return]    ${server}   ${server_obj}

Start client
    [Arguments]     ${host}
    ${client} =     Start Process   ${openssl}  s_client    -ign_eof    -quiet  -CAfile     ${CA_FILE}  -connect    ${host}
    Sleep   1s
    ${rslt} =   Is Process Running  ${client}
    Run Keyword If  ${rslt} == ${False}     Log Process Failed Start    ${client}   s_client
    ${client_obj} =     Get Process Object  ${client}
    [Return]    ${client}   ${client_obj}

Reset Data Dir
    Remove Directory    data    recursive=${True}
    Create Directory    data

Send Message String
    [Arguments]     ${src}      ${dest}     ${msg}
    ${expect_len} =     Get Length  ${msg}
    Log     Message length: ${expect_len}
    ${msg_byte} =   Encode String To Bytes  ${msg}  ASCII

    ${rslt} =   Call Method     ${src.stdin}    write   ${msg_byte}
    Should Be Equal As Integers  ${expect_len}    ${rslt}
    Call Method     ${src.stdin}    flush

    ${recv_msg} =   Call Method     ${dest.stdout}  read    ${rslt}
    ${str_recv} =   Decode Bytes To String      ${recv_msg}     ASCII
    Log     Message Received: ${str_recv}
    Should Be Equal As Strings  ${str_recv}     ${msg}

Post Test Cleanup
    Terminate All Processes
    ${rslt} =   Get Process Result  testprocess
    Log     tlslookieloo post-test exit code: ${rslt.rc}
    Log     tlslookieloo post-test stdout: ${rslt.stdout}
    Log     tlslookieloo post-test stderr: ${rslt.stderr}
