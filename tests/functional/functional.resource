*** Settings ***
Library     Process
Library     OperatingSystem

*** Variables ***
${openssl} =    /usr/bin/openssl

*** Keyword ***
Log Process Failed Start
    [Arguments]     ${handle}   ${procname}
    Terminate Process   ${handle}
    ${rslt} =   Get Process Result  ${handle}
    Log     ${procname} failed to start exit Code: ${rslt.rc} Console output: ${rslt.stdout}\n${rslt.stderr}    ERROR
    Fail

Start tlslookieloo
    [Arguments]    ${target_file}
    ${sut} =    Start Process   ${TLSLOOKIELOO}     -t  ${target_file}  alias=testprocess
    Sleep   500ms
    ${rslt} =   Is Process Running  handle=${sut}
    Run Keyword If  ${rslt} == ${False}     Log Process Failed Start    ${sut}  tlslookieloo
    [Return]    ${sut}

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
