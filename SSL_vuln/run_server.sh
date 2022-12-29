#!/bin/bash
if [[  $# -lt 1 ]]
    then 
        echo "usage ./run.sh <server_mode> <debug>"  
        echo "mode: ca , vuln"
        exit 1 ; 
fi 

## server
(cd ./server && ./create_server_cert.sh ${1})

if [ "$2" ==  "debug" ]
then
    gdb -x gdb_script --args $PATH_TO_OPENSSL/openssl s_server  -cert server/leaf.pem -key server/leaf.key -cert_chain "server/${1}.pem" -accept 9001 -verify 2 -tls1_2 
else
    $PATH_TO_OPENSSL/openssl s_server  -cert server/leaf.pem -key server/leaf.key -cert_chain "server/${1}.pem" -accept 9001 -verify 2 -state -tls1_2
fi

