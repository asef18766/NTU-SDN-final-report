#!/bin/bash
if [[  $# -lt 1 ]]
    then 
        echo "usage ./run.sh <client_mode>"
        echo "mode: ca , vuln"
        exit 1 ; 
fi 



## client
(cd ./client && ./create_client_cert.sh ${1})
$PATH_TO_OPENSSL/openssl s_client -connect localhost:9001 -chainCAfile "client/${1}.pem" -cert client/leaf.pem -key client/leaf.key -state
