#!/bin/bash
SERVER_IP=172.23.0.2
if [[  $# -lt 1 ]]
    then
        echo "usage ./run.sh <client_mode> <debug>"
        echo "mode: ca , vuln"
        exit 1 ;
fi

## client

(cd ./client && ./create_client_cert.sh ${1})

if [ "$2" ==  "debug" ]
then
    gdb -x gdb_script --args $PATH_TO_OPENSSL/openssl s_client -connect $SERVER_IP:9001 -chainCAfile "client/${1}.pem" -cert client/leaf.pem -key client/leaf.key -tls1_2
elif [ "$2" == "bypass" ]
then
    echo "bypass"
    gdb -x bypass_script --args $PATH_TO_OPENSSL/openssl s_client -connect $SERVER_IP:9001 -chainCAfile "client/${1}.pem" -cert client/leaf.pem -key client/leaf.key -tls1_2
else
    $PATH_TO_OPENSSL/openssl s_client -connect $SERVER_IP:9001 -chainCAfile "client/${1}.pem" -cert client/leaf.pem -key client/leaf.key -state -tls1_2

fi
