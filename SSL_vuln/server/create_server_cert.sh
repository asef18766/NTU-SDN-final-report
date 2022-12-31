#/bin/bash
if [ -z "$1" ]
    then 
        echo "usage : ./run.sh vuln or ca"
        exit 1
fi

## Create the CA CSR
$PATH_TO_OPENSSL/openssl req -new -newkey rsa:2048 -config "${1}.cnf" -keyout ca.key -noenc -out ca.csr

# Create the CA cert
$PATH_TO_OPENSSL/openssl x509 -in ca.csr -out "${1}.pem" -req -signkey ca.key -extfile "${1}.cnf" -extensions v3_req -days 1001

# Create the leaf CSR
$PATH_TO_OPENSSL/openssl req -new -newkey rsa:2048 -config leaf.cnf -keyout leaf.key -noenc -out leaf.csr

# Create the CA cert
$PATH_TO_OPENSSL/openssl x509 -CA "${1}.pem" -CAkey ca.key -CAcreateserial -in leaf.csr -out leaf.pem -req -extfile leaf.cnf -extensions v3_req -days 1001
