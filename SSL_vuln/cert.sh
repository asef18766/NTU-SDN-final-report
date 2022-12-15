#!/bin/bash
$PATH_TO_OPENSSL/openssl req -new -newkey rsa:2048 -config ca.cnf -keyout ca.key -noenc -out ca.csr
$PATH_TO_OPENSSL/openssl x509 -in ca.csr -out ca.pem -req -signkey ca.key -extfile ca.cnf -extensions v3_req -days 1001
$PATH_TO_OPENSSL/openssl req -new -newkey rsa:2048 -config leaf.cnf -keyout leaf.key -noenc -out leaf.csr
$PATH_TO_OPENSSL/openssl x509 -CA ca.pem -CAkey ca.key -CAcreateserial -in leaf.csr -out leaf.pem -req -extfile leaf.cnf -extensions v3_req -days 1001
