#!/bin/bash
set -e

function generate_ca_files()
{
    cn_name=${1:-"localhost"}
    # Generate CA files
    openssl req -x509 -nodes -days 1825 -newkey rsa:2048 -keyout myCA.key -out myCA.pem -subj "/CN=${cn_name}"
    # Prepare test private key
    openssl genrsa -out test.key 2048
    # Use private key to generate a Certificate Sign Request
    openssl req -new -key test.key -out test.csr -subj "/C=CN/ST=Shanghai/L=Shanghai/O=Ant/CN=${cn_name}"
    # Use CA private key and CA file to sign test CSR
    openssl x509 -req -in test.csr -CA myCA.pem -CAkey myCA.key -CAcreateserial -out test.crt -days 825 -sha256
}

generate_ca_files
