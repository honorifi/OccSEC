#! /bin/bash
cn_name=${1:-"localhost"}

# Generate the self-signed key and cert
function generate_key_cert()
{
    # Prepare test private key
    openssl genrsa -out test.key 2048
    # Use private key to generate a Certificate Sign Request
    openssl req -new -key test.key -out test.csr -subj "/C=CN/ST=Shanghai/L=Shanghai/O=Ant/CN=${cn_name}"
    # Use self private key to sign test CSR
    openssl x509 -req -in test.csr -signkey test.key -out test.crt
}

function generate_server_keys()
{
    generate_key_cert
    mv test.crt server-cert.pem
    mv test.key server-key.pem
}

function generate_client_keys()
{
    generate_key_cert
    mv test.crt client-cert.pem
    mv test.key client-key.pem
}

rm -rf myCA && mkdir myCA
cd myCA
generate_server_keys
generate_client_keys