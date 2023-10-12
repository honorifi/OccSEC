cn_name=${1:-"localhost"}

mkdir myCA
cd myCA

function generate_ca()
{
    # Generate CA files
    openssl req -x509 -nodes -days 1825 -newkey rsa:2048 -keyout ca.key -out cacert.pem -subj "/CN=${cn_name}"
}

function generate_key_cert()
{
    # Prepare test private key
    openssl genrsa -out test.key 2048
    # Use private key to generate a Certificate Sign Request
    openssl req -new -key test.key -out test.csr -subj "/C=CN/ST=Shanghai/L=Shanghai/O=Any/CN=${cn_name}"
    # Use CA private key and CA file to sign test CSR
    openssl x509 -req -in test.csr -CA cacert.pem -CAkey ca.key -CAcreateserial -out test.crt -days 825 -sha256
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

generate_ca
generate_server_keys
generate_client_keys