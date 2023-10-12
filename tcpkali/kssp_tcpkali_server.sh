cd occlum_instance

OPERATION="occlum run /bin/tcpkali -l 3308 -T 720"
SSL_CERT="/etc/server-cert.pem"
SSL_KEY="/etc/server-key.pem"

COM_OP=$OPERATION" --latency-connect"
# COM_OP=$COM_OP" --ssl"
# COM_OP=$COM_OP" --ssl-key "$SSL_KEY
# COM_OP=$COM_OP" --ssl-cert "$SSL_CERT

echo -e $COM_OP
eval $COM_OP
