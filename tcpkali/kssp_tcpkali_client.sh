cd occlum_instance_2

CONN="100"
DURATION="180"
CONN_RATE="100"
OPERATION="occlum run /bin/tcpkali 127.1:3308"
MSG="\"msg\""
SSL_CERT="/etc/client-cert.pem"
SSL_KEY="/etc/client-key.pem"

COM_OP=$OPERATION" --latency-connect"
COM_OP=$COM_OP" --connections="$CONN
COM_OP=$COM_OP" --duration="$DURATION
COM_OP=$COM_OP" --connect-rate="$CONN_RATE
# COM_OP=$COM_OP" --message "$MSG
# COM_OP=$COM_OP" --ssl"
# COM_OP=$COM_OP" --ssl-key "$SSL_KEY
# COM_OP=$COM_OP" --ssl-cert "$SSL_CERT

echo -e $COM_OP
eval $COM_OP