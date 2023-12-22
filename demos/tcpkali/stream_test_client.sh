cd occlum_instance_2

DURATION="120"
OPERATION="occlum run /bin/tcpkali 127.1:3308 -T 60"
MSG="'hello'"
SSL_CERT="/etc/client-cert.pem"
SSL_KEY="/etc/client-key.pem"

COM_OP=$OPERATION
COM_OP=$COM_OP" --ssl"
# COM_OP=$COM_OP" --ssl-key "$SSL_KEY
# COM_OP=$COM_OP" --ssl-cert "$SSL_CERT
COM_OP=$COM_OP" --message "$MSG

echo -e $COM_OP
eval $COM_OP