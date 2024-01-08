#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'

# Run the python demo

if [ $1 == '0' ];then
    cd occlum_instance
    echo -e "${BLUE}instance: occlum run /bin/easy_socket.py 0${NC}"
    occlum run /bin/python3 easy_socket.py 0 
else
    cd occlum_instance_2
    echo -e "${BLUE}instance_2: occlum run /bin/easy_socket.py 1 -n 1${NC}"
    occlum run /bin/python3 easy_socket.py 1 -n 1
fi
