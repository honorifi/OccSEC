#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'
REPEAT='128'
MSG_SIZE='1024'

# Run the python demo

if [ $1 == '0' ];then
    cd occlum_instance
    echo -e "${BLUE}instance: occlum run /bin/main 0 ${REPEAT}${NC}"
    occlum run /bin/main 0 $REPEAT $MSG_SIZE
elif [ $1 == '1' ];then
    cd occlum_instance_2
    echo -e "${BLUE}instance_2: occlum run /bin/main 1 ${REPEAT}${NC}"
    occlum run /bin/main 1 $REPEAT $MSG_SIZE
elif [ $1 == '2' ];then
    cd occlum_instance
    echo -e "${BLUE}instance: occlum run /bin/main 2 ${REPEAT}${NC}"
    occlum run /bin/main 2 $REPEAT $MSG_SIZE
else
    cd occlum_instance_2
    echo -e "${BLUE}instance_2: occlum run /bin/main 3 ${REPEAT}${NC}"
    occlum run /bin/main 3 $REPEAT $MSG_SIZE
fi
