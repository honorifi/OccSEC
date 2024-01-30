#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'
REPEAT='10'

# Run the python demo

if [ $1 == '0' ];then
    cd occlum_instance
    echo -e "${BLUE}instance: occlum run /bin/main 0 ${REPEAT}${NC}"
    occlum run /bin/main 0 $REPEAT
else
    cd occlum_instance_2
    echo -e "${BLUE}instance_2: occlum run /bin/main 1 ${REPEAT}${NC}"
    occlum run /bin/main 1 $REPEAT
fi
