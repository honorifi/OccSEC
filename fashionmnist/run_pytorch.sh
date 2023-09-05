#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'

# Run the python demo

if [ $1 == '0' ];then
    cd occlum_instance
    echo -e "${BLUE}instance: occlum run /bin/python3 mnist.py 0${NC}"
    WORLD_SIZE=2 RANK=0 OMP_NUM_THREADS=16 occlum run /bin/python3 mnist.py --epoch 3 --no-cuda --seed 42 --save-model 
else
    cd occlum_instance_2
    echo -e "${BLUE}instance_2: occlum run /bin/python3 mnist.py 1${NC}"
    WORLD_SIZE=2 RANK=1 OMP_NUM_THREADS=16 occlum run /bin/python3 mnist.py --epoch 3 --no-cuda --seed 42 --save-model
fi
