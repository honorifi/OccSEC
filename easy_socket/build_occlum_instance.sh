#!/bin/bash
set -e

BLUE='\033[1;34m'
NC='\033[0m'

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" >/dev/null 2>&1 && pwd )"
python_dir="$script_dir/occlum_instance/image/opt/python-occlum"

rm -rf occlum_instance && occlum new occlum_instance
rm -rf occlum_instance_2
cd occlum_instance && rm -rf image
copy_bom -f ../easy_socket.yaml --root image --include-dir /root/occlum/occlum/etc/template

if [ ! -d $python_dir ];then
    echo "Error: cannot stat '$python_dir' directory"
    exit 1
fi

new_json="$(jq '.resource_limits.user_space_size = "640MB" |
        .resource_limits.kernel_space_heap_size = "256MB" |
        .env.default += ["PYTHONHOME=/opt/python-occlum", "KSSP_MODE=off"]' Occlum.json)" && \
echo "${new_json}" > Occlum.json
occlum build

cd ..
cp -f myEC/ec* ./occlum_instance/
cp -r occlum_instance occlum_instance_2

