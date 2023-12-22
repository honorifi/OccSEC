#! /bin/bash

set -e

rm -rf occlum_instance occlum_instance_2
occlum new occlum_instance

cd occlum_instance
rm -rf image
copy_bom -f ../tcpkali.yaml --root image --include-dir /opt/occlum/etc/template

new_json="$(jq '.resource_limits.user_space_size = "8000MB" |
		.resource_limits.kernel_space_heap_size="20000MB" |
                .resource_limits.max_num_of_threads = 96 |
		.env.default += ["TERM=xterm", "KSSP_MODE=on"]' Occlum.json)" && \
echo "${new_json}" > Occlum.json

occlum build
cp -f ../myEC/* ./

cd ..
cp -r occlum_instance occlum_instance_2
#occlum run /bin/sysbench threads --threads=200 --thread-yields=100 --thread-locks=4 --time=10 run
