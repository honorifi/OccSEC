#! /bin/bash
set -e

cd bounce_back && make && cd ..
cp -f bounce_back/bounce_back ./main

rm -rf occlum_instance occlum_instance_2
occlum new occlum_instance

cd occlum_instance
rm -rf image
copy_bom -f ../main.yaml --root image --include-dir /opt/occlum/etc/template

new_json="$(jq '.resource_limits.user_space_size = "256MB" |
		.resource_limits.kernel_space_heap_size="256MB" |
        .resource_limits.max_num_of_threads = 64 |
		.env.default += ["KSSP_MODE=on"]' Occlum.json)" && \
echo "${new_json}" > Occlum.json

occlum build
cd ..
cp -f myEC/* occlum_instance/
cp -r occlum_instance occlum_instance_2
