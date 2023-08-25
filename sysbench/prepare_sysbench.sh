#! /bin/bash
set -e

rm -rf occlum_instance
occlum new occlum_instance

cd occlum_instance
rm -rf image
copy_bom -f ../sysbench.yaml --root image --include-dir /opt/occlum/etc/template
mv image/usr/local/share/sysbench/lua/* image/usr/local/share/sysbench/

new_json="$(jq '.resource_limits.user_space_size = "8000MB" |
		.resource_limits.kernel_space_heap_size="1000MB" |
                .resource_limits.max_num_of_threads = 96 |
		.env.default += ["KSSP_MODE=on"]' Occlum.json)" && \
echo "${new_json}" > Occlum.json

occlum build
cp -f ../myEC/* ./
#occlum run /bin/sysbench threads --threads=200 --thread-yields=100 --thread-locks=4 --time=10 run
