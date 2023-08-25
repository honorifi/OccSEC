OLTP="occlum run /bin/sysbench /usr/local/share/sysbench/oltp_read_only.lua \
--mysql-host='127.0.0.1' --mysql-user=root --time=60 \
--mysql-db=mysql --tables=3 --table-size=100000 --rand-type=pareto \
--mysql-ssl=DISABLED"

PREPARE=" prepare"
RUN=" --threads=2 --report-interval=10 run"
CLEAN=" --threads=2 --report-interval=10 cleanup"
tmp_op=""

cd occlum_instance
echo "choose op: [prepare/run/cleanup]"
read op

if [ $op = "prepare" ];then
	tmp_op=$OLTP$PREPARE
elif [ $op = "run" ];then
	tmp_op=$OLTP$RUN
elif [ $op = "cleanup" ];then
	tmp_op=$OLTP$CLEAN
fi

echo $tmp_op
eval $tmp_op
