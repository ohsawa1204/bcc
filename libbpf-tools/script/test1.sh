#!/bin/bash

NUM_LOOPS=10000
INTERVAL=10
SUDO_PASSWD=autoware

out_dir=$1
date_time=`date '+%Y%m%d_%H%M%S'`
aw_physmem_out_file=aw_physmem_${date_time}.txt
physmem_record_out_file=physmem_record_${date_time}.txt

if [ -d ${out_dir} ]; then
    echo ${out_dir} exists
    exit
fi
mkdir ${out_dir}
cd ${out_dir}
echo ${SUDO_PASSWD} | sudo -S ../../aw_physmem 2>stderr.txt >${aw_physmem_out_file} &
aw_physmem_pid=`ps aux|grep "aw_physmem" | grep -v grep | grep -v test1.sh | awk '{print $2}'`
trap 'echo ${SUDO_PASSWD} | sudo -S kill -INT ${aw_physmem_pid}; exit' SIGINT

read -p "Hit enter to start physmem_record: "
../../script/physmem_record.sh 0 "/opt/ros/humble/bin/ros2 launch" 1 ${NUM_LOOPS} ${INTERVAL} | tee ${physmem_record_out_file}
