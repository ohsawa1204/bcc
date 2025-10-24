#!/bin/bash

INIT_ALLOC_NUM=60
INTERVAL=10
SUDO_PASSWD=autoware

out_dir=$1
init_alloc_num=${2:-${INIT_ALLOC_NUM}}
interval=${3:-${INTERVAL}}
date_time=`date '+%Y%m%d_%H%M%S'`
aw_physmem_out_file=aw_physmem_${date_time}.txt
wastmem_out_file=wastmem_${date_time}.txt

if [ -d ${out_dir} ]; then
    echo ${out_dir} exists
    exit
fi
mkdir ${out_dir}
cd ${out_dir}
echo ${SUDO_PASSWD} | sudo -S ../../aw_physmem 2>stderr.txt >${aw_physmem_out_file} &
aw_physmem_pid=`ps aux|grep "aw_physmem" | grep -v grep | grep -v test1.sh | awk '{print $2}'`
trap 'echo ${SUDO_PASSWD} | sudo -S kill -INT ${aw_physmem_pid} > /dev/null 2>&1; exit' SIGINT

read -p "Hit enter to start wastmem: "
../wastmem -a ${init_alloc_num} -c ../../script/physmem_record.sh -i ${interval} | tee ${wastmem_out_file}
