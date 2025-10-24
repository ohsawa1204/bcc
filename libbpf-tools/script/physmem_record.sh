#!/bin/bash

SUDO_PASSWD=autoware

script_dir=`dirname $0`
first_index=${1:-0}
process=${2:-"/opt/ros/humble/bin/ros2 launch"}
use_aw_physmem=${3:-1}
num_loops=${4:-1}
interval=${5:-5}

process_pid=`ps aux|grep "${process}" | grep -v grep | grep -v physmem_record.sh | grep -v strace | grep -v 'bag play' | awk '{print $2}'`

while [ -z ${process_pid} ]; do
    process_pid=`ps aux|grep "${process}" | grep -v grep | grep -v physmem_record.sh | grep -v strace | grep -v 'bag play' | awk '{print $2}'`
    sleep 1
done

#kill -INT `ps aux | grep wastmem | grep -v grep | awk '{print $2}'`
for ((i=0; i < $num_loops; i++)); do
    date_time=`date '+%Y%m%d_%H%M%S'`
    index=`printf "%03d" $((first_index+i))`
    echo record ${index} @ ${date_time}
    suffix=${index}_${date_time}
    if [ $use_aw_physmem -eq 1 ]; then
        ${script_dir}/insert_marker_aw_physmem.sh
    fi
    top -c -b -n 1 > top_${suffix}.txt
    pstree ${process_pid} -p -T > pstree_${suffix}.txt
    ps ax -L > ps_${suffix}.txt
    echo ${SUDO_PASSWD} | sudo -S python3 ${script_dir}/ps_map.py pstree_${suffix}.txt
    free > free_${suffix}.txt
    cat /proc/meminfo > meminfo_${suffix}.txt
    if [ $num_loops -gt 1 -a $i -lt $((num_loops-1)) ]; then
        sleep $interval
    fi
done
