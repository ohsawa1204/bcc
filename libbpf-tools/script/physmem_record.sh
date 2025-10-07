#!/bin/bash

process=${1:-"/opt/ros/humble/bin/ros2 launch"}
DATE_TIME=`date '+%Y%m%d_%H%M%S'`
script_dir=`dirname $0`

#kill -INT `ps aux | grep wastmem | grep -v grep | awk '{print $2}'`
${script_dir}/insert_marker_aw_physmem.sh
top -c -b -n 1 > top_${DATE_TIME}.txt
pstree `ps aux|grep "${process}" | grep -v grep | grep -v physmem_record.sh | grep -v strace | grep -v 'bag play' | awk '{print $2}'` -p -T > pstree_${DATE_TIME}.txt
ps ax -L > ps_${DATE_TIME}.txt
sudo python3 ${script_dir}/ps_map.py pstree_${DATE_TIME}.txt
free > free_${DATE_TIME}.txt
cat /proc/meminfo > meminfo_${DATE_TIME}.txt
#${script_dir}/../../../linux-ftools/fincore_record_x1.sh ${DATE_TIME}
