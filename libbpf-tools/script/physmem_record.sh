#!/bin/bash

process=${1:-/opt/ros/humble/bin/ros2}
DATE_TIME=`date '+%Y%m%d_%H%M%S'`
script_dir=`dirname $0`

#${script_dir}/insert_marker_aw_physmem.sh
pstree `ps aux|grep ${process} | grep -v grep | grep -v physmem_record.sh | grep -v strace | grep -v 'bag play' | awk '{print $2}'` -p -T > pstree_${DATE_TIME}.txt
ps ax -L > ps_${DATE_TIME}.txt
python3 ${script_dir}/ps_map.py pstree_${DATE_TIME}.txt
free > free_${DATE_TIME}.txt
cat /proc/meminfo > meminfo_${DATE_TIME}.txt
