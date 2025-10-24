#!/bin/bash

script_name=$(basename $0)
sudo kill -USR1 `ps aux|grep aw_physmem | grep -v sudo | grep -v grep | grep -v tee | grep -v ${script_name} | awk '{print $2}'`
