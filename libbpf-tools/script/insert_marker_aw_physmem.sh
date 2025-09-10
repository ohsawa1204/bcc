#!/bin/bash

sudo kill -USR1 `ps aux|grep aw_physmem | grep -v sudo | grep -v grep | awk '{print $2}'`
