'''
Usage:

in a directory where free_xxx.txt, maps_xxx.txt, result_yyy.txt resides,

python3 gencsv.py
'''

import os
import glob
import re
import dataclasses

@dataclasses.dataclass
class PhysmemData:
    anon: int
    file: int
    pss_no_reclaiming: int
    reclaimed: int
    reclaimed_and_reaccessed: int

physmem_data_list = []

def get_item(data, index):
    items = data.split()
    return items[index]

def retrieve_from_result_file(result_file):
    do_retrieve = False
    with open(result_file, 'r') as f:
        datalist = f.readlines()
        for data in datalist:
            if re.search("AUTOWARE WIDE REPORT", data):
                do_retrieve = True
                physmem_data = PhysmemData(0, 0, 0, 0, 0)
                continue
            if do_retrieve:
                if re.search("total_anon = ", data):
                    physmem_data.anon = int(get_item(data, 2))
                elif re.search("total_cached = ", data):
                    physmem_data.file = int(get_item(data, 2))
                elif re.search("total_anon_no_reclaiming = ", data):
                    physmem_data.pss_no_reclaiming = int(get_item(data, 2))
                elif re.search("total_cached_no_reclaiming = ", data):
                    physmem_data.pss_no_reclaiming = physmem_data.pss_no_reclaiming + int(get_item(data, 2))
                elif re.search("total_reclaimed = ", data):
                    physmem_data.reclaimed = int(get_item(data, 2))
                elif re.search("total_reclaimed_and_reaccessed_anon = ", data):
                    physmem_data.reclaimed_and_reaccessed = int(get_item(data, 2))
                elif re.search("total_reclaimed_and_reaccessed_file = ", data):
                    physmem_data.reclaimed_and_reaccessed = physmem_data.reclaimed_and_reaccessed + int(get_item(data, 2))
                    physmem_data_list.append(physmem_data)
                    do_retrieve = False

def simple_physmem(maps_file):
    total_pss = 0
    total_pss_anon = 0
    total_pss_file =0
    with open(maps_file, 'r') as f:
        datalist = f.readlines()
        for data in datalist:
            if re.search("Rss:", data):
                pss = int(get_item(data, 5))
                pss_anon = int(get_item(data, 8))
                pss_file = int(get_item(data, 11))
                total_pss = total_pss + pss
                total_pss_anon = total_pss_anon + pss_anon
                total_pss_file = total_pss_file + pss_file

    return total_pss, total_pss_anon, total_pss_file

def get_free_info(free_file):
    with open(free_file, 'r') as f:
        datalist = f.readlines()
        for data in datalist:
            if re.search("Mem:", data):
                used = int(get_item(data, 2))
                free = int(get_item(data, 3))
                buff_cache = int(get_item(data, 5))
                available = int(get_item(data, 6))
            if re.search("Swap:", data):
                swap_free = int(get_item(data, 3))
        return used, free, swap_free, buff_cache, available

def get_cached_pages(fincore_file):
    with open(fincore_file, 'r') as f:
        datalist = f.readlines()
        for data in datalist:
            if re.search("total cached size:", data):
                total_cached_size = int(get_item(data, 3))
                return total_cached_size

def get_cpu_top(top_file):
    with open(top_file, 'r') as f:
        datalist = f.readlines()
        for data in datalist:
            if re.search("%Cpu\(s\)", data):
                us = float(get_item(data, 1))
                si = float(get_item(data, 3))
                return us, si

def retrieve(dir):
    print("datetime, total_pss,total_anon,total_file,total_pss_plus_reclaimed,reclaimed,reaccessed,used,free,swap_free,buff_cache,available,cpu_usage")
    files = glob.glob(dir + "/*")
    files.sort()
    for file in files:
        if os.path.isfile(file):
            file = os.path.basename(file)
            if re.search('^result_\d+_\d+\.txt', file):
                retrieve_from_result_file(file)

    idx = 0
    for file in files:
        if os.path.isfile(file):
            file = os.path.basename(file)
            if re.search('^maps_\d+_\d+\.txt', file):
                total_pss, total_pss_anon, total_pss_file = simple_physmem(file)
                date_time = os.path.basename(file)[5:-4]
                free_file = 'free_' + date_time + '.txt'
                used, free, swap_free, buff_cache, available = get_free_info(free_file)
                #print(used, free, swap_free, buff_cache, available)
                '''
                fincore_rosbag_file = 'fincore_rosbag_record_' + date_time + '.txt'
                rosbag_cached_size = get_cached_pages(fincore_rosbag_file)
                fincore_maps_file = 'fincore_maps_' + date_time + '.txt'
                maps_cached_size = get_cached_pages(fincore_maps_file)
                '''
                #print(rosbag_cached_size, maps_cached_size)
                top_file = 'top_' + date_time + '.txt'
                us, si = get_cpu_top(top_file)
                print(date_time, total_pss, total_pss_anon, total_pss_file,
                      physmem_data_list[idx].pss_no_reclaiming,
                      physmem_data_list[idx].reclaimed,
                      physmem_data_list[idx].reclaimed_and_reaccessed,
                      used,  free, swap_free, buff_cache, available, us + si, sep=',')
                idx = idx + 1

if __name__ == "__main__":
    retrieve("./")
