'''
Usage:

python3 ps_map.py pstree.txt
'''
import re
import sys
import os

def extract_pids(datalist) -> list[int]:
    pidlist = []
    for data in datalist:
        pid_strings = re.findall(r"\((\d+)\)", data)

        for pid_str in pid_strings:
            pidlist.append(int(pid_str))

    return pidlist

def write_maps(pids, out_file):
    f = open(out_file, 'w')
    for pid in pids:
        f.write('------\n')
        status_file = "/proc/" + str(pid) + "/smaps_rollup"
        if os.path.isfile(status_file) == False:
            continue
        s = open(status_file, 'r')
        datalist = s.readlines()
        s.close()
        for data in datalist:
            if re.match(r"Rss:", data):
                items = data.split()
                rss_val = items[1]
                rss_unit = items[2]
            elif re.match(r"Pss:", data):
                items = data.split()
                pss_val = items[1]
                pss_unit = items[2]
            elif re.match(r"Pss_Anon:", data):
                items = data.split()
                pss_anon_val = items[1]
                pss_anon_unit = items[2]
            elif re.match(r"Pss_File:", data):
                items = data.split()
                pss_file_val = items[1]
                pss_file_unit = items[2]
        f.write(str(pid) + ' Rss: ' + rss_val + ' ' + rss_unit + ' Pss: ' + pss_val + ' ' + pss_unit + ' Pss_Anon: ' + pss_anon_val + ' ' + pss_anon_unit + ' Pss_File: ' + pss_file_val + ' ' + pss_file_unit + '\n')
        map_file = "/proc/" + str(pid) + "/maps"
        m = open(map_file, 'r')
        f.write(m.read())
        m.close()

if __name__ == "__main__":
    args = sys.argv
    ps_file = args[1]
    f = open(ps_file, 'r')
    datalist = f.readlines()
    f.close()
    date_time = os.path.basename(ps_file)[7:-4]

    extracted_pids = extract_pids(datalist)
    print(extracted_pids)
    out_file = "maps_" + date_time + ".txt"
    write_maps(extracted_pids, out_file)
