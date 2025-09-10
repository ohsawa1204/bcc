'''
Usage:

python3 simple_physmem.py maps.txt
'''
import sys
import re

def analysis(maps_file):
    total_pss = 0
    total_pss_anon = 0
    total_pss_file =0
    with open(maps_file, 'r') as f:
        datalist = f.readlines()
        for data in datalist:
            if re.search("Rss:", data):
                items = data.split()
                pss = int(items[5])
                pss_anon = int(items[8])
                pss_file = int(items[11])
                total_pss = total_pss + pss
                total_pss_anon = total_pss_anon + pss_anon
                total_pss_file = total_pss_file + pss_file
    print("total_pss:", total_pss, "kB total_pss_anon:", total_pss_anon, "kB total_pss_file:", total_pss_file)

if __name__ == "__main__":
    args = sys.argv
    maps_file = args[1]
    analysis(maps_file)
