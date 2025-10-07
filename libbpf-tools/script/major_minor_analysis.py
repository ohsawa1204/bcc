'''
Usage:

python3 out.txt
(out.txt is output with HOOK_HANDLE_MM_FAULT enabled)

'''

import sys
import numpy as np

if __name__ == "__main__":
    args = sys.argv
    out_file = args[1]

    major_delta = []
    minor_delta = []

    f = open(out_file, 'r')
    datalist = f.readlines()
    f.close()
    cnt = 0
    for data in datalist:
        items = data.split()
        if items[5] == '1':
            major_delta.append(int(items[4]))
        else:
            minor_delta.append(int(items[4]))

    print("minor_cnt = ", len(minor_delta), "major_cnt = ", len(major_delta))
    print("minor_avg = ", sum(minor_delta) / len(minor_delta), "major_avg = ", sum(major_delta) / len(major_delta))
    print("minor_min = ", min(minor_delta), "major_min = ", min(major_delta))
    print("minor_max = ", max(minor_delta), "major_max = ", max(major_delta))
    print("minor_std = ", np.std(minor_delta), "major_std = ", np.std(major_delta))
