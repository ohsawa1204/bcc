'''
Usage:

python3 physmem_analysis_bin.py out.bin ps.txt pstree.txt maps.txt <marker_idx>

'''

import sys
import os
import re

print_vma = False
print_vma_detail = False

UNMAP_FLAG = int(1 << 31)
ZAP_FLAG   = int(1 << 30)
EXEC_FLAG  = int(1 << 29)
MARKER     = int(1 << 20)
END        = int(1 << 19)

process_tgid_dict = {}                    # key: tgid, val: Process
tgid_pid_dict = {}                        # key: pid, val: tgid
mapped_file_dict = {}                     # key: file name, val: MappedFile

class MappedFile:
    def __init__(self, name):
        self.name = name                  # file name
        self.offsets = {}                 # offset to which an access has occurred
        self.offsets_no_reclamation = {}  # while `offsets` can be shrinked by reclamation,
                                          # `offsets_no_reclamation` keeps staying
class Access:
    def __init__(self, addr, write):
        self.addr = addr                  # page aligned address
        self.write = write                # False if read, True if write
        self.num_reclamation = 0          # number of reclamations
        self.num_reaccess = 0             # number of reaccesses after reclamation

class NumAnonFilePages:
    def __init__(self, num_anon, num_file):
        self.anon = num_anon              # anonymous page
        self.file = num_file              # file mapped page
    def add(self, num_anon, num_file):
        self.anon += num_anon
        self.file += num_file

def is_file(name, perm, write):
    if (write == False or perm[3] == 's' or perm[1] == '-') and name != "anon" and name != "[heap]" and name != "[stack]":
        return True
    else:
        return False

class Vma:
    def __init__(self, file, perm, start, end, file_mapped_start_addr):
        global mapped_file_dict
        self.file = file
        self.perm = perm
        self.start = start
        self.end = end
        self.file_mapped_start_addr = file_mapped_start_addr
        if mapped_file_dict.get(self.file) == None:
            self.mapped_file = MappedFile(self.file)
            mapped_file_dict[self.file] = self.mapped_file
        else:
            self.mapped_file = mapped_file_dict[self.file]
        self.reset()

    def reset(self):
        self.anon_accesses = []
        self.file_accesses = []
        self.num_write_accessed_pages = 0
        self.num_read_accessed_pages = 0
        self.num_pages = NumAnonFilePages(0, 0)
        self.num_pages_plus_reclamations = NumAnonFilePages(0, 0)
        self.num_reclaimed_pages = NumAnonFilePages(0, 0)
        self.num_reaccessed_pages = NumAnonFilePages(0, 0)

    def hit(self, addr):
        if self.start <= addr and addr < self.end:
            return True
        else:
            return False

    def addAccess(self, access):
        if access.write == True:
            self.num_write_accessed_pages += 1
        else:
            self.num_read_accessed_pages += 1

        if is_file(self.file, self.perm, access.write):
            self.file_accesses.append(access)
            if access.num_reclamation == access.num_reaccess:
                self.num_pages.file += 1
            self.num_reclaimed_pages.file += access.num_reclamation
            self.num_reaccessed_pages.file += access.num_reaccess
            self.num_pages_plus_reclamations.file += 1

            offset = access.addr - self.file_mapped_start_addr
            if access.num_reclamation == access.num_reaccess and self.mapped_file.offsets.get(offset) == None:
                self.mapped_file.offsets[offset] = offset
            if self.mapped_file.offsets_no_reclamation.get(offset) == None:
                self.mapped_file.offsets_no_reclamation[offset] = offset
        else:
            self.anon_accesses.append(access)
            if access.num_reclamation == access.num_reaccess:
                self.num_pages.anon += 1
            self.num_reclaimed_pages.anon += access.num_reclamation
            self.num_reaccessed_pages.anon += access.num_reaccess
            self.num_pages_plus_reclamations.anon += 1

    def sortAccess(self):
        self.file_accesses.sort(key=lambda x: x.addr)
        self.anon_accesses.sort(key=lambda x: x.addr)

    def print(self):
        print(self.file, self.perm, hex(self.start), "-", hex(self.end))
        print("", len(self.file_accesses) + len(self.anon_accesses), "pages")
        print(" R:", self.num_read_accessed_pages, "W:", self.num_write_accessed_pages)
        if print_vma_detail:
            for access in self.file_accesses:
                if access.write == True:
                    print("", hex(access.addr), 'W')
                else:
                    print("", hex(access.addr), 'R')
            for access in self.anon_accesses:
                if access.write == True:
                    print("", hex(access.addr), 'W')
                else:
                    print("", hex(access.addr), 'R')
            print()

class Process:
    def __init__(self, tgid, rss, pss, pss_anon, pss_file):
        self.name = ""
        self.node = ""
        self.ns = ""
        self.tgid = tgid
        self.rss = rss
        self.pss = pss
        self.pid_list = []
        self.vma_list = []
        self.mapped_file_start = {}
        self.accesses = {}
        self.total_pages = 0
        self.max_pages = 0
        self.all_time_max_pages = 0
        self.reset()

    def reset(self):
        for vma in self.vma_list:
            vma.reset()
        self.non_mapped_read_accesses_list = []
        self.non_mapped_write_accesses_list = []
        self.num_write_accessed_pages = 0
        self.num_read_accessed_pages = 0
        self.num_pages = NumAnonFilePages(0, 0)
        self.num_pages_plus_reclamations = NumAnonFilePages(0, 0)
        self.num_reclaimed_pages = NumAnonFilePages(0, 0)
        self.num_reaccessed_pages = NumAnonFilePages(0, 0)

    def setName(self, name, node, ns):
        self.name = name
        self.node = node
        self.ns = ns

    def addVma(self, vma):
        self.vma_list.append(vma)

    def addPid(self, pid):
        self.pid_list.append(pid)

    def handle_page_fault(self, addr, flag):
        addr = addr & ~(0x1000 - 1)
        if flag & 0x1 or flag & 0x2:
            write = True
        else:
            write = False
        if self.accesses.get(addr) == None:
            access = Access(addr, write)
            self.accesses[addr] = access
        else:
            access = self.accesses[addr]
            if write == True:
                access.write = True
            if access.num_reclamation > access.num_reaccess:
                access.num_reaccess += 1

        self.total_pages += 1
        if self.total_pages > self.max_pages:
            self.max_pages = self.total_pages
        if self.total_pages > self.all_time_max_pages:
            self.all_time_max_pages = self.total_pages

    def handle_munmap(self, start, end):
        accesses_copy = self.accesses.copy()
        for addr in accesses_copy.keys():
            if addr >= start and addr < end:
                del self.accesses[addr]
                self.total_pages -= 1

    def handle_page_reclaim(self, addr):
        if self.accesses.get(addr):
            access = self.accesses[addr]
            access.num_reclamation += 1
            self.total_pages -= 1

    def post_process(self):
        self.reset()
        for addr in self.accesses.keys():
            hit = False
            access = self.accesses[addr]
            for vma in self.vma_list:
                if vma.hit(addr) == True:
                    vma.addAccess(access)
                    hit = True
                    break
            if hit == False:
                if access.write == True:
                    self.non_mapped_write_accesses_list.append(access)
                else:
                    self.non_mapped_read_accesses_list.append(access)

        self.num_write_accessed_pages = len(self.non_mapped_write_accesses_list)
        self.num_read_accessed_pages = len(self.non_mapped_read_accesses_list)
        self.num_pages.anon = len(self.non_mapped_write_accesses_list) + len(self.non_mapped_read_accesses_list)
        self.num_pages_plus_reclamations.anon = len(self.non_mapped_write_accesses_list) + len(self.non_mapped_read_accesses_list)
        for vma in self.vma_list:
            vma.sortAccess()
            self.num_write_accessed_pages += vma.num_write_accessed_pages
            self.num_read_accessed_pages += vma.num_read_accessed_pages
            self.num_pages.add(vma.num_pages.anon, vma.num_pages.file)
            self.num_pages_plus_reclamations.add(vma.num_pages_plus_reclamations.anon, vma.num_pages_plus_reclamations.file)
            self.num_reclaimed_pages.add(vma.num_reclaimed_pages.anon,  vma.num_reclaimed_pages.file)
            self.num_reaccessed_pages.add(vma.num_reaccessed_pages.anon, vma.num_reaccessed_pages.file)

    def print(self):
        print("process =", self.name, self.node, self.ns)
        print(" pid =", self.tgid)
        #print(" Rss:", self.rss)
        #print(" Pss:", self.pss)
        print(" Rss Anon kB:", self.num_pages.anon * 4)
        print(" Rss File kB:", self.num_pages.file * 4)
        print(" Rss + Reclaimed Anon kB:", self.num_pages_plus_reclamations.anon * 4)
        print(" Rss + Reclaimed File kB:", self.num_pages_plus_reclamations.file * 4)
        print(" Rss Max kB:", self.max_pages * 4)
        print(" Rss Max kB (All Time):", self.all_time_max_pages * 4)
        print(" (Rss total kB:", self.total_pages * 4, ")")
        print(" reclaimed_kb:", (self.num_reclaimed_pages.anon + self.num_reclaimed_pages.file) * 4)
        print("  anon_reclaimed kB:", self.num_reclaimed_pages.anon * 4)
        print("  file_reclaimed kB:", self.num_reclaimed_pages.file * 4)
        print("  anon_reaccessed kB:", self.num_reaccessed_pages.anon * 4)
        print("  file_reaccessed kB:", self.num_reaccessed_pages.file * 4)
        print(" R:", self.num_read_accessed_pages * 4, "kB W:", self.num_write_accessed_pages * 4, "kB")
        if print_vma:
            for vma in self.vma_list:
                vma.print()

def parse_map_file(map_file):
    f = open(map_file, 'r')
    datalist = f.readlines()
    f.close()
    next_is_tgid = False
    for data in datalist:
        if data == "------\n":
            next_is_tgid = True
            continue
        if next_is_tgid == True:
            items = data.split()
            tgid = int(items[0])
            rss = int(items[2])
            pss = int(items[5])
            pss_anon = int(items[8])
            pss_file = int(items[11])
            p = Process(tgid, rss, pss, pss_anon, pss_file)
            process_tgid_dict[tgid] = p
            tgid_pid_dict[tgid] = tgid
            next_is_tgid = False
            continue
        items = data.split()
        range = items[0].split('-')
        start = int('0x' + range[0], 16)
        end = int('0x' + range[1], 16)
        perm = items[1]
        if len(items) == 6:
            file = items[5]
            if file != "[heap]" and file != "[stack]":
                if p.mapped_file_start.get(file) == None:
                    p.mapped_file_start[file] = start
                vma = Vma(file, perm, start, end, p.mapped_file_start[file])
            else:
                vma = Vma(file, perm, start, end, 0)
        else:
            file = "anon"
            vma = Vma(file, perm, start, end, 0)
        p.addVma(vma)

def __get_process_name(items):
    process = os.path.basename(items[5])
    node = ""
    ns = ""
    for item in items:
        if re.search("__node:=", item):
            node = item[8:]
        elif re.search("__ns:=", item):
            ns = item[6:]
    return process, node, ns

def parse_ps_file(ps_file, pstree_file):
    f = open(pstree_file, 'r')
    datalist = f.readlines()
    f.close()
    pid_list = []
    for data in datalist:
        pid_strings = re.findall(r"\((\d+)\)", data)
        for pid_str in pid_strings:
            pid_list.append(int(pid_str))
    f = open(ps_file, 'r')
    datalist = f.readlines()
    f.close()
    for data in datalist:
        items = data.split()
        if items[0] == 'PID':
            continue
        tgid = int(items[0])
        if tgid in pid_list:
            if process_tgid_dict.get(tgid) == None:
                continue
            p = process_tgid_dict[tgid]
            pid = int(items[1])
            p.addPid(pid)
            if tgid == pid:
                name, node, ns = __get_process_name(items)
                p.setName(name, node, ns)
            tgid_pid_dict[pid] = tgid

def parse_page_fault_file_bin(page_fault_file, marker_index):
    marker_cnt = 0
    with open(page_fault_file, 'rb') as f:
        while True:
            pagedata = f.read(4096)
            if len(pagedata) == 0:
                break
            for i in range(int(4096/32)):
                data = pagedata[i*32:(i+1)*32]
                pid = int.from_bytes(data[0:4], byteorder = "little")
                flag = int.from_bytes(data[8:12], byteorder = "little")
                addr = int.from_bytes(data[16:24], byteorder = "little")
                addr2 = int.from_bytes(data[24:32], byteorder = "little")
                if flag & END:
                    print("END found")
                    #show('END')
                    return
                elif flag & MARKER:
                    marker_cnt += 1
                    print("MARKER found, cnt =", marker_cnt)
                    if marker_cnt == marker_index:
                        show(marker_cnt)
                        return
                    elif marker_index == 0:
                        show(marker_cnt)
                        continue
                if tgid_pid_dict.get(pid) == None:
                    continue
                tgid = tgid_pid_dict[pid]
                p = process_tgid_dict[tgid]
                if flag & EXEC_FLAG:
                    continue
                elif flag & ZAP_FLAG:
                    p.handle_munmap(addr, addr2)
                elif flag & UNMAP_FLAG:
                    p.handle_page_reclaim(addr)
                else:
                    p.handle_page_fault(addr, flag)

def parse_page_fault_file_txt(page_fault_file):
    marker_cnt = 0
    with open(page_fault_file, 'r') as f:
        datalist = f.readlines()
        for data in datalist:
            items = data.split()
            if len(items) < 3:
                continue
            pid = int(items[0])
            if tgid_pid_dict.get(pid) == None:
                continue
            tgid = tgid_pid_dict[pid]
            addr = int(items[1], 16)
            addr2 = int(items[2], 16)
            flag = int(items[3], 16)
            if flag & END:
                print("END found")
                return
            if tgid_pid_dict.get(pid) == None:
                continue
            tgid = tgid_pid_dict[pid]
            p = process_tgid_dict[tgid]
            if flag & EXEC_FLAG:
                continue
            elif flag & ZAP_FLAG:
                p.handle_munmap(addr, addr2)
            elif flag & UNMAP_FLAG:
                p.handle_page_reclaim(addr)
            else:
                p.handle_page_fault(addr, flag)

def show(marker_idx):
    global mapped_file_dict

    print("-----", marker_idx, "-----")

    for p in process_tgid_dict.values():
        p.post_process()

    total_pages = NumAnonFilePages(0, 0)
    total_pages_plus_reclamations = NumAnonFilePages(0, 0)
    total_reclaimed_pages = NumAnonFilePages(0, 0)
    total_reaccessed_pages = NumAnonFilePages(0, 0)

    print("PER PROCESS REPORT")
    for i, p in enumerate(process_tgid_dict.values()):
        print("PROCESS", i)
        p.print()
        print("")
        p.max_pages = p.total_pages

        total_pages.anon += p.num_pages.anon
        total_pages_plus_reclamations.anon += p.num_pages_plus_reclamations.anon
        total_reclaimed_pages.add(p.num_reclaimed_pages.anon, p.num_reclaimed_pages.file)
        total_reaccessed_pages.add(p.num_reaccessed_pages.anon, p.num_reaccessed_pages.file)

    for mf in mapped_file_dict.values():
        total_pages.file += len(mf.offsets)

    for mf in mapped_file_dict.values():
        total_pages_plus_reclamations.file += len(mf.offsets_no_reclamation)

    print("AUTOWARE WIDE REPORT")
    print("total_anon =", total_pages.anon * 4, "kB")
    print("total_file =", total_pages.file * 4 , "kB")
    print("total_anon_plus_reclamations =", total_pages_plus_reclamations.anon * 4, "kB")
    print("total_file_plus_reclamations =", total_pages_plus_reclamations.file * 4 , "kB")
    print("total_reclaimed =", (total_reclaimed_pages.anon + total_reclaimed_pages.file) * 4, "kB")
    print(" total_reclaimed_anon =", total_reclaimed_pages.anon * 4, "kB")
    print(" total_reclaimed_file =", total_reclaimed_pages.file * 4, "kB")
    print(" total_reaccessed_anon =", total_reaccessed_pages.anon * 4, "kB")
    print(" total_reaccessed_file =", total_reaccessed_pages.file * 4, "kB")
    print("")

if __name__ == "__main__":
    args = sys.argv
    page_fault_file = args[1]
    ps_file = args[2]
    pstree_file = args[3]
    map_file = args[4]
    if len(args) > 5:
        marker_index = int(args[5])
    else:
        marker_index = 0

    parse_map_file(map_file)
    parse_ps_file(ps_file, pstree_file)
    if os.path.splitext(page_fault_file)[1] == '.bin':
        parse_page_fault_file_bin(page_fault_file, marker_index)
    else:
        parse_page_fault_file_txt(page_fault_file)
