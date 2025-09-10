'''
Usage:

python3 physmem_analysis_bin.py out.bin ps.txt pstree.txt maps.txt <marker_idx>

'''

import sys
import os
import re
import dataclasses

UNMAP_FLAG = int(1 << 31)
ZAP_FLAG   = int(1 << 30)
EXEC_FLAG  = int(1 << 29)
MARKER     = int(1 << 20)
END        = int(1 << 19)

print_vma_detail = 0
process_tgid_dict = {}  # key: tgid, val: Process
tgid_pid_dict = {}      # key: pid, val: tgid
mapped_file_dict = {}   # key: file name, val: MappedFile

class MappedFile:
    def __init__(self, name):
        self.name = name       # file name
        self.offset_list = []  # list of offset to which an access has occurred

class Access:
    def __init__(self, addr, write):
        self.addr = addr       # page aligned address
        self.write = write     # False when read, True when write

@dataclasses.dataclass
class NumPages:
    anon: int
    file: int

def is_file(name, perm, write):
    if (write == True and perm[3] == 's') or (write == False and name != "anon" and name != "[heap]" and name != "[stack]") or (perm[1] == '-' and name != "anon" and name != "[heap]" and name != "[stack]"):
        return True
    else:
        return False

class Vma:
    def __init__(self, file, perm, start, end, file_mapped_start_addr):
        self.file = file
        self.perm = perm
        self.start = start
        self.end = end
        self.file_mapped_start_addr = file_mapped_start_addr
        self.accesses_list = []
        self.reclaimed_list = []
        self.reclaimed_and_reaccessed_list = []
        self.num_write_accessed_pages = 0
        self.num_read_accessed_pages = 0
        self.num_pages = NumPages(0, 0)
        self.num_reclaimed_pages = NumPages(0, 0)
        self.num_reclaimed_and_reaccessed_pages = NumPages(0, 0)
    def reset(self):
        self.accesses_list = []
        self.reclaimed_list = []
        self.reclaimed_and_reaccessed_list = []
        self.num_write_accessed_pages = 0
        self.num_read_accessed_pages = 0
        self.num_pages = NumPages(0, 0)
        self.num_reclaimed_pages = NumPages(0, 0)
        self.num_reclaimed_and_reaccessed_pages = NumPages(0, 0)
    def hit(self, addr):
        if self.start <= addr and addr < self.end:
            return True
        else:
            return False
    def addAccess(self, access):
        global mapped_file_dict
        self.accesses_list.append(access)
        if access.write == True:
            self.num_write_accessed_pages = self.num_write_accessed_pages + 1
        else:
            self.num_read_accessed_pages = self.num_read_accessed_pages + 1
        if is_file(self.file, self.perm, access.write):
            if mapped_file_dict.get(self.file) == None:
                mapped_file = MappedFile(self.file)
                mapped_file_dict[self.file] = mapped_file
            else:
                mapped_file = mapped_file_dict[self.file]
            offset = access.addr - self.file_mapped_start_addr
            if not offset in mapped_file.offset_list:
                mapped_file.offset_list.append(offset)
            self.num_pages.file = self.num_pages.file + 1
        else:
            self.num_pages.anon = self.num_pages.anon + 1
    def addReclaimedAddr(self, addr, accesses_dict):
        self.reclaimed_list.append(addr)
        access = accesses_dict[addr]
        if is_file(self.file, self.perm, access.write):
            self.num_reclaimed_pages.file = self.num_reclaimed_pages.file + 1
        else:
            self.num_reclaimed_pages.anon = self.num_reclaimed_pages.anon + 1
    def addReclaimedAndReaccessedAddr(self, addr, accesses_dict):
        self.reclaimed_and_reaccessed_list.append(addr)
        access = accesses_dict[addr]
        if is_file(self.file, self.perm, access.write):
            self.num_reclaimed_and_reaccessed_pages.file = self.num_reclaimed_and_reaccessed_pages.file + 1
        else:
            self.num_reclaimed_and_reaccessed_pages.anon = self.num_reclaimed_and_reaccessed_pages.anon + 1
    def sortAccess(self):
        self.accesses_list.sort(key=lambda x: x.addr)
    def print(self):
        print(self.file, self.perm, hex(self.start), "-", hex(self.end))
        print("", len(self.accesses_list), "pages")
        print(" R:", self.num_read_accessed_pages, "W:", self.num_write_accessed_pages)
        if print_vma_detail:
            for access in self.accesses_list:
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
        self.num_pss_pages = NumPages(pss_anon, pss_file)
        self.pidlist = []
        self.vmalist = []
        self.mapped_file_dict = {}
        self.accesses = {}
        self.accesses_wo_reclaim = {}
        self.non_mapped_accesses_list = []
        self.reclaimed_addr_list = []
        self.reclaimed_and_reaccessed_addr_list = []
        self.num_write_accessed_pages = 0
        self.num_read_accessed_pages = 0
        self.num_pages = NumPages(0, 0)
        self.num_reclaimed_pages = NumPages(0, 0)
        self.num_reclaimed_and_reaccessed_pages = NumPages(0, 0)
    def reset(self):
        for vma in self.vmalist:
            vma.reset()
        self.num_write_accessed_pages = 0
        self.num_read_accessed_pages = 0
        self.num_pages = NumPages(0, 0)
        self.num_reclaimed_pages = NumPages(0, 0)
        self.num_reclaimed_and_reaccessed_pages = NumPages(0, 0)
    def setName(self, name, node, ns):
        self.name = name
        self.node = node
        self.ns = ns
    def addVma(self, vma):
        self.vmalist.append(vma)
    def addPid(self, pid):
        self.pidlist.append(pid)
    def handle_page_fault(self, addr, flag):
        addr = addr & ~(0x1000 - 1)
        if flag & 0x1 or flag & 0x2:
            write = True
        else:
            write = False
        if self.accesses_wo_reclaim.get(addr) == None:
            access = Access(addr, write)
            self.accesses_wo_reclaim[addr] = access
        else:
            access = self.accesses_wo_reclaim[addr]
            if write == True:
                access.write = True
        if self.accesses.get(addr) == None:
            self.accesses[addr] = access
        if addr in self.reclaimed_addr_list:
            self.reclaimed_and_reaccessed_addr_list.append(addr)
    def handle_munmap(self, start, end):
        accesses_copy = self.accesses.copy()
        for addr in accesses_copy.keys():
            if addr >= start and addr < end:
                del self.accesses[addr]
        accesses_wo_reclaim_copy = self.accesses_wo_reclaim.copy()
        for addr in accesses_wo_reclaim_copy.keys():
            if addr >= start and addr < end:
                del self.accesses_wo_reclaim[addr]
    def handle_page_reclaim(self, addr):
        if self.accesses.get(addr):
            del self.accesses[addr]
            self.reclaimed_addr_list.append(addr)
    def post_process(self):
        self.reset()
        for addr in self.accesses.keys():
            hit = False
            for vma in self.vmalist:
                if vma.hit(addr) == True:
                    access = self.accesses[addr]
                    vma.addAccess(access)
                    hit = True
                    break
            if hit == False:
                access = self.accesses[addr]
                self.non_mapped_accesses_list.append(access)
        for addr in self.reclaimed_addr_list:
            for vma in self.vmalist:
                if vma.hit(addr) == True:
                    vma.addReclaimedAddr(addr, self.accesses_wo_reclaim)
                    break
        for addr in self.reclaimed_and_reaccessed_addr_list:
            for vma in self.vmalist:
                if vma.hit(addr) == True:
                    vma.addReclaimedAndReaccessedAddr(addr, self.accesses_wo_reclaim)
                    break
        for vma in self.vmalist:
            vma.sortAccess()
            self.num_write_accessed_pages = self.num_write_accessed_pages + vma.num_write_accessed_pages
            self.num_read_accessed_pages = self.num_read_accessed_pages + vma.num_read_accessed_pages
            self.num_pages.anon = self.num_pages.anon + vma.num_pages.anon
            self.num_pages.file = self.num_pages.file + vma.num_pages.file
            self.num_reclaimed_pages.anon = self.num_reclaimed_pages.anon + vma.num_reclaimed_pages.anon
            self.num_reclaimed_pages.file = self.num_reclaimed_pages.file + vma.num_reclaimed_pages.file
            self.num_reclaimed_and_reaccessed_pages.anon = self.num_reclaimed_and_reaccessed_pages.anon + vma.num_reclaimed_and_reaccessed_pages.anon
            self.num_reclaimed_and_reaccessed_pages.file = self.num_reclaimed_and_reaccessed_pages.file + vma.num_reclaimed_and_reaccessed_pages.file

    def print(self):
        #print("tgid = ", self.tgid)
        print("process =", self.name, self.node, self.ns)
        print(" Rss:", self.rss)
        print(" Pss:", self.pss)
        print(" Pss_Anon:", self.num_pss_pages.anon)
        print(" Pss_File:", self.num_pss_pages.file)
        print(" reclaimed_kb:", len(self.reclaimed_addr_list) * 4)
        print("  anon_reclaimed kB:", self.num_reclaimed_pages.anon * 4)
        print("  file_reclaimed kB:", self.num_reclaimed_pages.file * 4)
        print("  anon_reclaimed_and_reaccessed kB:", self.num_reclaimed_and_reaccessed_pages.anon * 4)
        print("  file_reclaimed_and_reaccessed kB:", self.num_reclaimed_and_reaccessed_pages.file * 4)
        print(" R:", self.num_read_accessed_pages * 4, "kB W:", self.num_write_accessed_pages * 4, "kB")
        for vma in self.vmalist:
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
                if p.mapped_file_dict.get(file) == None:
                    p.mapped_file_dict[file] = start
                vma = Vma(file, perm, start, end, p.mapped_file_dict[file])
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
    pidlist = []
    for data in datalist:
        pid_strings = re.findall(r"\((\d+)\)", data)
        for pid_str in pid_strings:
            pidlist.append(int(pid_str))
    f = open(ps_file, 'r')
    datalist = f.readlines()
    f.close()
    for data in datalist:
        items = data.split()
        if items[0] == 'PID':
            continue
        tgid = int(items[0])
        if tgid in pidlist:
            if process_tgid_dict.get(tgid) == None:
                continue
            p = process_tgid_dict[tgid]
            pid = int(items[1])
            p.addPid(pid)
            if tgid == pid:
                name, node, ns = __get_process_name(items)
                p.setName(name, node, ns)
            tgid_pid_dict[pid] = tgid

def parse_page_fault_file_bin(page_fault_file, till_num_marks):
    marker_cnt = 0
    with open(page_fault_file, 'rb') as f:
        while True:
            pagedata = f.read(4096)
            if len(pagedata) == 0:
                break
            for i in range(int(4096/32)):
                data = pagedata[i*32:(i+1)*32]
                pid = int.from_bytes(data[0:8], byteorder = "little")
                flag = int.from_bytes(data[8:16], byteorder = "little")
                addr = int.from_bytes(data[16:24], byteorder = "little")
                addr2 = int.from_bytes(data[24:32], byteorder = "little")
                if flag & END:
                    print("END found")
                    show('END')
                    return
                elif flag & MARKER:
                    marker_cnt = marker_cnt + 1
                    print("MARKER found, cnt =", marker_cnt)
                    if marker_cnt == till_num_marks:
                        show(marker_cnt)
                        return
                    elif till_num_marks == 0:
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
    mapped_file_dict = {}

    print("-----", marker_idx, "-----")

    for p in process_tgid_dict.values():
        p.post_process()
    total_anon_pages = 0
    total_reclaimed_pages = NumPages(0, 0)
    total_reclaimed_and_reaccessed_pages = NumPages(0, 0)
    print("PER PROCESS REPORT")
    for i, p in enumerate(process_tgid_dict.values()):
        print("PROCESS", i)
        p.print()
        print("")
        total_anon_pages = total_anon_pages + p.num_pages.anon
        total_reclaimed_pages.anon = total_reclaimed_pages.anon + p.num_reclaimed_pages.anon
        total_reclaimed_pages.file = total_reclaimed_pages.file + p.num_reclaimed_pages.file
        total_reclaimed_and_reaccessed_pages.anon = total_reclaimed_and_reaccessed_pages.anon + p.num_reclaimed_and_reaccessed_pages.anon
        total_reclaimed_and_reaccessed_pages.file = total_reclaimed_and_reaccessed_pages.file + p.num_reclaimed_and_reaccessed_pages.file

    total_cached_pages = 0
    for mf in mapped_file_dict.values():
        total_cached_pages = total_cached_pages + len(mf.offset_list)

    print("AUTOWARE WIDE REPORT")
    print("total_anon =", total_anon_pages * 4, "kB")
    print("total_cached =", total_cached_pages * 4 , "kB")
    print("total_reclaimed =", (total_reclaimed_pages.anon + total_reclaimed_pages.file) * 4, "kB")
    print(" total_reclaimed_anon =", total_reclaimed_pages.anon * 4, "kB")
    print(" total_reclaimed_file =", total_reclaimed_pages.file * 4, "kB")
    print(" total_reclaimed_and_reaccessed_anon =", total_reclaimed_and_reaccessed_pages.anon * 4, "kB")
    print(" total_reclaimed_and_reaccessed_file =", total_reclaimed_and_reaccessed_pages.file * 4, "kB")
    print("")

if __name__ == "__main__":
    args = sys.argv
    page_fault_file = args[1]
    ps_file = args[2]
    pstree_file = args[3]
    map_file = args[4]
    if len(args) > 5:
        till_num_marks = int(args[5])
    else:
        till_num_marks = 0

    parse_map_file(map_file)
    parse_ps_file(ps_file, pstree_file)
    if os.path.splitext(page_fault_file)[1] == '.bin':
        parse_page_fault_file_bin(page_fault_file, till_num_marks)
    else:
        parse_page_fault_file_txt(page_fault_file)
