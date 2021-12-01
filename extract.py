from ctypes import sizeof
import os
import re
import io
import random
import pefile
import struct
from multiprocessing import Process

import sys
import subprocess

from win_structs import mpengine as mp
from win_structs import windows


class SignatureDatabase(object):
    def __init__(self, ptr_sz, fname) -> None:
        super().__init__()
        self.ptr_sz = ptr_sz
        with open(fname ,"rb") as fp:
            self._bin = fp.read()
        
def read_wide_stirng(buf):
    idx = 0
    wstr = ""
    while True:
        wc = buf[idx:idx+2]
        if wc == b'\x00\x00':
            break
        wstr += wc.decode("utf-16le")
        idx+=2
    return wstr

class VdmExtractor(object):
    def __init__(self, sd) -> None:
        super().__init__()
        self.ptr_sz = 4
        self.sd = sd
        self.db_sz = len(self.sd._bin)

    def check_header_validation(self, buf):
        if len(buf) < mp._FILE_CONTAINER_HDR(self.ptr_sz).sizeof():
            return False
        hdr_cand = mp._FILE_CONTAINER_HDR(self.ptr_sz).cast(buf)
        padd = int.from_bytes(hdr_cand.unk3, "little")
        mtime = int.from_bytes(hdr_cand.mtime, "little")
        atime = int.from_bytes(hdr_cand.atime, "little")
        ctime = int.from_bytes(hdr_cand.ctime, "little")
        if (hdr_cand.unk1 >= 0x20 and hdr_cand.unk1 < 0x30)and \
            hdr_cand.unk2 == 0 and \
                padd == 0 and \
                    (mtime != 0 and atime != 0 and ctime != 0) and\
                        ((mtime == atime) or (mtime == ctime) or (atime == ctime)) :
            return True
        return False

    def file_write(self, path, fname, contents):
        p = os.path.join(path, fname)
        f = open(p, 'wb')
        f.write(contents)
        f.close()

    def extract_mock_files(self):
        global FILE_DROP_PATH
        off = 0
        fheader_sz = mp._FILE_CONTAINER_HDR(self.ptr_sz).sizeof()
        abs_offset = 0
        _bin = self.sd._bin
        hdr_regex = re.compile(b'[\x20-\x29]\x00\x00\x00.{24}\x00{4}.{4}\x00{8}')
        while True:
            #container_offset = _bin.find(b'\x20\x00\x00\x00[\x00-\xff]{24}\x00{4}[\x00-\xff]{4}\x00{8}')
            r = re.search(hdr_regex, _bin)
            if r:
                container_offset = r.start()
            else:
                break
            abs_offset += container_offset
            if container_offset == -1:
                break
            _bin = _bin[container_offset:]
            
            if self.check_header_validation(_bin):
                hdr_cand = mp._FILE_CONTAINER_HDR(self.ptr_sz).cast(_bin)
                bstream = io.BytesIO(_bin[fheader_sz:])
                contents_buf = bstream.read(hdr_cand.size_of_file)
                if self.check_header_validation(contents_buf):
                    _bin = _bin[fheader_sz:]
                    abs_offset += fheader_sz
                    header_chain = [hdr_cand]
                    while True:
                        # if header chain
                        if self.check_header_validation(_bin):
                            hdr_cand_tmp = mp._FILE_CONTAINER_HDR(self.ptr_sz).cast(_bin)
                            header_chain.append(hdr_cand_tmp)
                            _bin = _bin[fheader_sz:]
                            abs_offset += fheader_sz
                        else:
                            break
                    for header in header_chain:
                        bstream = io.BytesIO(_bin)
                        fname = read_wide_stirng(bytes(header.file_name)).replace("\\", "_").replace(":", ";")
                        self.file_write(FILE_DROP_PATH, fname, bstream.read(header.size_of_file))
                    _bin = _bin[header_chain[0].size_of_file:]
                else:
                    fname = read_wide_stirng(bytes(hdr_cand.file_name)).replace("\\", "_").replace(":", ";")
                    self.file_write(FILE_DROP_PATH, fname, contents_buf)
                    _bin = _bin[fheader_sz + hdr_cand.size_of_file:]
                    abs_offset += (fheader_sz + hdr_cand.size_of_file)
            else:
                _bin = _bin[1:]
                abs_offset += 1

    def extract_dlls(self):
        global DLL_DROP_PATH
        regex = b"MZ\x90\x00"
        _bin = self.sd._bin
        cnt = 0
        for m in re.compile(regex).finditer(_bin):
            match_offset = m.start()
            MZ_start = match_offset
            raw_sz = 0
            try:
                pe = pefile.PE(data=_bin[MZ_start:MZ_start+0x1000])
                # check pe validation
                if hex(pe.DOS_HEADER.e_magic) == "0x5a4d" and hex(pe.NT_HEADERS.Signature) == "0x4550":
                    if pe.OPTIONAL_HEADER.Magic in (0x10b, 0x20b):
                        if pe.FILE_HEADER.Characteristics & 0x2000:
                            cnt += 1
                            for section in pe.sections:
                                raw_sz += section.SizeOfRawData
                            raw_sz += pe.OPTIONAL_HEADER.SizeOfHeaders
                            pe_bin = _bin[MZ_start : MZ_start + raw_sz]
                            pe = pefile.PE(data=pe_bin)
                            try:
                                fname = pe.DIRECTORY_ENTRY_EXPORT.name.decode("ascii")
                                _path = os.path.join(DLL_DROP_PATH, fname)
                                if os.path.exists(_path):
                                    fname + "_" + str(cnt)
                                self.file_write(DLL_DROP_PATH, fname, pe_bin)
                            except AttributeError as e:
                                continue
                        else:
                            continue
                    else:
                        continue
            except Exception as e:
                continue
        pass

FILE_DROP_PATH = os.path.join(os.getcwd(), "files")
DLL_DROP_PATH = os.path.join(os.getcwd(), "dlls")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("input mpasbase.vdm")
        sys.exit()
    
    if sys.argv[1] in ("-h", "--help"):
        print("python extract.py [vdm_file] -option")
        print("options > ")
        print("-d : disable extract dlls")
        print("-f : disable extract files")
        exit(0)

    print("extraction started!")

    target_file = sys.argv[1]
    disable_dll_extraction = False
    disable_extract_files = False
    out_file = target_file + ".unp"
    ps_extractor = "vdm_decomp.ps1"
    ptr_sz = 4

    if "-d" in sys.argv:
        disable_dll_extraction = True
    if "-f" in sys.argv:
        disable_extract_files = True

    if not os.path.exists(FILE_DROP_PATH):
        os.makedirs(FILE_DROP_PATH)
    
    if not os.path.exists(DLL_DROP_PATH):
        os.makedirs(DLL_DROP_PATH)

    if not os.path.exists(os.path.join(os.getcwd(), out_file)):
        p = subprocess.Popen([
            "powershell.exe",
            "-file",
            os.path.join(os.getcwd(), ps_extractor), 
            "-vdm", 
            target_file, 
            "-out", 
            out_file], 
            stdout=sys.stdout,
            shell=True)
        p.communicate()
        if not os.path.exists(out_file):
            print("unpacking vdm failed..")
            exit(-1)
        else:
            print("vdm unpacking finished!")

    sd = SignatureDatabase(ptr_sz, out_file)
    vdm_ext = VdmExtractor(sd)

    if not disable_dll_extraction:
        dll_extractor = Process(target=vdm_ext.extract_dlls)
        dll_extractor.start()
        dll_extractor.join()
    
    if not disable_extract_files:
        file_extractor = Process(target=vdm_ext.extract_mock_files)
        file_extractor.start()
        file_extractor.join()
    
    print("VDM Extract Finished")
