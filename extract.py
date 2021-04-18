import os
import re
import random
import pefile
import struct
from multiprocessing import Process

from win_structs import mpengine as mp
from win_structs import windows

SIGNATURE = b'\x20\x00\x00\x00\x00\x44\xC9\xB3\x25\xBC\xD3\x01\x00\x44\xC9\xB3\x25\xBC\xD3\x01\x00\x44\xC9\xB3\x25\xBC\xD3\x01\x00\x00\x00\x00'

class SignatureDatabase(object):
    def __init__(self, ptr_sz, fname) -> None:
        super().__init__()
        self.ptr_sz = ptr_sz
        with open(fname ,"rb") as fp:
            self._bin = fp.read()
    
    def checkNIS(self):
        nisdata_hdr = mp._CDATA_HEADER_NIS(self.ptr_sz).cast(self._bin)
        if nisdata_hdr.utf8marker[0] == 0xef \
            and nisdata_hdr.utf8marker[1] == 0xbb \
            and nisdata_hdr.utf8marker[2] == 0xbf:
            return True
        else:
            return False
        

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
    def __init__(self, drop_path, sd) -> None:
        super().__init__()
        DROP_PATH, DLL_DROP_PATH = drop_path
        self.DROP_PATH = DROP_PATH
        self.DLL_DROP_PATH = DLL_DROP_PATH
        self.ptr_sz = 4
        self.sd = sd
        self.db_sz = len(self.sd._bin)
        self.dll_name_list = []
        self.file_name_list = []

    def extract_files(self):
        _bin = self.sd._bin
        off = 0
        _bin = _bin[_bin.find(SIGNATURE):]
        while True:
            container_offset = _bin.find(SIGNATURE)
            if container_offset == -1:
                break
            hdr = mp._FILE_CONTAINER(self.ptr_sz).cast(_bin[container_offset:])
            file_name = read_wide_stirng(bytes(hdr.file_name))
            o_file_name = file_name
            file_content = hdr.get_file_contents(_bin, container_offset)
            _bin = _bin[container_offset + (hdr.sizeof() + len(file_content)):]
            file_name = file_name.replace(":", ";").replace("\\","-")
            if file_name in self.file_name_list:
                file_name = file_name + "." + str(random.randint(0, 0xffff))
            with open(self.DROP_PATH + "/" + file_name, "wb") as f:
                f.write(file_content)
            self.file_name_list.append(file_name)

    def __check_valid_pe(self, _bin):
        dos_hdr = windows._IMAGE_DOS_HEADER(self.ptr_sz).cast(_bin)
        if dos_hdr.e_lfanew < self.db_sz:
            nt_hdr = windows._IMAGE_NT_HEADER(self.ptr_sz).cast(_bin[dos_hdr.e_lfanew:])
            if dos_hdr.e_magic == 0x5a4d and \
                nt_hdr.signature == 0x4550 and \
                nt_hdr.opt_hdr.magic in (0x10b, 0x20b):
                return True
        return False

    def __get_dll_name(self, raw_dll):
        _pe = pefile.PE(data=raw_dll) # maybe this is the main factor 
                                      # of making slow the program
                                      # if you want to make faster this program.
                                      # add structures which 
                                      # related with export table
        return _pe.DIRECTORY_ENTRY_EXPORT.name.decode("ASCII")

    def extract_dlls(self):
        regex = b"(y|\|)...MZ"
        _bin = self.sd._bin
        for m in re.compile(regex).finditer(_bin):
            match_offset = m.start()
            MZ_start = match_offset + 4
            if self.__check_valid_pe(_bin[MZ_start:]):
                size_of_dll = struct.unpack("<I", _bin[match_offset+1 : MZ_start] + b"\x00")[0]
                raw_dll = _bin[MZ_start : MZ_start + size_of_dll]
                dll_name = self.__get_dll_name(raw_dll)
                if dll_name in self.dll_name_list:
                    dll_name = dll_name + "." + str(random.randint(0, 0xffff))
                with open(self.DLL_DROP_PATH + "/" + dll_name, "wb") as f:
                    f.write(raw_dll)
                del raw_dll
                self.dll_name_list.append(dll_name)

        pass


if __name__ == "__main__":
    DROP_PATH = "./files"
    DLL_DROP_PATH = "./dlls"
    target_file = "mpasbase.vdm.unpacked"
    ptr_sz = 4

    if not os.path.exists(DROP_PATH):
        os.makedirs(DROP_PATH)
    
    if not os.path.exists(DLL_DROP_PATH):
        os.makedirs(DLL_DROP_PATH)
    
    sd = SignatureDatabase(ptr_sz, target_file)
    vdm_ext = VdmExtractor((DROP_PATH, DLL_DROP_PATH), sd)
    _bin = sd._bin
    db_sz = len(_bin)
    idx = 0

    dll_extractor = Process(target=vdm_ext.extract_dlls)
    file_extractor = Process(target=vdm_ext.extract_files)

    dll_extractor.start()
    file_extractor.start()

    file_extractor.join()
    dll_extractor.join()

    print("VDM Extract Finished")
    

