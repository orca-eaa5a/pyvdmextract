from win_structs.winstruct import WinStruct, Ptr, WinUnion
import ctypes

class _RMDX_HEADER(WinStruct):
    '''
        typedef struct _RMDX_HEADER {
            ULONG Signature;        //0
            ULONG Timestamp;        //4
            ULONG Unknown1;         //8
            ULONG Options;          //12 (0C)
            ULONG Unknown2;         //16
            ULONG Unknown3;         //20
            ULONG DataOffset;       //24 (18)
            ULONG DataSize;         //28 (1C)
            //incomplete, irrelevant
        } RMDX_HEADER, *PRMDX_HEADER;
    '''
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.signature = ctypes.c_uint32
        self.timestamp = ctypes.c_uint32
        self.unk1 = ctypes.c_uint32
        self.opt = ctypes.c_uint32
        self.unk2 = ctypes.c_uint32
        self.unk3 = ctypes.c_uint32
        self.dataoffset = ctypes.c_uint32
        self.datasize = ctypes.c_uint32

class _DATA_U1(WinUnion):
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.data = Ptr
        self.unk = ctypes.c_uint32

class _CDATA_HEADER(WinStruct):
    '''
        typedef struct _CDATA_HEADER {
            ULONG Length;             //0
            ULONG Unknown1;           //4
            union {                   //8
                BYTE Data[1];
                ULONG Unknown2;
            } u1;
        } CDATA_HEADER, *PCDATA_HEADER;
    '''
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.length = ctypes.c_uint32
        self.unk = ctypes.c_uint32
        self.u1 = _DATA_U1(ptr_sz).get_cstruct()

class _CDATA_HEADER_NIS(WinStruct):
    '''
        typedef _CDATA_HEADER_NISstruct _CDATA_HEADER_NIS {
            ULONG Unknown0;             //0
            ULONG Unknown1;             //4
            BYTE Utf8Marker[3];         //8
            BYTE Data[1];
        } CDATA_HEADER_NIS, *PCDATA_HEADER_NIS;
    '''
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.unk1 = ctypes.c_uint32
        self.unk2 = ctypes.c_uint32
        self.utf8marker = ctypes.c_byte*3
        self.data = Ptr

class _FILE_CONTAINER_HDR(WinStruct):
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.sig = ctypes.c_uint32*8
        self.size_of_file = ctypes.c_uint32
        self.padd1 = ctypes.c_uint32
        self.padd2 = ctypes.c_uint32
        self.file_name = ctypes.c_byte*548
    
    def get_file_contents(self, buf):
        file_contents = buf[:self.size_of_file]

        return file_contents

class _DLL_CONTAINER_HDR(WinStruct):
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.signature = ctypes.c_byte*4
        self.size_of_file = ctypes.c_uint32
        self.dll_name = ctypes.c_byte*80
    
    def get_dll_contents(self, buf):
        file_contents = buf[:self.size_of_file]

        return file_contents