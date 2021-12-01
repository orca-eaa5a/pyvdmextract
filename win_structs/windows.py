from win_structs.winstruct import WinStruct, Ptr, WinUnion
import ctypes

class _IMAGE_DOS_HEADER(WinStruct):
    '''
    typedef struct _IMAGE_DOS_HEADER // DOS .EXE header
    {
        WORD e_magic;       // Magic number
        WORD e_cblp;        // Byte on last page of file
        WORD e_cp;          // Pages in file
        WORD e_crlc;        // Relocations
        WORD e_cparhdr;     // Size of header in paragraphs
        WORD e_minalloc;    // Minimum extra paragraphs needed
        WORD e_maxalloc;    // Maximum extra paragraphs needed
        WORD e_ss;          // Initial (relative) SS value
        WORD e_sp;          // Checksum
        WORD e_ip;          // Initital IP value
        WORD e_cs;          // Initial (relative) CS value
        WORD e_lfarlc;      // File address of relocation table
        WORD e_ovno;        // Overlay number
        WORD e_res[4];      // Reserved words
        WORD e_oemid;       // OEM identifier (for e_oeminfo)
        WORD e_oeminfo;     // OEM information; e_oemid specific
        WORD e_res2[10];    // Reserved words
        LONG e_lfanew;      // File address of new exe header
    } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
    '''
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.e_magic = ctypes.c_short
        self.not_used = ctypes.c_short*28
        self.e_lfanew = ctypes.c_uint32

class _IMAGE_DATA_DIRECTORY(WinStruct):
    '''
    typedef struct _IMAGE_DATA_DIRECTORY {
        DWORD VirtualAddress;
        DWORD Size;
    } IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
    '''
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.virtual_addr = ctypes.c_uint32
        self.size = ctypes.c_uint32

class _IMAGE_FILE_HEADER(WinStruct):
    '''
    typedef struct _IMAGE_FILE_HEADER {
        WORD  Machine;
        WORD  NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD  SizeOfOptionalHeader;
        WORD  Characteristics;
    } IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
    '''
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.machine = ctypes.c_ushort
        self.number_of_sections = ctypes.c_ushort
        self.timestamp = ctypes.c_uint32
        self.pointer_to_symtab = ctypes.c_uint32
        self.number_of_sym = ctypes.c_uint32
        self.size_of_opt_hdr = ctypes.c_ushort
        self.characteristics = ctypes.c_ushort

class _IMAGE_OPTIONAL_HEADER(WinStruct):
    '''
    typedef struct _IMAGE_OPTIONAL_HEADER {
        WORD                 Magic;
        BYTE                 MajorLinkerVersion;
        BYTE                 MinorLinkerVersion;
        DWORD                SizeOfCode;
        DWORD                SizeOfInitializedData;
        DWORD                SizeOfUninitializedData;
        DWORD                AddressOfEntryPoint;
        DWORD                BaseOfCode;
        DWORD                BaseOfData;
        DWORD                ImageBase;
        DWORD                SectionAlignment;
        DWORD                FileAlignment;
        WORD                 MajorOperatingSystemVersion;
        WORD                 MinorOperatingSystemVersion;
        WORD                 MajorImageVersion;
        WORD                 MinorImageVersion;
        WORD                 MajorSubsystemVersion;
        WORD                 MinorSubsystemVersion;
        DWORD                Win32VersionValue;
        DWORD                SizeOfImage;
        DWORD                SizeOfHeaders;
        DWORD                CheckSum;
        WORD                 Subsystem;
        WORD                 DllCharacteristics;
        DWORD                SizeOfStackReserve;
        DWORD                SizeOfStackCommit;
        DWORD                SizeOfHeapReserve;
        DWORD                SizeOfHeapCommit;
        DWORD                LoaderFlags;
        DWORD                NumberOfRvaAndSizes;
        IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
    } IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
    '''
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.magic = ctypes.c_ushort
        self.major_linker_v = ctypes.c_byte
        self.minor_linker_v = ctypes.c_byte
        self.size_of_code = ctypes.c_uint32
        self.size_of_init_data = ctypes.c_uint32
        self.size_of_uninit_data = ctypes.c_uint32
        self.address_of_entry_point = ctypes.c_uint32
        self.base_of_code = ctypes.c_uint32
        self.base_of_data = ctypes.c_uint32
        self.image_base = ctypes.c_uint32
        self.section_align = ctypes.c_uint32
        self.file_align = ctypes.c_uint32
        self.major_os_v = ctypes.c_ushort
        self.minor_os_v = ctypes.c_ushort
        self.major_img_v = ctypes.c_ushort
        self.minor_img_v = ctypes.c_ushort
        self.major_subsystem_v = ctypes.c_ushort
        self.minor_subsystem_v = ctypes.c_ushort        
        self.win32_version_value = ctypes.c_uint32
        self.size_of_image = ctypes.c_uint32
        self.size_of_header = ctypes.c_uint32
        self.chksum = ctypes.c_uint32
        self.subsystem = ctypes.c_ushort
        self.dll_characteristics = ctypes.c_ushort
        self.size_of_stack_reserv = ctypes.c_uint32
        self.size_of_heap_reserv = ctypes.c_uint32
        self.size_of_heap_commit = ctypes.c_uint32
        self.loadr_flag = ctypes.c_uint32
        self.number_of_rva_and_size = ctypes.c_uint32
        self.data_directory = _IMAGE_DATA_DIRECTORY(ptr_sz).get_cstruct()*1


class _IMAGE_NT_HEADER(WinStruct):
    '''
    typedef struct _IMAGE_NT_HEADERS
    {
        DWORD Signature;
        IMAGE_FILE_HEADER FileHeader;
        IMAGE_OPTIONAL_HEADER32 OptionalHeader;
    } IMAGE_NT_HEADER32, *PIMAGE_NT_HEADER32;
    '''
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.signature = ctypes.c_uint32
        self.file_hdr = _IMAGE_FILE_HEADER(ptr_sz).get_cstruct()
        self.opt_hdr = _IMAGE_OPTIONAL_HEADER(ptr_sz).get_cstruct()

class _IMAGE_SECTION_HEADER(WinStruct):
    def __init__(self, ptr_sz):
        super().__init__(ptr_sz)
        self.name = ctypes.c_char*8
        self.virtual_size = ctypes.c_int32
        self.virtual_address = ctypes.c_int32
        self.size_of_raw_data = ctypes.c_int32
        self.pointer_to_raw_data = ctypes.c_int32
        self.pointer_to_relocs = ctypes.c_int32
        self.pointer_to_line_numbers = ctypes.c_int32
        self.number_of_relocs = ctypes.c_int16
        self.number_of_line_nums =ctypes.c_int16
        self.characteriscs = ctypes.c_int32