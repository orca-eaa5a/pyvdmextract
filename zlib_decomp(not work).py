import deflate
import pefile
from win_structs import mpengine as mp

ZLIB_CHUNK = 0x4000

# becuase of zlib of python not
# support the 'inflate' alg
# this code is not avaliable

import zlib
import base64

class Resource(object):
    def __init__(self, img, pe_strt:pefile.PE):
        self.pe_strt = pe_strt
        self.img = img
        self.rsrc_list = []
        self.parse_rsrc()

    def parse_rsrc(self):
        def deep_parse_rsrc(rsrc, lst):
            rsrc_info = {}
            for etry in rsrc.directory.entries:
                if hasattr(etry, "id"):
                    rsrc_info["id"] = etry.struct.Id
                    rsrc_info["name"] = etry.struct.Name
                    rsrc_info["name_offset"] = etry.struct.NameOffset
                    rsrc_info["rsrc_offset"] = etry.struct.OffsetToData
                    if hasattr(etry, "data"):
                        rsrc_info["rsrc_size"] = etry.data.struct.Size
                        rsrc_info["data_offset"] = etry.data.struct.OffsetToData
                    lst.append(rsrc_info)
                if hasattr(etry, "directory"):
                    deep_parse_rsrc(etry, lst)
                return


        for rsrc in self.pe_strt.DIRECTORY_ENTRY_RESOURCE.entries:
            rsrc_info = {}
            if rsrc.name:
                rsrc_info["name"] = rsrc.name.string.decode("ascii")
            else:
                rsrc_info["name"] = rsrc.name
            rsrc_info["subresource"] = []
            deep_parse_rsrc(rsrc, rsrc_info["subresource"])
            self.rsrc_list.append(rsrc_info)


    def find_rsrc(self, name):
        for rsrc in self.rsrc_list:
            if rsrc["name"] == name:
                return rsrc["subresource"][1]
        return None
    
    def get_rsrc_size(self, rsrc):
        return rsrc["rsrc_size"]

    def get_rsrc_offset(self, rsrc):
        return rsrc["data_offset"]

    def get_resource_binary(self, name):
        rsrc = self.find_rsrc(name)
        rsrc_off = self.get_rsrc_offset(rsrc)
        rsrc_sz = self.get_rsrc_size(rsrc)

        return self.img[rsrc_off : rsrc_off + rsrc_sz]

r = open("mpasbase.vdm", "rb")
_bin = r.read()
r.close()

pe_strt = pefile.PE(data=_bin)
ptr_sz = 4 # AMD64
_bin = pe_strt.get_memory_mapped_image()
rsrc_container = Resource(_bin, pe_strt)
rsrc = rsrc_container.find_rsrc("RT_RCDATA")
rt_rcdat_sz = rsrc_container.get_rsrc_size(rsrc)

del rsrc

rt_rcdat = rsrc_container.get_resource_binary("RT_RCDATA")
rmdx_hdr = mp._RMDX_HEADER(ptr_sz).cast(rt_rcdat)
cdata_hdr = mp._CDATA_HEADER(ptr_sz).cast(rt_rcdat[rmdx_hdr.dataoffset : ])

if not ( rmdx_hdr.opt >> 1 ) & 0xff:
    raise Exception("Unkown VDM file")

cdata_content_offset = rmdx_hdr.dataoffset + 8
cdata_content = rt_rcdat[cdata_content_offset : cdata_content_offset + cdata_hdr.length]

chunk_sz = ZLIB_CHUNK # ZLIB_CHUNK

idx = 0
decomp = b''
while True:
    try:
        chunk = cdata_content[chunk_sz*idx:]
    except IndexError:
        break
    if len(chunk) > chunk_sz:
        chunk = chunk[:chunk_sz]
    decomp += deflate.gzip_decompress(chunk) # <-- zlib.inflate is needed
    #decomp += zlib.decompress(chunk)
    idx+=1

with open("test.decmp", "wb") as res:
    res.write(decomp)
