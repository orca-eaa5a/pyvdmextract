# pyvdmextract

##### - Extract the emulated file which in the Windows Defender

- parse mpasbase.vdm and extract the emulated file and its contents

  which in the Windows Defender.

- before parse the .vdm files, we have to unpack it.

- you can do this by using "vdm_decomp.ps1".

  - since python does not support the zlib.inflate algorithm,

  ​       unpacking .vdm couldn't implement yet.

  - so you have to use other .vdm decompression tools.

    ( "vdm_decomp.ps1" is not my work)