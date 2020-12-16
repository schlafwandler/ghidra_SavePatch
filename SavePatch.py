# Write the selected memory (including patches) back to a copy of the binary file
#@author schlafwandler
#@category Memory
#@keybinding 
#@menupath 
#@toolbar 

import shutil
import jarray
import os

def address_to_file_offset(address):
    tested_file_formats = [u'Executable and Linking Format (ELF)',u'Portable Executable (PE)']
    if currentProgram.getExecutableFormat() not in tested_file_formats:
        print('Warning: this script was not tested for executable format "%s"'%(currentProgram.getExecutableFormat()))

    mem = currentProgram.getMemory()
    sourceinfo = mem.getAddressSourceInfo(address)
    return sourceinfo.getFileOffset()

def getPatchRange():
    if currentSelection is not None:
        if len(list(currentSelection.getAddressRanges())) != 1:
            print("Only patches in one address range are supported. Aborting.")
            return

        addr_range  = currentSelection.getFirstRange()
        start_addr  = addr_range.getMinAddress()
        size        = addr_range.getLength()

        return start_addr,size
    else:
        monitor.setMessage("Waiting for user input")
        start_addr  = askAddress("Patch address","Start of patch:")
        size        = askInt("Patch size","Patch size (bytes):")
    return start_addr,size

def main():
    start_addr,size = getPatchRange()
    print("Patch starting at 0x%08x (%d bytes)"%(start_addr.getOffset(),size))

    imagebase_offset    =   start_addr.getOffset() - currentProgram.getImageBase().getOffset()

    file_offset = address_to_file_offset(start_addr)
    if not file_offset:
        print("Failed to get file offset. Aborting.")
        return
    else:
        print("Memory offset 0x%08x corresponds to file offset 0x%08x"%(imagebase_offset,file_offset))

    monitor.setMessage("Waiting for user input")
    orig_path   = str(currentProgram.getExecutablePath())
    
    # workaround for https://github.com/NationalSecurityAgency/ghidra/pull/2220
    if os.sep == "\\" and orig_path[0] == "/":
        orig_path = orig_path[1:]
    
    output_path = str(askFile("Select output file name","Save changes"))

    if not os.path.isfile(output_path):
        shutil.copy(orig_path,output_path)

    with open(output_path,"rb+") as f:
        monitor.setMessage("Patching copied file")
        print("Writing %d bytes to file offset 0x%08x"%(size,file_offset))

        # https://github.com/NationalSecurityAgency/ghidra/issues/858
        data_buffer = jarray.zeros(size,"b")
        currentProgram.getMemory().getBytes(start_addr,data_buffer)
        data_buffer = bytearray(data_buffer)

        f.seek(file_offset,0)
        f.write(data_buffer)

main()
