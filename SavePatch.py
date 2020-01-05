# Write the selected memory (including patches) back to a copy of the binary file
#@author schlafwandler
#@category Memory
#@keybinding 
#@menupath 
#@toolbar 

import ghidra.app.util.bin.MemoryByteProvider as MemoryByteProvider
import generic.continues.RethrowContinuesFactory as RethrowContinuesFactory
import shutil
import jarray
import os

def imagebase_offset_to_file_offset_ELF(imagebase_offset):
    import ghidra.app.util.bin.format.elf as elf

    mem_provider = MemoryByteProvider(currentProgram.getMemory(), currentProgram.getImageBase())
    elffile = elf.ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE,mem_provider)

    try:
        elffile.parse()
    except:
        pass

    segment = elffile.getProgramLoadHeaderContaining(imagebase_offset)
    segment_offset = segment.getOffset()
    segment_RVA = segment.getVirtualAddress()
    file_offset = segment_offset + imagebase_offset - segment_RVA
    return file_offset

def imagebase_offset_to_file_offset_PE(imagebase_offset):
    import ghidra.app.util.bin.format.pe as pe
    mem_provider = MemoryByteProvider(currentProgram.getMemory(), currentProgram.getImageBase())
    pefile = pe.PortableExecutable.createPortableExecutable(
                            RethrowContinuesFactory.INSTANCE,
                            mem_provider,
                            pe.PortableExecutable.SectionLayout.MEMORY)
    
    section = pefile.getNTHeader().getFileHeader().getSectionHeaderContaining(imagebase_offset)
    section_offset = section.getPointerToRawData()
    section_RVA = section.getVirtualAddress()
    file_offset = section_offset + imagebase_offset - section_RVA
    return file_offset
    
def imagebase_offset_to_file_offset(imagebase_offset):
    monitor.setMessage("Calculating file offset")
    file_format = currentProgram.getExecutableFormat()
    if file_format == u'Executable and Linking Format (ELF)':
        return imagebase_offset_to_file_offset_ELF(imagebase_offset)
    elif file_format == u'Portable Executable (PE)':
        return imagebase_offset_to_file_offset_PE(imagebase_offset)
    else:
        print("Unsupported executable format: %s"%(file_format))
        return None

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

    file_offset = imagebase_offset_to_file_offset(imagebase_offset)
    if not file_offset:
        print("Failed to get file offset. Aborting.")
        return
    else:
        print("Memory offset 0x%08x corresponds to file offset 0x%08x"%(imagebase_offset,file_offset))

    monitor.setMessage("Waiting for user input")
    orig_path   = str(currentProgram.getExecutablePath())
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
