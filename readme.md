# SavePatch
## A Ghidra script to save small patches back to the executable file
This ghidra script writes small modifications made in a executable back to the analysed file.
This allows you to edit a binary and save the modifications, without having to reload the file in raw mode.
The script was developed for ELF and PE files, but *might* work with other file types as well.

This is my personal attempt at a workaround for issues [#19](https://github.com/NationalSecurityAgency/ghidra/issues/19)/[#530](https://github.com/NationalSecurityAgency/ghidra/issues/530).

## Installation
Copy `SavePatch.py` to your Ghidra scripts directory (the Script Manager has a button to show you all directories where Ghidra is looking for scripts).

If the script is not shown in the Script Manager, try the 'Refresh Script List` button.

## Usage
  * Make the change to the executable
  * (optional) Select the patched lines in the listing window (not just highlight; **select**)
  * Run the SavePatch script
  * If you did not select the patched area, you will be asked for its start address and lenght
  * Select a location for the changed file. If the file does not exist, the current executable is copied there and then modified. Otherwise, the existing file is patched.
  * Check the results!

Once you have saved the first patched location, you can select another location, re-run the script and chose the same target file.
The script will open the file again and apply the second patch.
These steps can be repeated multiple times.

## Project status
I have tested this script with PE32, PE64, ELF32 and ELF64 executables (all x86), but I would still consider it experimental.
Executable formats are complex, and I can not guarantee that the script will always work error free.
Have a look at the known problems (see below), and always check if the modified file works as expected.

## Bugs/Limitations
### File types
`SavePatch.py` has been tested with ELF and PE files. It *might* work with other file types, but this is not guaranteed.
### Relocations
The `SavePatch.py` script currently ignores [relocations](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only).
Existing relocation entries are not modified, and no new relocation entries are added.

This means that if a instruction that gets relocated is written back using this script, strange things might happen.
Similar problems appear if you insert an instruction that needs to be relocated.

For the most part this is a problem with access to global/static variables in x86_32 binaries.

At the moment, the only workaround here is to avoid touching any instructions that are relocated.
