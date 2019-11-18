# SavePatch
## A Ghidra script to save small patches back to the executable file
This ghidra script writes small modifications made in a PE or ELF executable back to the analysed file.
This allows you to edit a binary and save the modifications, without having to reload the file in raw mode.

This is my personal attempt at a workaround for issues [#19](https://github.com/NationalSecurityAgency/ghidra/issues/19)/[#530](https://github.com/NationalSecurityAgency/ghidra/issues/530).

## Installation
Copy `SavePatch.py` to your Ghidra scripts directory (the Script Manager has a button to show you all directories where Ghidra is looking for scripts).

If the script is not shown in the Script Manager, try the 'Refresh Script List` button.

## Usage
  * Make the change to the executable
  * Select the patched lines in the listing window (not just highlight; **select**)
  * Run the SavePatch script
  * Select a location for the changed file. If the file does not exist, the current executable is copied there and then modified. Otherwise, the existing file is patched.
  * Check the results!

## Project status
I have tested this script with PE32, PE64, ELF32 and ELF64 executables (all x86), but I would still consider it experimental.
Executable formats are complex, and I can not guarantee that the script will always work error free.
Have a look at the known problems (see below), and always check if the modified file works as expected.

## Bugs/Limitations
### Relocations
The `SavePatch.py` script currently ignores [relocations](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#the-reloc-section-image-only).
This means that if a instruction that gets relocated is modified and written back, strange things might happen.
Similar problems appear if you insert an instruction that needs to be relocated.

For the most part this is a problem with access to global/static variables on 32 bit x86.

The only workaround is to avoid touching any instructions that are relocated.
