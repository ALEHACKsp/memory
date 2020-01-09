# Mem
A memory library for Windows in C++.

# Features
**[EX]** = Function is only available on the external version
 - x86-32 & x86-64 support
 - Unicode & Multibyte support
 - MD5Hash()
 - Hook, Unhook()
 - Call() **[EX]**
 - GetInstructionLength()
 - FindCodeCave()
 - PatternScan(), AOBScan()
 - PatternScanModule(), AOBScanModule()
 - PatternScanAllModules(), AOBScanAllModules()
 - AOBToPattern()
 - ReadMultiLevelPointer()
 - Read(), Write(), Patch()
 - Nop(), Restore()
 - Copy(), Set(), Compare()
 - GetProcessIdByName(), GetProcessIdByWindow()
 - GetModuleBase()
 - EnumModules()
 - Attach(), AttachByWindow() **[EX]**
 - WaitAttach(), WaitAttachByWindow() **[EX]**
 - Detach(), IsAttached() **[EX]**
 - GetProcess(), GetPid() **[EX]**
 - AllocateSharedMemory(), CreateSharedMemory() **[EX]**
 - MapLocalViewOfFile(), UnmapLocalViewOfFile() **[EX]**
 - MapRemoteViewOfFile(), UnmapRemoteViewOfFile **[EX]**

# Example
```C++
#include "MemEx.h"

int main()
{
  MemEx m;
  m.WaitAttach("target.exe");
  
  uintptr_t address = m.AOBScanModule("some_module.dll", "64 A1 ?? ?? ?? ?? BA 08 28 7A 77 8B 48 ??");
  m.Patch(address, "\x8B\x15", 2);
  
  return 0;
}
```
