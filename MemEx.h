//Every parameter of 'uintptr_t' type refers to an address in the context of the virtual address space of the attached process.
//Every parameter of pointer type refer to an address/pointer/buffer in the context of the virtual address space of the current process.

#ifndef MEMEX_H
#define MEMEX_H

#include <Windows.h>
#include <vector>
#include <map>
#include <unordered_map>
#include <atomic>
#include <string>
#include <TlHelp32.h>
#include <memory>

#define ENABLE_PATTERN_SCAN_MULTITHREADING 1
#define USE_CODE_CAVE_AS_MEMORY 0

#define HOOK_MARK_END __asm _emit 0xD6 __asm _emit 0xD6 __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0xD6 __asm _emit 0xD6

#define CPTR(pointerToData, sizeOfData) ArgPtr(pointerToData, sizeOfData, true, false)
#define PTR(pointerToData, sizeOfData) ArgPtr(pointerToData, sizeOfData, false, false)

typedef struct ArgPtr
{
	const void* const data;
	const size_t size;
	const bool constant, immediate, isString;
	void* volatileBuffer;

#ifdef _WIN64
	bool isFloat = false;
#endif

	ArgPtr(const void* pointerToData, const size_t sizeOfData, const bool isDataConstant = true, const bool isDataImmediate = false, const bool isDataString = false)
		:data(pointerToData),
		size(sizeOfData),
		constant(isDataConstant),
		immediate(isDataImmediate),
		isString(isDataString),
		volatileBuffer(nullptr) {}
} Arg;

//List of suported calling conventions
enum class CConv
{
	DEFAULT,
	THIS_PTR_RET_SIZE_OVER_8,
#ifndef _WIN64
	_CDECL,
	//_CLRCALL, Only callable from managed code.
	_STDCALL,
	_FASTCALL,
	_THISCALL,
	//_VECTORCALL, [TODO]
#endif
};

//CPU STATES(for use in the saveCpuStateMask parameter on the Hook() function)
#define GPR 0x01
#define FLAGS 0x02
#define XMMX 0x04

class MemEx
{
	struct Nop
	{
		std::unique_ptr<uint8_t[]> buffer;
		size_t size = 0;
	};

	struct HookStruct
	{
		uintptr_t address = 0; //place where the hook is placed
		uint16_t callbackSize = 0;
		uint8_t trampolineSize = 0;
		uint8_t saveCpuStateBufferSize = 0;
	};

	HANDLE m_hProcess; // A handle to the target process.
	DWORD m_dwProcessId; // The process id of the target process.

	HANDLE m_hFileMapping; // A handle to the file mapping object.
	HANDLE m_hFileMappingDuplicate; // A handle to the file mapping object valid on the target process. In case the system doesn't support MapViewOfFile2.
	uint8_t* m_thisMappedView; // Starting address of the mapped view on this process.
	uint8_t* m_targetMappedView; // Starting address of the mapped view on the target process.

	size_t m_numPages;

	//Event objects to perform synchronization with our thread on the target process.
	HANDLE m_hEvent1, m_hEventDuplicate1;
	HANDLE m_hEvent2, m_hEventDuplicate2;

	HANDLE m_hThread; // A handle to our thread on the target process.
		
	//Store addresses/bytes which the user nopped so they can be restored later with Patch()
	std::unordered_map<uintptr_t, Nop> m_Nops;

	//Key(uintptr_t) stores the address of the hooked function
	std::map<uintptr_t, HookStruct> m_Hooks;

public:
	const static DWORD dwPageSize;

	MemEx();
	~MemEx();

	//Returns true if attached, false otherwise.
	bool IsAttached();

	//Attaches to a process using a handle.
	//Parameters:
	//  hProcess [in] A handle to the process. The handle must have the following permissions:
	//                PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION. If Hook() or
	//                Call() is used, the handle must also have the following permissions:
	//                PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION.
	bool Attach(const HANDLE hProcess);

	//Attaches to a process using a PID.
	//Parameters:
	//  dwProcessId [in] The process's id.
	bool Attach(const DWORD dwProcessId);

	//Attaches to a process using its name.
	//Parameters:
	//  processName [in] The process's name.
	bool Attach(const TCHAR* const processName);

	//Attaches to a process using a window and class name.
	//Parameters:
	//  windowName [in] The window's title. If NULL, all window 
	//                  names match.
	//  className  [in] The class name. If NULL, any window title
	//                  matching windowName is considered.
	bool AttachByWindow(const TCHAR* const windowName, const TCHAR* const className = nullptr);
	
	//Attaches to a process using its name. The functions does not return until a process that matches processName is found.
	//Parameters:
	//  processName    [in] The process's name.
	//  dwMilliseconds [in] The number of milliseconds the
	//                      thread sleeps every iteration.
	void WaitAttach(const TCHAR* const processName, const DWORD dwMilliseconds = 500);

	//Attaches to a process using a window and class name. The functions does not return until a process that matches processName is found.
	//Parameters:
	//  windowName     [in] The window's title. If NULL, all window 
	//                      names match.
	//  className      [in] The class name. If NULL, any window title
	//                      matching windowName is considered.
	//  dwMilliseconds [in] The number of milliseconds the thread 
	//                      sleeps every iteration.
	void WaitAttachByWindow(const TCHAR* const windowName, const TCHAR* const className = nullptr, const DWORD dwMilliseconds = 500);

	//Terminates any remote threads and memory allocations created by this library on the process. 
	void Detach();

	//Retuns a handle to the attached process.
	HANDLE GetProcess() const;

	//Returns the PID of the attached process.
	DWORD GetPid() const;

	//Returns a copy of the data at 'address'.
	//Parameters:
	//  address [in]  The address where the bytes will be read from.
	template <typename T>
	inline T Read(const uintptr_t address) const
	{
		T t;
		if (!Read(address, &t, sizeof(T)))
			memset(&t, 0x00, sizeof(T));
		return t;
	}

	//Copies 'size' bytes from 'address' to 'buffer'.
	//Parameters:
	//  address [in]  The address where the bytes will be copied from.
	//  buffer  [out] The buffer where the bytes will be copied to.
	//  size    [in]  The number of bytes to be copied.
	bool Read(const uintptr_t address, void* const buffer, const SIZE_T size) const;

	//Copies 'value' to 'address'.
	//Parameters:
	//  address [in] The address where the bytes will be copied to.
	//  value   [in] The value where the bytes will be copied from.
	template <typename T>
	inline bool Write(uintptr_t address, const T& value) const { return Write(address, &value, sizeof(T)); }

	//Copies 'size' bytes from 'buffer' to 'address'.
	//Parameters:
	//  address [in] The address where the bytes will be copied to.
	//  buffer  [in] The buffer where the bytes will be copied from.
	//  size    [in] The number of bytes to be copied.
	bool Write(uintptr_t address, const void* const buffer, const SIZE_T size) const;

	//Patches 'address' with 'size' bytes stored on 'bytes'.
	//Parameters:
	//  address [in] The address where the bytes will be copied to.
	//  buffer  [in] The buffer where the bytes will be copied from.
	//  size    [in] The number of bytes to be copied.
	bool Patch(const uintptr_t address, const char* const bytes, const size_t size) const;

	//Writes 'size' 0x90(opcode for the NOP(no operation) instruction) bytes at address.
	//Parameters:
	//  address   [in] The address where the bytes will be nopped.
	//  size      [in] The number of bytes to be written.
	//  saveBytes [in] If true, save the original bytes located at 'address'
	//                 where they can be later restored by calling Restore().
	bool Nop(const uintptr_t address, const size_t size, const bool saveBytes = true);

	//Restores the bytes that were nopped at 'address'.
	//Parameters:
	//  address   [in] The address where the bytes will be restored.
	bool Restore(const uintptr_t address);

	//Copies 'size' bytes from 'sourceAddress' to 'destinationAddress'.
	//Parameters:
	//  destinationAddress [in] The destination buffer's address.
	//  sourceAddress      [in] The souce buffer's address.
	//  size               [in] The number of bytes to be copied.
	bool Copy(const uintptr_t destinationAddress, const uintptr_t sourceAddress, const size_t size) const;

	//Sets 'size' 'value' bytes at 'address'.
	//Parameters:
	//  address [in] The address where the bytes will be written to.
	//  value   [in] The byte to be set.
	//  size    [in] The nmber of bytes to be set.
	bool Set(const uintptr_t address, const int value, const size_t size) const;

	//Compares the first 'size' bytes of 'address1' and 'address2'.
	//Parameters:
	//  address1 [in] the address where the first buffer is located.
	//  address2 [in] the address where the second buffer is located.
	//  size     [in] The number of bytes to be compared.
	bool Compare(const uintptr_t address1, const uintptr_t address2, const size_t size) const;

	//Calculates the MD5 hash of a memory region of the attached process.
	//Parameters:
	//  address [in]  The address where the hash will be calculated.
	//  size    [in]  The size of the region.
	//  outHash [out] A buffer capable of holding a MD5 hash which is 16 bytes.
	bool HashMD5(const uintptr_t address, const size_t size, uint8_t* const outHash) const;

	//Scans a range of memory for a pattern. By default 'start' and 'end' 
	//specify that the entire address space should be scanned.
	//Parameters:
	//  pattern [in] A buffer containing the pattern. An example of a
	//               pattern is "\x68\xAB\x00\x00\x00\x00\x4F\x90\x00\x08".
	//  mask    [in] A string that specifies how the pattern should be 
	//               interpreted. If mask[i] is equal to '?', then the
	//               byte pattern[i] is ignored. A example of a mask is
	//               "xx????xxxx".
	//  start   [in] The start address of the region to be scanned.
	//  end     [in] The end address of the region to be scanned.
	//  protect [in] Specifies a mask of memory protection constants
	//               which defines what memory regions will be scanned.
	//               The default value(-1) specifies that pages with any
	//               protection between 'start' and 'end' should be scanned.
	uintptr_t PatternScan(const char* const pattern, const char* const mask, uintptr_t start = 0, const uintptr_t end = -1, const DWORD protect = -1) const;
	
	//Scans a range of memory for an AOB. By default 'start' and 'end' 
	//specify that the entire address space should be scanned.
	//Parameters:
	//  AOB     [in] The array of bytes(AOB) in string form. To specify
	//               a byte that should be ignore use the '?' character.
	//               An example of AOB is "68 AB ?? ?? ?? ?? 4F 90 00 08".
	//  start   [in] The start address of the region to be scanned.
	//  end     [in] The end address of the region to be scanned.
	//  protect [in] Specifies a mask of memory protection constants
	//               which defines what memory regions will be scanned.
	//               The default value(-1) specifies that pages with any
	//               protection between 'start' and 'end' should be scanned.
	uintptr_t AOBScan(const char* const AOB, uintptr_t start = 0, const uintptr_t end = -1, const DWORD protect = -1) const;

	//Scans a module for a pattern. By default the ".exe" module is scanned.
	//Parameters:
	//  pattern    [in] A buffer containing the pattern. An example of a
	//                  pattern is "\x68\xAB\x00\x00\x00\x00\x4F\x90\x00\x08".
	//  mask       [in] A string that specifies how the pattern should be 
	//                  interpreted. If mask[i] is equal to '?', then the
	//                  byte pattern[i] is ignored. A example of a mask is
	//                  "xx????xxxx".
	//  moduleName [in] The name of the module to be scanned.
	//  protect    [in] Specifies a mask of memory protection constants
	//                  which defines what memory regions will be scanned.
	//                  The default value(-1) specifies that pages with any
	//                  protection between 'start' and 'end' should be scanned.
	uintptr_t PatternScanModule(const char* const pattern, const char* const mask, const TCHAR* const moduleName = nullptr, const DWORD protect = -1) const;
	
	//Scans a module for an AOB. By default the ".exe" module is scanned.
	//Parameters:
	//  AOB        [in] The array of bytes(AOB) in string form. To specify
	//                  a byte that should be ignore use the '?' character.
	//                  An example of AOB is "68 AB ?? ?? ?? ?? 4F 90 00 08".
	//  moduleName [in] The name of the module to be scanned.
	//  protect    [in] Specifies a mask of memory protection constants
	//                  which defines what memory regions will be scanned.
	//                  The default value(-1) specifies that pages with any
	//                  protection between 'start' and 'end' should be scanned.
	uintptr_t AOBScanModule(const char* const AOB, const TCHAR* const moduleName = nullptr, const DWORD protect = -1) const;

	//Scans all modules for a pattern.
	//Parameters:
	//  pattern [in] A buffer containing the pattern. An example of a
	//               pattern is "\x68\xAB\x00\x00\x00\x00\x4F\x90\x00\x08".
	//  mask    [in] A string that specifies how the pattern should be 
	//               interpreted. If mask[i] is equal to '?', then the
	//               byte pattern[i] is ignored. A example of a mask is
	//               "xx????xxxx".
	//  protect [in] Specifies a mask of memory protection constants
	//               which defines what memory regions will be scanned.
	//               The default value(-1) specifies that pages with any
	//               protection between 'start' and 'end' should be scanned.
	uintptr_t PatternScanAllModules(const char* const pattern, const char* const mask, const DWORD protect = -1) const;
	
	//Scans all modules for an AOB on the attached process.
	//Parameters:
	//  AOB     [in] The array of bytes(AOB) in string form. To specify
	//               a byte that should be ignore use the '?' character.
	//               An example of AOB is "68 AB ?? ?? ?? ?? 4F 90 00 08".
	//  protect [in] Specifies a mask of memory protection constants
	//               which defines what memory regions will be scanned.
	//               The default value(-1) specifies that pages with any
	//               protection between 'start' and 'end' should be scanned.
	uintptr_t AOBScanAllModules(const char* const AOB, const DWORD protect = -1) const;

	//Reads a multilevel pointer.
	//Parameters:
	//  base    [in] The base address.
	//  offsets [in] A vector specifying the offsets.
	uintptr_t ReadMultiLevelPointer(const uintptr_t base, const std::vector<uint32_t>& offsets) const;

	//Do not use 'void' as return type, use any other type instead.
	template<typename TyRet = int, CConv cConv = CConv::DEFAULT, typename ... Args>
	TyRet Call(const uintptr_t address, Args&& ... arguments)
	{
		if ((!m_hThread && !SetupRemoteThread()) || (cConv == CConv::THIS_PTR_RET_SIZE_OVER_8 && sizeof(TyRet) <= 8))
			return TyRet();

		//Parse arguments
		std::vector<Arg> args;
		GetArguments(args, arguments...);

		return *static_cast<TyRet*>(CallImpl(cConv, std::is_same<TyRet, float>::value, std::is_same<TyRet, double>::value, sizeof(TyRet), address, args));
	}
	
	bool Hook(const uintptr_t address, const void* const callback, uintptr_t* const trampoline = nullptr, const DWORD saveCpuStateMask = 0);

	//Array of bytes with known size at compile time
	template <class _Ty, size_t callbackSize>
	bool Hook(const uintptr_t address, _Ty(&callback)[callbackSize], uintptr_t* const trampoline = nullptr, const DWORD saveCpuStateMask = 0) { return Hook(address, callback, callbackSize, trampoline, saveCpuStateMask); };

	bool Hook(const uintptr_t address, const void* const callback, const size_t callbackSize, uintptr_t* const trampoline = nullptr, const DWORD saveCpuStateMask = 0);
	
	//Removes a previously placed hook at 'address'.
	//Parameters:
	//  address [in] The address to be unhooked.
	bool Unhook(const uintptr_t address);
	
	//Scans a range of memory to find a code cave.
	//Parameters:
	//  size       [in] The size of the code cave.
	//  nullByte   [in] The byte of the code cave.
	//  start      [in] The start address of the region to be scanned.
	//  end        [in] The end address of the region to be scanned.
	//  protection [in] Specifies a mask of memory protection constants
	//                  which defines what memory regions will be scanned.
	//                  The default value(-1) specifies that pages with any
	//                  protection between 'start' and 'end' should be scanned.
	uintptr_t FindCodeCave(const size_t size, const uint8_t nullByte = static_cast<uint8_t>(0x00), uintptr_t start = 0, const uintptr_t end = -1, const DWORD protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) const;

	//Scans a range of memory to find a code cave.
	//Parameters:
	//  size       [in] The size of the code cave.
	//  nullBytes  [in] The byte of the code cave.
	//  start      [in] The start address of the region to be scanned.
	//  end        [in] The end address of the region to be scanned.
	//  protection [in] Specifies a mask of memory protection constants
	//                  which defines what memory regions will be scanned.
	//                  The default value(-1) specifies that pages with any
	//                  protection between 'start' and 'end' should be scanned.
	uintptr_t FindCodeCaveBatch(const size_t size, const std::vector<uint8_t>& nullBytes = {}, uint8_t* const pNullByte = nullptr, uintptr_t start = 0, const uintptr_t end = -1, const DWORD protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) const;

	//Creates and returns a handle to an unnamed file-mapping object backed by the system's 
	//paging system. It basically represents a page which can be shared with other processes.
	//Additionaly, maps a view of the file locally and remotely(attached process).
	//Parameters:
	//  size       [in]  The size of the file-mapping object.
	//  localView  [out] A reference to a variable that will receive the locally mapped view.
	//  remoteView [out] A reference to a variable that will receive the remotely mapped view.
	HANDLE AllocateSharedMemory(const size_t size, PVOID& localView, PVOID& remoteView) const;

	//Unmaps the views previously mapped views and deletes the file-mapping object.
	//Parameters:
	//  hFileMapping [in] A handle to a file-mapping object.
	//  localView    [in] The local view.
	//  remoteView   [in] The remote view.
	bool FreeSharedMemory(HANDLE hFileMapping, LPCVOID localView, LPCVOID remoteView) const;

	//Maps a view of a file-mapping object on the address space of the current process.
	//Internally, it's a wrapper around MapViewOfFile().
	//Parameters:
	//  hFileMapping [in] A handle to a file-mapping object created by
	//                    AllocateSharedMemory() or CreateSharedMemory().
	static PVOID MapLocalViewOfFile(const HANDLE hFileMapping);

	//Unmaps a view of a file-mapping object on the address space of the current process.
	//Internally it's a wrapper around UnmapViewOfFile().
	//Parameters:
	//  localAddress [in] The address of the view on the address space of the current process.
	static bool UnmapLocalViewOfFile(LPCVOID localAddress);

	//Maps a view of a file-mapping object on the address space of the attached process.
	//Internally, it's a wrapper around MapViewOfFileNuma2() if available, otherwise
	//perform a workaround.
	//Parameters:
	//  hFileMapping [in] A handle to a file-mapping object created by
	//                    AllocateSharedMemory() or CreateSharedMemory().
	PVOID MapRemoteViewOfFile(const HANDLE hFileMapping) const;

	//Unmaps a view of a file-mapping object on the address space of the attached process.
	//Internally it's a wrapper around UnmapViewOfFile2() if available, otherwise
	//perform a workaround.
	//Parameters:
	//  localAddress [in] The address of the view on the address space of the attached process.
	bool UnmapRemoteViewOfFile(LPCVOID remoteAddress) const;

	//Returns the PID of the specified process.
	//Parameters:
	//  processName [in] The name of the process.
	static DWORD GetProcessIdByName(const TCHAR* const processName);

	//Returns the PID of the window's owner.
	//Parameters:
	//  windowName [in] The window's title. If NULL, all window 
	//                  names match.
	//  className  [in] The class name. If NULL, any window title
	//                  matching windowName is considered.
	static DWORD GetProcessIdByWindow(const TCHAR* const windowName, const TCHAR* const className = nullptr);

	//If moduleName is NULL, GetModuleBase() returns the base of the module created by the file used to create the process specified (.exe file)
	//Returns a module's base address on the attached process.
	//Parameters:
	//  moduleName  [in]  The name of the module.
	//  pModuleSize [out] An optional pointer that if provided, receives the size of the module.
	uintptr_t GetModuleBase(const TCHAR* const moduleName = nullptr, DWORD* const pModuleSize = nullptr) const;

	//Returns a module's base address on the process specified by dwProcessId.
	//Parameters:
	//  dwProcessId [in]  The PID of the process where the module base is retried.
	//  moduleName  [in]  The name of the module.
	//  pModuleSize [out] An optional pointer that if provided, receives the size of the module.
	static uintptr_t GetModuleBase(const DWORD dwProcessId, const TCHAR* const moduleName = nullptr, DWORD* const pModuleSize = nullptr);

	//Returns the size of first parsed instruction on the buffer at 'address'.
	//Parameters:
	//  address [in] The address of the buffer on the current process's address space containing instruction.
	static size_t GetInstructionLength(const void* const address);
	
	//Loops through all modules of a process passing its information to a callback function.
	//Parameters:
	//  processId [in] The PID of the process which the modules will be looped.
	//  callback  [in] A function pointer to a callback function.
	//  param     [in] An optional pointer to be passed to the callback.
	static void EnumModules(const DWORD processId, bool (*callback)(MODULEENTRY32& me, void* param), void* param);

	//Converts an AOB in string form into pattern & mask form.
	//Parameters:
	//  AOB     [in]  The array of bytes(AOB) in string form.
	//  pattern [out] The string that will receive the pattern.
	//  mask    [out] The string that will receive th mask.
	static void AOBToPattern(const char* const AOB, std::string& pattern, std::string& mask);

	//Returns the size of a page on the system.
	static DWORD GetPageSize();

	//Creates and returns a handle to an unnamed file-mapping object backed by the system's 
	//paging system. It basically represents a page which can be shared with other processes.
	//Parameters:
	//  size [in] The size of the file-mapping object.
	static HANDLE CreateSharedMemory(const size_t size);

private:
	void PatternScanImpl(std::atomic<uintptr_t>& address, std::atomic<size_t>& finishCount, const uint8_t* const pattern, const char* const mask, uintptr_t start = 0, const uintptr_t end = -1, const DWORD protect = -1) const;
	
	void* CallImpl(const CConv cConv, const bool isReturnFloat, const bool isReturnDouble, const size_t returnSize, const uintptr_t functionAddress, std::vector<Arg>& args);

	template<typename T> Arg GetArgument(T& t) { return Arg(&t, sizeof(t), true, true); }
	Arg GetArgument(const char t[]) { return Arg(t, strlen(t) + 1, true, false, true); }
	Arg GetArgument(const wchar_t t[]) { return Arg(t, (static_cast<size_t>(lstrlenW(t)) + 1) * 2, true, false, true); }
	Arg GetArgument(Arg& t) { return t; }

#ifdef _WIN64
	Arg GetArgument(float& t) { Arg arg(&t, sizeof(float), true, true); arg.isFloat = true; return arg; }
	Arg GetArgument(double& t) { Arg arg(&t, sizeof(double), true, true); arg.isFloat = true; return arg; }
#endif

	void GetArguments(std::vector<Arg>& args) {}

	template<typename T, typename ... Args>
	void GetArguments(std::vector<Arg>& args, T& first, Args&& ... arguments)
	{
		args.emplace_back(GetArgument(first));

		GetArguments(args, arguments...);
	}

	bool SetupRemoteThread();
	void DeleteRemoteThread();
};

#endif // MEMEX_H