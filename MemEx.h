#pragma once

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

//Little trick. The x64 compile version of visual studio does not support inline assembly
#ifndef _WIN64
	#define HOOK_MARK_END __asm _emit 0xD6 __asm _emit 0xD6 __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0x0F __asm _emit 0xD6 __asm _emit 0xD6
#endif

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
		uintptr_t address; //place where the hook is placed
		uint16_t callbackSize;
		uint8_t trampolineSize;
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

	bool IsAttached();

	//Required permissions for hProcess:
	// - MUST HAVE: PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
	// - IF FUNCTION CALLING/HOOKING: PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION.
	bool Attach(const HANDLE hProcess);
	bool Attach(const DWORD dwProcessId);
	bool Attach(const TCHAR* const processName);
	bool AttachByWindow(const TCHAR* const windowName, const TCHAR* const className = nullptr);

	void WaitAttach(const TCHAR* const processName, const DWORD dwMilliseconds = 500);
	void WaitAttachByWindow(const TCHAR* const windowName, const TCHAR* const className = nullptr, const DWORD dwMilliseconds = 500);

	void Detach();

	HANDLE GetProcess() const;
	DWORD GetPid() const;

	template <typename T>
	inline T Read(const uintptr_t address, const bool protect = false) const
	{
		T t;
		if (!Read(address, &t, sizeof(T), protect))
			memset(&t, 0x00, sizeof(T));
		return t;
	}
	bool Read(const uintptr_t address, void* const buffer, const SIZE_T size, const bool protect = false) const;

	template <typename T>
	inline bool Write(uintptr_t address, const T& value, const bool protect = false) const { return Write(address, &value, sizeof(T), protect); }
	bool Write(uintptr_t address, const void* const buffer, const SIZE_T size, const bool protect = false) const;

	bool Patch(const uintptr_t address, const char* const bytes, const size_t size) const;

	bool Nop(const uintptr_t address, const size_t size, const bool saveBytes = true);
	bool Restore(const uintptr_t address);

	bool Copy(const uintptr_t destinationAddress, const uintptr_t sourceAddress, const size_t size) const;

	bool Set(const uintptr_t address, const int value, const size_t size) const;

	bool Compare(const uintptr_t address1, const uintptr_t address2, const size_t size) const;

	//outHash: A buffer capable of holding a MD5 hash which is 16 bytes.
	bool HashMD5(const uintptr_t address, const size_t size, uint8_t* const outHash) const;

	uintptr_t PatternScan(const char* const pattern, const char* const mask, uintptr_t start = 0, const uintptr_t end = -1) const;
	uintptr_t AOBScan(const char* const AOB, uintptr_t start = 0, const uintptr_t end = -1) const;

	uintptr_t PatternScanModule(const char* const pattern, const char* const mask, const TCHAR* const moduleName = nullptr) const;
	uintptr_t AOBScanModule(const char* const AOB, const TCHAR* const moduleName = nullptr) const;

	uintptr_t PatternScanAllModules(const char* const pattern, const char* const mask) const;
	uintptr_t AOBScanAllModules(const char* const AOB) const;

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
	
#ifndef _WIN64
	//Use the HOOK_MARK_END macro(if x86)
	bool Hook(const uintptr_t address, const void* const callback, uintptr_t* const trampoline = nullptr, const DWORD saveCpuStateMask = 0);
#endif

	//Array of bytes with known size at compile time
	template <class _Ty, size_t callbackSize>
	bool Hook(const uintptr_t address, _Ty(&callback)[callbackSize], uintptr_t* const trampoline = nullptr, const DWORD saveCpuStateMask = 0) { return Hook(address, callback, callbackSize, trampoline, saveCpuStateMask); };

	bool Hook(const uintptr_t address, const void* const callback, const size_t callbackSize, uintptr_t* const trampoline = nullptr, const DWORD saveCpuStateMask = 0);
		
	bool Unhook(const uintptr_t address);

	uintptr_t FindCodeCave(const size_t size, uintptr_t start = 0, const uintptr_t end = -1, const uint8_t nullByte = static_cast<uint8_t>(0x00)) const;

	HANDLE AllocateSharedMemory(const size_t size, PVOID& localView, PVOID& remoteView) const;

	bool FreeSharedMemory(HANDLE hFileMapping, LPCVOID localView, LPCVOID remoteView) const;

	//Wrapper around MapViewOfFile()
	static PVOID MapLocalViewOfFile(const HANDLE hFileMapping);

	//Wrapper around UnmapViewOfFile()
	static bool UnmapLocalViewOfFile(LPCVOID localAddress);

	//Use MapViewOfFileNuma2() if supported by the system(Win 10+), otherwise perform a workaround.
	PVOID MapRemoteViewOfFile(const HANDLE hFileMapping) const;

	//Use UnmapViewOfFile2() if supported by the system(Win 10+), otherwise perform a workaround.
	bool UnmapRemoteViewOfFile(LPCVOID remoteAddress) const;

	static DWORD GetProcessIdByName(const TCHAR* const processName);
	static DWORD GetProcessIdByWindow(const TCHAR* const windowName, const TCHAR* const className = nullptr);

	//If moduleName is NULL, GetModuleBase() returns the base of the module created by the file used to create the process specified (.exe file)
	uintptr_t GetModuleBase(const TCHAR* const moduleName = nullptr, DWORD* const pModuleSize = nullptr) const;
	static uintptr_t GetModuleBase(const DWORD dwProcessId, const TCHAR* const moduleName = nullptr, DWORD* const pModuleSize = nullptr);

	//address on the virtual address space of the current process.
	static size_t GetInstructionLength(const void* const address);
	
	static void EnumModules(const DWORD processId, bool (*callback)(const MODULEENTRY32& me, void* param), void* param);

	static void AOBToPattern(const char* const AOB, std::string& pattern, std::string& mask);

	static DWORD GetPageSize();

	static HANDLE CreateSharedMemory(const size_t size);

private:
	void PatternScanImpl(std::atomic<uintptr_t>& address, std::atomic<size_t>& finishCount, const uint8_t* const pattern, const char* const mask, uintptr_t start = 0, const uintptr_t end = -1) const;
	
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