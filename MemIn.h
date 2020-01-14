#pragma once

#ifndef MEMIN_H
#define MEMIN_H

#define ENABLE_PATTERN_SCAN_MULTITHREADING 1
#define USE_CODE_CAVE_AS_MEMORY 1

#include <Windows.h>
#include <memory>
#include <vector>
#include <map>
#include <unordered_map>
#include <atomic>
#include <TlHelp32.h>

class MemIn
{
	class ProtectRegion
	{
		uintptr_t m_Address;
		const size_t m_Size;
		DWORD m_Protection;
		BOOL m_Success;
	public:
		ProtectRegion(const uintptr_t address, const SIZE_T size, const bool m_Protect = true);
		~ProtectRegion();

		inline bool Success() { return m_Success; }
	};

	struct NopStruct
	{
		std::unique_ptr<uint8_t[]> buffer;
		SIZE_T size = 0;
	};

	struct HookStruct
	{
		uintptr_t trampoline = 0;
		uint8_t trampolineSize = 0;
	};

	//Store addresses/bytes which the user nopped so they can be restored later with Patch()
	static std::unordered_map<uintptr_t, NopStruct> m_Nops;

	static std::unordered_map<uintptr_t, HookStruct> m_Hooks;

public:
	template <typename T>
	static inline T Read(const uintptr_t address, bool protect) { if (!ProtectRegion(address, sizeof(T), protect).Success()) { return T(); }; return *reinterpret_cast<T*>(address); }
	static bool Read(const uintptr_t address, void* const buffer, const SIZE_T size, const bool protect = false);

	template <typename T>
	static inline bool Write(const uintptr_t address, const T& value) { return Write(address, &value, sizeof(T)); }
	static bool Write(const uintptr_t address, const void* const buffer, const SIZE_T size, const bool protect = false);

	static bool Patch(const uintptr_t address, const char* bytes, const size_t size);

	static bool Nop(const uintptr_t address, const size_t size, const bool saveBytes = true);
	static bool Restore(const uintptr_t address);

	static bool Copy(const uintptr_t destinationAddress, const uintptr_t sourceAddress, const size_t size);

	static bool Set(const uintptr_t address, const int value, const size_t size);

	static bool Compare(const uintptr_t address1, const uintptr_t address2, const size_t size);

	//outHash: A buffer capable of holding a MD5 hash which is 16 bytes.
	static bool HashMD5(const uintptr_t address, const size_t size, uint8_t* const outHash);

	static uintptr_t PatternScan(const char* const pattern, const char* const mask, uintptr_t start = 0, const uintptr_t end = -1);
	static uintptr_t AOBScan(const char* const AOB, uintptr_t start = 0, const uintptr_t end = -1);

	static uintptr_t PatternScanModule(const char* const pattern, const char* const mask, const TCHAR* const moduleName = nullptr);
	static uintptr_t AOBScanModule(const char* const AOB, const TCHAR* const moduleName = nullptr);

	static uintptr_t PatternScanAllModules(const char* const pattern, const char* const mask);
	static uintptr_t AOBScanAllModules(const char* const AOB);

	static uintptr_t ReadMultiLevelPointer(const uintptr_t base, const std::vector<uint32_t>& offsets);

	static bool Hook(const uintptr_t address, const void* const callback, uintptr_t* const trampoline = nullptr);

	static bool Unhook(const uintptr_t address);

	static uintptr_t FindCodeCave(const size_t size, uintptr_t start = 0, const uintptr_t end = -1, const uint8_t nullByte = static_cast<uint8_t>(0x00));

	static DWORD GetProcessIdByName(const TCHAR* const processName);
	static DWORD GetProcessIdByWindow(const TCHAR* const windowName, const TCHAR* const className = nullptr);

	//If moduleName is NULL, GetModuleBase() returns the base of the module created by the file used to create the process specified (.exe file)
	static uintptr_t GetModuleBase(const TCHAR* const moduleName = nullptr, DWORD* const pModuleSize = nullptr);
	static uintptr_t GetModuleBase(const DWORD dwProcessId, const TCHAR* const moduleName = nullptr, DWORD* const pModuleSize = nullptr);

	//address on the virtual address space of the current process.
	static size_t GetInstructionLength(const void* const address);

	static void EnumModules(const DWORD processId, bool (*callback)(const MODULEENTRY32& me, void* param), void* param);

	static void AOBToPattern(const char* const AOB, std::string& pattern, std::string& mask);
private:
	static void PatternScanImpl(std::atomic<uintptr_t>& returnValue, std::atomic<size_t>& finishCount, const uint8_t* const pattern, const char* const mask, uintptr_t start = 0, const uintptr_t end = -1);
};

#endif // MEMIN_H