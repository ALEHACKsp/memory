//Every address parameter is in the context of the virtual address space of the current process unless explicity stated otherwise.
#pragma once

#ifndef MEMIN_H
#define MEMIN_H

#define SCAN_IN_MULTITHREADING 1

#include <Windows.h>
#include <memory>
#include <vector>
#include <map>
#include <unordered_map>
#include <atomic>
#include <TlHelp32.h>

//CPU STATES(for use in the saveCpuStateMask parameter on the Hook() function)
//Even though the upper portions of YMM0-15 and ZMM0-15 are volatile, there's no mechanism to save them. 
#define GPR 0x01
#define FLAGS 0x02
#define XMMX 0x04

enum class SCAN_BOUNDARIES
{
	RANGE,
	MODULE,
	ALL_MODULES
}; 

struct ScanBoundaries
{
	const SCAN_BOUNDARIES scanBoundaries;
	union
	{
		struct { uintptr_t start, end; };
		const TCHAR* const moduleName;
	};

	ScanBoundaries(const SCAN_BOUNDARIES scanBoundaries, const uintptr_t start, const uintptr_t end);
	ScanBoundaries(const SCAN_BOUNDARIES scanBoundaries, const TCHAR* const moduleName);
	ScanBoundaries(const SCAN_BOUNDARIES scanBoundaries);
};

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
		uintptr_t buffer = 0;
		uint8_t bufferSize = 0;
		uint8_t numReplacedBytes = 0;
		bool useCodeCaveAsMemory = true;
		uint8_t codeCaveNullByte = 0;
	};

	//Store addresses/bytes which the user nopped so they can be restored later with Patch()
	static std::unordered_map<uintptr_t, NopStruct> m_Nops;

	static std::unordered_map<uintptr_t, HookStruct> m_Hooks;

	static std::unordered_map<uintptr_t, size_t> m_Pages;
public:
	//Returns a copy of the data at 'address'.
	//Parameters:
	//  address [in] The address where the bytes will be read from.
	template <typename T>
	static inline T Read(const uintptr_t address)
	{
		T t;
		Read(address, &t, sizeof(T));
		return t;
	}

	//Copies 'size' bytes from 'address' to 'buffer'.
	//Parameters:
	//  address [in]  The address where the bytes will be copied from.
	//  buffer  [out] The buffer where the bytes will be copied to.
	//  size    [in]  The number of bytes to be copied.
	static void Read(const uintptr_t address, void* const buffer, const SIZE_T size);

	//Copies 'value' to 'address'.
	//Parameters:
	//  address [in] The address where the bytes will be copied to.
	//  value   [in] The value where the bytes will be copied from.
	template <typename T>
	static inline bool Write(const uintptr_t address, const T& value) { return Write(address, &value, sizeof(T)); }

	//Copies 'size' bytes from 'buffer' to 'address'.
	//Parameters:
	//  address [in] The address where the bytes will be copied to.
	//  buffer  [in] The buffer where the bytes will be copied from.
	//  size    [in] The number of bytes to be copied.
	static bool Write(const uintptr_t address, const void* const buffer, const SIZE_T size);

	//Patches 'address' with 'size' bytes stored on 'buffer'.
	//Parameters:
	//  address [in] The address where the bytes will be copied to.
	//  buffer  [in] The buffer where the bytes will be copied from.
	//  size    [in] The number of bytes to be copied.
	static bool Patch(const uintptr_t address, const char* bytes, const size_t size);

	//Writes 'size' 0x90 bytes at address.
	//Parameters:
	//  address   [in] The address where the bytes will be nopped.
	//  size      [in] The number of bytes to be written.
	//  saveBytes [in] If true, save the original bytes located at 'address'
	//                 where they can be later restored by calling Restore().
	static bool Nop(const uintptr_t address, const size_t size, const bool saveBytes = true);

	//Restores the bytes that were nopped at 'address'.
	//Parameters:
	//  address   [in] The address where the bytes will be restored.
	static bool Restore(const uintptr_t address);

	//Copies 'size' bytes from 'sourceAddress' to 'destinationAddress'.
	//Parameters:
	//  destinationAddress [in] The destination buffer's address.
	//  sourceAddress      [in] The souce buffer's address.
	//  size               [in] The number of bytes to be copied.
	static bool Copy(const uintptr_t destinationAddress, const uintptr_t sourceAddress, const size_t size);

	//Sets 'size' 'value' bytes at 'address'.
	//Parameters:
	//  address [in] The address where the bytes will be written to.
	//  value   [in] The byte to be set.
	//  size    [in] The nmber of bytes to be set.
	static bool Set(const uintptr_t address, const int value, const size_t size);

	//Compares the first 'size' bytes of 'address1' and 'address2'.
	//Parameters:
	//  address1 [in] the address where the first buffer is located.
	//  address2 [in] the address where the second buffer is located.
	//  size     [in] The number of bytes to be compared.
	static bool Compare(const uintptr_t address1, const uintptr_t address2, const size_t size);

	//Calculates the MD5 hash of a memory region of the attached process.
	//Parameters:
	//  address [in]  The address where the hash will be calculated.
	//  size    [in]  The size of the region.
	//  outHash [out] A buffer capable of holding a MD5 hash which is 16 bytes.
	static bool HashMD5(const uintptr_t address, const size_t size, uint8_t* const outHash);

	//Scans the address space according to 'scanBoundaries' for a pattern & mask.
	//Parameters:
	//  pattern        [in] A buffer containing the pattern. An example of a
	//                      pattern is "\x68\xAB\x00\x00\x00\x00\x4F\x90\x00\x08".
	//  mask           [in] A string that specifies how the pattern should be 
	//                      interpreted. If mask[i] is equal to '?', then the
	//                      byte pattern[i] is ignored. A example of a mask is
	//                      "xx????xxxx".
	//  scanBoundaries [in] See defination of the ScanBoundaries class.
	//  protect        [in] Specifies a mask of memory protection constants
	//                      which defines what memory regions will be scanned.
	//                      The default value(-1) specifies that pages with any
	//                      protection between 'start' and 'end' should be scanned.
	static uintptr_t PatternScan(const char* const pattern, const char* const mask, const ScanBoundaries& scanBoundaries = ScanBoundaries(SCAN_BOUNDARIES::RANGE, 0, -1), const DWORD protect = -1);
	
	//Scans the address space according to 'scanBoundaries' for an AOB.
	//Parameters:
	//  AOB            [in] The array of bytes(AOB) in string form. To specify
	//                      a byte that should be ignore use the '?' character.
	//                      An example of AOB is "68 AB ?? ?? ?? ?? 4F 90 00 08".
	//  scanBoundaries [in] See defination of the ScanBoundaries class.
	//  protect        [in] Specifies a mask of memory protection constants
	//                      which defines what memory regions will be scanned.
	//                      The default value(-1) specifies that pages with any
	//                      protection between 'start' and 'end' should be scanned.
	static uintptr_t AOBScan(const char* const AOB, const ScanBoundaries& scanBoundaries = ScanBoundaries(SCAN_BOUNDARIES::RANGE, 0, -1), const DWORD protect = -1);

	//Reads a multilevel pointer.
	//Parameters:
	//  base    [in] The base address.
	//  offsets [in] A vector specifying the offsets.
	static uintptr_t ReadMultiLevelPointer(const uintptr_t base, const std::vector<uint32_t>& offsets);

	//Hooks an address.
	//Parameters:
	//  address             [in] The address to be hooked.
	//  callback            [in] The callback to be executed when the CPU executes 'address'.
	//  trampoline          [in] An optional pointer to a variable that receives the address
	//                           of the trampoline. The trampoline contains the original replaced
	//                           instructions of the 'address' and a jump back to 'address'.
	//  saveCpuStateMask    [in] A mask containing a bitwise OR combination of one or more of
	//                           the following macros: GPR(general purpose registers),
	//                           FLAGS(eflags/rflags), XMMX(xmm0, xmm1, xmm2, xmm3, xmm4, xmm5).
	//                           Push the CPU above states to the stack before executing callback.
	//                           You should use this parameter if you perform a mid function hook.
	//                           By default no CPU state is saved.
	static bool Hook(const uintptr_t address, const void* const callback, uintptr_t* const trampoline = nullptr, const DWORD saveCpuStateMask = 0);

	//Removes a previously placed hook at 'address'.
	//Parameters:
	//  address [in] The address to be unhooked.
	static bool Unhook(const uintptr_t address);

	//Scans the address space according to 'scanBoundaries' for a nullByte.
	//Parameters:
	//  size           [in]  The size of the code cave.
	//  nullByte       [in]  The byte of the code cave. If -1 is specified,
	//                       the null byte is any byte, that is, FindCodeCave()
	//                       will return any sequence of the same byte.
	//  scanBoundaries [in]  See defination of the ScanBoundaries class.
	//  codeCaveSize   [out] If not NULL, the variable pointed by this argument
	//                       receives the size of the code cave found. If no code
	//                       cave is found, 0(zero) is set.
	//  protection     [in]  Specifies a mask of memory protection constants
	//                       which defines what memory regions will be scanned.
	//                       The default value(-1) specifies that pages with any
	//                       protection between 'start' and 'end' should be scanned.
	static uintptr_t FindCodeCave(const size_t size, const uint32_t nullByte = 0x00, const ScanBoundaries& scanBoundaries = ScanBoundaries(SCAN_BOUNDARIES::RANGE, 0, -1), size_t* const codeCaveSize = nullptr, const DWORD protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);

	//Scans the address space according to 'scanBoundaries' for nullBytes.
	//Parameters:
	//  size           [in]  The size of the code cave.
	//  nullBytes      [in]  The byte of the code cave.
	//  pNullByte      [in]  If a codecave is found and pNullByte is not NULL,
	//                       the byte that the codecave contains is written to
	//                       the variable pointed by pNullByte.
	//  scanBoundaries [in]  See defination of the ScanBoundaries class.
	//  codeCaveSize   [out] If not NULL, the variable pointed by this argument
	//                       receives the size of the code cave found. If no code
	//                       cave is found, 0(zero) is set.
	//  protection     [in]  Specifies a mask of memory protection constants
	//                       which defines what memory regions will be scanned.
	//                       The default value(-1) specifies that pages with any
	//                       protection between 'start' and 'end' should be scanned.
	static uintptr_t FindCodeCaveBatch(const size_t size, const std::vector<uint8_t>& nullBytes, uint8_t* const pNullByte = nullptr, const ScanBoundaries& scanBoundaries = ScanBoundaries(SCAN_BOUNDARIES::RANGE, 0, -1), size_t* const codeCaveSize = nullptr, const DWORD protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);

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
	static uintptr_t GetModuleBase(const TCHAR* const moduleName = nullptr, DWORD* const pModuleSize = nullptr);

	//Returns the size of first parsed instruction on the buffer at 'address'.
	//Parameters:
	//  address [in] The address of the buffer containing instruction.
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
private:
	static void PatternScanImpl(std::atomic<uintptr_t>& returnValue, std::atomic<size_t>& finishCount, const uint8_t* const pattern, const char* const mask, uintptr_t start = 0, const uintptr_t end = -1, const DWORD protect = -1);

	static void FindCodeCaveImpl(std::atomic<uintptr_t>& returnValue, std::atomic<size_t>& finishCount, const size_t size, uintptr_t start = 0, const uintptr_t end = -1, const DWORD protect = -1);

};

#endif // MEMIN_H