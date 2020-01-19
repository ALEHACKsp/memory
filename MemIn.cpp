#include "MemIn.h"
#include <string>
#include <algorithm>
#include <thread>
#include <cstdint>

#define PLACE(type, value) *reinterpret_cast<type*>(buffer) = (type)(value); buffer += sizeof(type)
#define PLACE1(value) *buffer++ = static_cast<uint8_t>(value)
#define PLACE2(value) PLACE(uint16_t, value)
#define PLACE4(value) PLACE(uint32_t, value)
#define PLACE8(value) PLACE(uint64_t, value)

#ifdef UNICODE
	#define lstrstr wcsstr
#else
	#define lstrstr strstr
#endif

#ifdef _WIN64
	#define HOOK_JUMP_SIZE 12
	#define HOOK_MAX_NUM_REPLACED_BYTES 26
	#define CALCULATE_SAVE_CPU_STATE_BUFFER_SIZE(mask) (static_cast<size_t>(mask ? HOOK_JUMP_SIZE : 0) + (mask & FLAGS ? 2 : 0) + (mask & GPR ? 22 : 0) + (mask & XMMX ? 78 : 0))
#else
	#define HOOK_JUMP_SIZE 5
	#define HOOK_MAX_NUM_REPLACED_BYTES 19
	#define CALCULATE_SAVE_CPU_STATE_BUFFER_SIZE(mask) ((mask ? HOOK_JUMP_SIZE : 0) + (mask & FLAGS ? 2 : 0) + (mask & GPR ? 2 : 0) + (mask & XMMX ? 76 : 0))
#endif

//LDE
#define R (*b >> 4) // Four high-order bits of an opcode to index a row of the opcode table
#define C (*b & 0xF) // Four low-order bits to index a column of the table
static const uint8_t prefixes[] = { 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67 };
static const uint8_t op1modrm[] = { 0x62, 0x63, 0x69, 0x6B, 0xC0, 0xC1, 0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7, 0xFE, 0xFF };
static const uint8_t op1imm8[] = { 0x6A, 0x6B, 0x80, 0x82, 0x83, 0xA8, 0xC0, 0xC1, 0xC6, 0xCD, 0xD4, 0xD5, 0xEB };
static const uint8_t op1imm32[] = { 0x68, 0x69, 0x81, 0xA9, 0xC7, 0xE8, 0xE9 };
static const uint8_t op2modrm[] = { 0x0D, 0xA3, 0xA4, 0xA5, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };

bool findByte(const uint8_t* arr, const size_t N, const uint8_t x) { for (size_t i = 0; i < N; i++) { if (arr[i] == x) { return true; } }; return false; }

void parseModRM(uint8_t** b, const bool addressPrefix)
{
	uint8_t modrm = *++*b;

	if (!addressPrefix || (addressPrefix && **b >= 0x40))
	{
		bool hasSIB = false; //Check for SIB byte
		if (**b < 0xC0 && (**b & 0b111) == 0b100 && !addressPrefix)
			hasSIB = true, (*b)++;

		if (modrm >= 0x40 && modrm <= 0x7F) // disp8 (ModR/M)
			(*b)++;
		else if ((modrm <= 0x3F && (modrm & 0b111) == 0b101) || (modrm >= 0x80 && modrm <= 0xBF)) //disp16,32 (ModR/M)
			*b += (addressPrefix) ? 2 : 4;
		else if (hasSIB && (**b & 0b111) == 0b101) //disp8,32 (SIB)
			*b += (modrm & 0b01000000) ? 1 : 4;
	}
	else if (addressPrefix && modrm == 0x26)
		*b += 2;
};

//MD5
#define ROL(x,s)((x<<s)|x>>(32-s))
uint32_t r[] = { 7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
uint32_t k[] = { 0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };

std::unordered_map<uintptr_t, MemIn::NopStruct> MemIn::m_Nops;
std::unordered_map<uintptr_t, MemIn::HookStruct> MemIn::m_Hooks;

MemIn::ProtectRegion::ProtectRegion(const uintptr_t address, const SIZE_T size, const bool protect)
	: m_Address(NULL), m_Size(size), m_Protection(NULL), m_Success(true)
{
	if (protect)
	{
		m_Success = VirtualProtect(reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE, &m_Protection);
		m_Address = address;
	}
}

MemIn::ProtectRegion::~ProtectRegion() { VirtualProtect(reinterpret_cast<LPVOID>(m_Address), m_Size, m_Protection, &m_Protection); }

bool MemIn::Read(const uintptr_t address, void* const buffer, const SIZE_T size, const bool protect)
{
	ProtectRegion pr(address, size, protect);
	if (!pr.Success())
		return false;

	memcpy(buffer, reinterpret_cast<const void*>(address), size);

	return true;
}

bool MemIn::Write(const uintptr_t address, const void* const buffer, const SIZE_T size, const bool protect)
{
	ProtectRegion pr(address, size, protect);
	if (!pr.Success())
		return false;

	memcpy(reinterpret_cast<void*>(address), buffer, size);

	return true;
}

bool MemIn::Patch(const uintptr_t address, const char* bytes, const size_t size) { return Write(address, bytes, size, true) && static_cast<bool>(FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), static_cast<SIZE_T>(size))); }

bool MemIn::Nop(const uintptr_t address, const size_t size, const bool saveBytes)
{
	if (saveBytes)
	{
		m_Nops[address].buffer = std::make_unique<uint8_t[]>(size);
		m_Nops[address].size = size;

		if (!Read(address, m_Nops[address].buffer.get(), size))
		{
			m_Nops.erase(address);
			return false;
		}
	}

	return Set(address, 0x90, size) && static_cast<bool>(FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), static_cast<SIZE_T>(size)));
}

bool MemIn::Restore(const uintptr_t address)
{
	bool bRet = Patch(address, reinterpret_cast<const char*>(m_Nops[address].buffer.get()), m_Nops[address].size);

	m_Nops.erase(address);

	return bRet && static_cast<bool>(FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), static_cast<SIZE_T>(m_Nops[address].size)));
}

bool MemIn::Copy(const uintptr_t destinationAddress, const uintptr_t sourceAddress, const size_t size)
{
	ProtectRegion prd(destinationAddress, size), prs(sourceAddress, size);
	if (!prd.Success() || !prs.Success())
		return false;

	return memcpy(reinterpret_cast<void*>(destinationAddress), reinterpret_cast<const void*>(sourceAddress), size);
}

bool MemIn::Set(const uintptr_t address, const int value, const size_t size)
{
	ProtectRegion pr(address, size);
	if (!pr.Success())
		return false;

	return memset(reinterpret_cast<void*>(address), value, size);
}

bool MemIn::Compare(const uintptr_t address1, const uintptr_t address2, const size_t size)
{
	ProtectRegion pr1(address1, size), pr2(address2, size);
	if (!pr1.Success() || !pr2.Success())
		return false;

	return memcmp(reinterpret_cast<const void*>(address1), reinterpret_cast<const void*>(address2), size) == 0;
}

//Credits to: https://gist.github.com/creationix/4710780
bool MemIn::HashMD5(const uintptr_t address, const size_t size, uint8_t* const outHash)
{
	size_t N = ((((size + 8) / 64) + 1) * 64) - 8;

	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(N + 64);
	if (!Read(address, buffer.get(), size, true))
		return false;

	buffer[size] = static_cast<uint8_t>(0x80); // 0b10000000
	*reinterpret_cast<uint32_t*>(buffer.get() + N) = static_cast<uint32_t>(size * 8);

	uint32_t X[4] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
	for (uint32_t i = 0, AA = X[0], BB = X[1], CC = X[2], DD = X[3]; i < N; i += 64)
	{
		for (uint32_t j = 0, f, g; j < 64; j++)
		{
			if (j < 16) {
				f = (BB & CC) | ((~BB) & DD);
				g = j;
			}
			else if (j < 32) {
				f = (DD & BB) | ((~DD) & CC);
				g = (5 * j + 1) % 16;
			}
			else if (j < 48) {
				f = BB ^ CC ^ DD;
				g = (3 * j + 5) % 16;
			}
			else {
				f = CC ^ (BB | (~DD));
				g = (7 * j) % 16;
			}

			uint32_t temp = DD;
			DD = CC;
			CC = BB;
			BB += ROL((AA + f + k[j] + reinterpret_cast<uint32_t*>(buffer.get() + i)[g]), r[j]);
			AA = temp;
		}

		X[0] += AA, X[1] += BB, X[2] += CC, X[3] += DD;
	}

	for (int i = 0; i < 4; i++)
		reinterpret_cast<uint32_t*>(outHash)[i] = X[i];

	return true;
}

uintptr_t MemIn::PatternScan(const char* const pattern, const char* const mask, uintptr_t start, const uintptr_t end)
{
#if ENABLE_PATTERN_SCAN_MULTITHREADING
	unsigned int numThreads = std::thread::hardware_concurrency();  numThreads ? numThreads : 1;
#else
	unsigned int numThreads = 1;
#endif
	size_t chunkSize = (end - start) / numThreads;

	std::atomic<uintptr_t> address = 0; std::atomic<size_t> finishCount = 0;
	for (unsigned int i = 0; i < numThreads; i++)
		std::thread(&MemIn::PatternScanImpl, std::ref(address), std::ref(finishCount), reinterpret_cast<const uint8_t* const>(pattern), mask, start + chunkSize * i, start + chunkSize * (static_cast<size_t>(i) + 1)).detach();

	while (finishCount.load() != numThreads)
		Sleep(1);

	return address.load();
}

uintptr_t MemIn::AOBScan(const char* const AOB, const uintptr_t start, const uintptr_t end)
{
	std::string pattern, mask;
	AOBToPattern(AOB, pattern, mask);

	return PatternScan(pattern.c_str(), mask.c_str(), start, end);
}

uintptr_t MemIn::PatternScanModule(const char* const pattern, const char* const mask, const TCHAR* const moduleName)
{
	uintptr_t moduleBase; DWORD moduleSize;
	if (!(moduleBase = GetModuleBase(moduleName, &moduleSize)))
		return 0;

	return PatternScan(pattern, mask, moduleBase, moduleBase + moduleSize);
}

uintptr_t MemIn::AOBScanModule(const char* const AOB, const TCHAR* const moduleName)
{
	std::string pattern, mask;
	AOBToPattern(AOB, pattern, mask);

	return PatternScanModule(pattern.c_str(), mask.c_str(), moduleName);
}

//Credits: https://guidedhacking.com/threads/internal-pattern-scanning-without-know-the-module.13315/
uintptr_t MemIn::PatternScanAllModules(const char* const pattern, const char* const mask)
{
	struct PatternInfo
	{
		const char* const pattern, * const mask;
		uintptr_t address;
	};

	PatternInfo pi = { pattern, mask, 0 };

	EnumModules(
		GetCurrentProcessId(),
		[](const MODULEENTRY32& me, void* param)
		{
			PatternInfo* pi = static_cast<PatternInfo*>(param);
			return !(pi->address = MemIn::PatternScan(pi->pattern, pi->mask, reinterpret_cast<uintptr_t>(me.modBaseAddr), reinterpret_cast<uintptr_t>(me.modBaseAddr + me.modBaseSize)));
		},
		&pi
	);

	return pi.address;
}

uintptr_t MemIn::AOBScanAllModules(const char* const AOB)
{
	std::string pattern, mask;
	AOBToPattern(AOB, pattern, mask);

	return PatternScanAllModules(pattern.c_str(), mask.c_str());
}

//Based on https://guidedhacking.com/threads/finddmaaddy-c-multilevel-pointer-function.6292/
uintptr_t MemIn::ReadMultiLevelPointer(uintptr_t base, const std::vector<uint32_t>& offsets)
{
	MEMORY_BASIC_INFORMATION mbi;
	for (auto& offset : offsets)
	{
		if (!VirtualQuery(reinterpret_cast<LPCVOID>(base), &mbi, sizeof(MEMORY_BASIC_INFORMATION)) || mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
			return 0;

		base = *reinterpret_cast<uintptr_t*>(base) + offset;
	}

	return base;
}

/*If you perform a mid function hook(the saveCpuStateMask is not zero),
you should not use the trampoline to try execute the rest of the original function.*/
bool MemIn::Hook(const uintptr_t address, const void* const callback, uintptr_t* const trampoline, const DWORD saveCpuStateMask)
{
	ProtectRegion pr(address, HOOK_MAX_NUM_REPLACED_BYTES);
	if(!pr.Success())
		return false;

	size_t numReplacedBytes = 0;
	while (numReplacedBytes < HOOK_JUMP_SIZE)
		numReplacedBytes += GetInstructionLength(reinterpret_cast<const void* const>(address + numReplacedBytes));

	const size_t saveCpuStateBufferSize = CALCULATE_SAVE_CPU_STATE_BUFFER_SIZE(saveCpuStateMask);
	const size_t trampolineSize = numReplacedBytes + HOOK_JUMP_SIZE;
	const size_t bufferSize = saveCpuStateBufferSize + trampolineSize;

	//Allocate buffer to store the saveCpuStateBuffer and the trampoline
	uintptr_t bufferAddress = NULL; DWORD oldProtect;
	if (!(bufferAddress =
#if USE_CODE_CAVE_AS_MEMORY
		FindCodeCave(bufferSize)
#else
		reinterpret_cast<uintptr_t>(new uint8_t[bufferSize])
#endif
		) || !VirtualProtect(reinterpret_cast<LPVOID>(bufferAddress), bufferSize, PAGE_EXECUTE_READWRITE, &oldProtect))
		{ return false; }

	uint8_t* buffer = reinterpret_cast<uint8_t*>(bufferAddress);
	if (saveCpuStateMask)
	{
		if (saveCpuStateMask & GPR)
		{
#ifdef _WIN64
			// push rax, rcx, rdx, r8, r9, r10, r11
			PLACE8(0x4151415041525150); PLACE1(0x52); PLACE2(0x5341);
#else
			PLACE1(0x60); // pushad
#endif
		}
		if (saveCpuStateMask & XMMX)
		{
#ifdef _WIN64
			PLACE4(0x60EC8348); // sub rsp, 0x60
#else
			PLACE1(0x83); PLACE2(0x60EC); // sub esp, 0x60
#endif
			PLACE1(0xF3); PLACE4(0x246C7F0F); PLACE1(0x50); // movdqu xmmword ptr ss:[r/esp+0x50], xmm5
			PLACE1(0xF3); PLACE4(0x24647F0F); PLACE1(0x40); // movdqu xmmword ptr ss:[r/esp+0x40], xmm4
			PLACE1(0xF3); PLACE4(0x245C7F0F); PLACE1(0x30); // movdqu xmmword ptr ss:[r/esp+0x30], xmm3
			PLACE1(0xF3); PLACE4(0x24547F0F); PLACE1(0x20); // movdqu xmmword ptr ss:[r/esp+0x20], xmm2
			PLACE1(0xF3); PLACE4(0x244C7F0F); PLACE1(0x10); // movdqu xmmword ptr ss:[r/esp+0x10], xmm1
			PLACE1(0xF3); PLACE4(0x24047F0F); // movdqu xmmword ptr ss:[r/esp], xmm0
		}
		if (saveCpuStateMask & FLAGS)
			{ PLACE1(0x9C); } // pushfd/q

		// call callback
#ifdef _WIN64
		PLACE2(0xB848); PLACE8(callback); PLACE2(0xD0FF);
#else
		PLACE1(0xE8); PLACE4(reinterpret_cast<ptrdiff_t>(callback) - reinterpret_cast<ptrdiff_t>(buffer + 4));
#endif

		if (saveCpuStateMask & FLAGS)
			{ PLACE1(0x9D); } // popfd/q
		if (saveCpuStateMask & XMMX)
		{
			PLACE1(0xF3); PLACE4(0x24046F0F); // movdqu xmm0, xmmword ptr ss:[r/esp]
			PLACE1(0xF3); PLACE4(0x244C6F0F); PLACE1(0x10); // movdqu xmm1, xmmword ptr ss:[r/esp+0x10]
			PLACE1(0xF3); PLACE4(0x24546F0F); PLACE1(0x20); // movdqu xmm2, xmmword ptr ss:[r/esp+0x20]
			PLACE1(0xF3); PLACE4(0x245C6F0F); PLACE1(0x30); // movdqu xmm3, xmmword ptr ss:[r/esp+0x30]
			PLACE1(0xF3); PLACE4(0x24646F0F); PLACE1(0x40); // movdqu xmm4, xmmword ptr ss:[r/esp+0x40]
			PLACE1(0xF3); PLACE4(0x246C6F0F); PLACE1(0x50); // movdqu xmm5, xmmword ptr ss:[r/esp+0x50]
#ifdef _WIN64
			PLACE4(0x60C48348); // add rsp, 0x60
#else
			PLACE1(0x83); PLACE2(0x60C4); // add esp, 0x60
#endif
		}
		if (saveCpuStateMask & GPR)
		{
#ifdef _WIN64
			// pop r11, r10, r9, r8, rdx, rcx, rax
			PLACE8(0x584159415A415B41); PLACE1(0x5A); PLACE2(0x5859);
#else
			PLACE1(0x61); // popad
#endif
		}
	}

	//Copy original instructions
	memcpy(reinterpret_cast<void*>(buffer), reinterpret_cast<const void*>(address), numReplacedBytes); buffer += numReplacedBytes;

	//Jump back to original function
#ifdef _WIN64
	PLACE2(0xB848); PLACE8(address + numReplacedBytes); PLACE2(0xE0FF);
#else
	PLACE1(0xE9); PLACE4(static_cast<ptrdiff_t>(address + numReplacedBytes) - reinterpret_cast<ptrdiff_t>(buffer + 4));
#endif

	//Jump from hooked function to callback
	buffer = reinterpret_cast<uint8_t*>(address);
#ifdef _WIN64
	PLACE2(0xB848); PLACE8((saveCpuStateMask) ? bufferAddress : reinterpret_cast<uintptr_t>(callback)); PLACE2(0xE0FF);
#else
	PLACE1(0xE9); PLACE4(static_cast<ptrdiff_t>((saveCpuStateMask) ? bufferAddress : reinterpret_cast<uintptr_t>(callback)) - reinterpret_cast<ptrdiff_t>(buffer + 4));
#endif

	m_Hooks[address] = { bufferAddress, static_cast<uint8_t>(trampolineSize), saveCpuStateBufferSize };

	if (trampoline)
		*trampoline = saveCpuStateMask ? bufferAddress + saveCpuStateBufferSize : bufferAddress;

	return static_cast<bool>(FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), static_cast<SIZE_T>(numReplacedBytes)));
}

bool MemIn::Unhook(const uintptr_t address)
{
	ProtectRegion pr(address, static_cast<SIZE_T>(m_Hooks[address].trampolineSize - HOOK_JUMP_SIZE));
	if (!pr.Success())
		return false;

	//Restore original instruction(s)
	memcpy(reinterpret_cast<void*>(address), reinterpret_cast<const void*>(m_Hooks[address].trampoline + m_Hooks[address].saveCpuStateBufferSize), m_Hooks[address].trampolineSize - HOOK_JUMP_SIZE);

	//Free memory used to the buffer(i.e. saveCpuStateBuffer and trampoline)
#if USE_CODE_CAVE_AS_MEMORY
	memset(reinterpret_cast<void*>(m_Hooks[address].trampoline), 0xCC, static_cast<size_t>(m_Hooks[address].trampolineSize) + m_Hooks[address].saveCpuStateBufferSize);
#else
	delete[] reinterpret_cast<uint8_t*>(m_Hooks[address].trampoline);
#endif

	m_Hooks.erase(address);

	return static_cast<bool>(FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), static_cast<SIZE_T>(m_Hooks[address].trampolineSize - HOOK_JUMP_SIZE)));
}

uintptr_t MemIn::FindCodeCave(const size_t size, uintptr_t start, const uintptr_t end, const uint8_t nullByte)
{
	MEMORY_BASIC_INFORMATION mbi;
	size_t count = 0;

	while (start < end && VirtualQuery(reinterpret_cast<LPCVOID>(start), &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		//Only scan executable regions that don't have the PAGE_NOACCESS and PAGE_GUARD flags
		if (!(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && (mbi.Protect & 0xF0))
		{
			for (size_t i = 0; i < 4096 - (start % 4096); i++)
			{
				if (*reinterpret_cast<uint8_t*>(start + i) == nullByte && ++count == size)
					return start + i;
				else
					count = 0;
			}
		}

		start += 4096;
	}

	return 0;
}

DWORD MemIn::GetProcessIdByName(const TCHAR* processName)
{
	const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnapshot)
		return 0;

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe32))
	{
		do
		{
			if (!lstrcmp(processName, pe32.szExeFile))
			{
				CloseHandle(hSnapshot);
				return pe32.th32ProcessID;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}

	CloseHandle(hSnapshot);

	return 0;
}

DWORD MemIn::GetProcessIdByWindow(const TCHAR* windowName, const TCHAR* className)
{
	DWORD dwProcessId;
	GetWindowThreadProcessId(FindWindow(className, windowName), &dwProcessId);

	return dwProcessId;
}

uintptr_t MemIn::GetModuleBase(const TCHAR* moduleName, DWORD* const pModuleSize) { return MemIn::GetModuleBase(GetCurrentProcessId(), moduleName, pModuleSize); }

uintptr_t MemIn::GetModuleBase(const DWORD dwProcessId, const TCHAR* const moduleName, DWORD* const pModuleSize)
{
	struct ModuleInfo { const TCHAR* const name; uintptr_t base; DWORD* const size; };
	ModuleInfo mi = { moduleName };

	EnumModules(dwProcessId, 
		[](const MODULEENTRY32& me, void* param)
		{
			ModuleInfo* mi = static_cast<ModuleInfo*>(param);
			if ((mi->name) ? (!lstrcmp(me.szModule, mi->name)) : (lstrstr(me.szModule, TEXT(".exe")) != nullptr))
			{
				mi->base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
				if (mi->size)
					*mi->size = me.modBaseSize;
				return false;
			}
			return true;
		}, &mi);

	return mi.base;
}

//https://github.com/Nomade040/length-disassembler
size_t MemIn::GetInstructionLength(const void* const address)
{
	size_t offset = 0;
	bool operandPrefix = false, addressPrefix = false, rexW = false;
	uint8_t* b = (uint8_t*)(address);

	//Parse legacy prefixes & REX prefixes
#if UINTPTR_MAX == UINT64_MAX
	for (; findByte(prefixes, sizeof(prefixes), *b) || (R == 4); b++)
#else
	for (; findByte(prefixes, sizeof(prefixes), *b); b++)
#endif
	{
		if (*b == 0x66)
			operandPrefix = true;
		else if (*b == 0x67)
			addressPrefix = true;
		else if (R == 4 && C >= 8)
			rexW = true;
	}

	//Parse opcode(s)
	if (*b == 0x0F) // 2,3 bytes
	{
		b++;
		if (*b == 0x38 || *b == 0x3A) // 3 bytes
		{
			if (*b++ == 0x3A)
				offset++;

			parseModRM(&b, addressPrefix);
		}
		else // 2 bytes
		{
			if (R == 8) //disp32
				offset += 4;
			else if ((R == 7 && C < 4) || *b == 0xA4 || *b == 0xC2 || (*b > 0xC3 && *b <= 0xC6) || *b == 0xBA || *b == 0xAC) //imm8
				offset++;

			//Check for ModR/M, SIB and displacement
			if (findByte(op2modrm, sizeof(op2modrm), *b) || (R != 3 && R > 0 && R < 7) || *b >= 0xD0 || (R == 7 && C != 7) || R == 9 || R == 0xB || (R == 0xC && C < 8) || (R == 0 && C < 4))
				parseModRM(&b, addressPrefix);
		}
	}
	else // 1 byte
	{
		//Check for immediate field
		if ((R == 0xE && C < 8) || (R == 0xB && C < 8) || R == 7 || (R < 4 && (C == 4 || C == 0xC)) || (*b == 0xF6 && !(*(b + 1) & 48)) || findByte(op1imm8, sizeof(op1imm8), *b)) //imm8
			offset++;
		else if (*b == 0xC2 || *b == 0xCA) //imm16
			offset += 2;
		else if (*b == 0xC8) //imm16 + imm8
			offset += 3;
		else if ((R < 4 && (C == 5 || C == 0xD)) || (R == 0xB && C >= 8) || (*b == 0xF7 && !(*(b + 1) & 48)) || findByte(op1imm32, sizeof(op1imm32), *b)) //imm32,16
			offset += (rexW) ? 8 : (operandPrefix ? 2 : 4);
		else if (R == 0xA && C < 4)
			offset += (rexW) ? 8 : (addressPrefix ? 2 : 4);
		else if (*b == 0xEA || *b == 0x9A) //imm32,48
			offset += operandPrefix ? 4 : 6;

		//Check for ModR/M, SIB and displacement
		if (findByte(op1modrm, sizeof(op1modrm), *b) || (R < 4 && (C < 4 || (C >= 8 && C < 0xC))) || R == 8 || (R == 0xD && C >= 8))
			parseModRM(&b, addressPrefix);
	}

	return (size_t)((ptrdiff_t)(++b + offset) - (ptrdiff_t)(address));
}

void MemIn::EnumModules(const DWORD processId, bool (*callback)(const MODULEENTRY32& me, void* param), void* param)
{
	const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return;

	MODULEENTRY32 me = { sizeof(MODULEENTRY32) };
	if (Module32First(hSnapshot, &me))
	{
		do
		{
			if (!callback(me, param))
				break;
		} while (Module32Next(hSnapshot, &me));
	}

	CloseHandle(hSnapshot);
}

//Credits to: https://guidedhacking.com/threads/universal-pattern-signature-parser.9588/ & https://guidedhacking.com/threads/python-script-to-convert-ces-aob-signature-to-c-s-signature-mask.14095/
void MemIn::AOBToPattern(const char* const AOB, std::string& pattern, std::string& mask)
{
	if (!AOB)
		return;

	auto ishex = [](const char c) -> bool { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'); };
	auto hexchartoint = [](const char c) -> uint8_t { return (c >= 'A') ? (c - 'A' + 10) : (c - '0'); };

	const char* bytes = static_cast<const char*>(AOB);
	for (; *bytes != '\0'; bytes++)
	{
		if (ishex(*bytes))
			pattern += static_cast<char>((ishex(*(bytes + 1))) ? hexchartoint(*bytes) | (hexchartoint(*(bytes++)) << 4) : hexchartoint(*bytes)), mask += 'x';
		else if (*bytes == '?')
			pattern += '\x00', mask += '?', (*(bytes + 1) == '?') ? (bytes++) : (bytes);
	}
}

//Inspired by https://github.com/cheat-engine/cheat-engine/blob/ac072b6fae1e0541d9e54e2b86452507dde4689a/Cheat%20Engine/ceserver/native-api.c
void MemIn::PatternScanImpl(std::atomic<uintptr_t>& address, std::atomic<size_t>& finishCount, const uint8_t* const pattern, const char* const mask, uintptr_t start, const uintptr_t end)
{
	MEMORY_BASIC_INFORMATION mbi;
	const size_t patternSize = strlen(mask);

	while (!address.load() && start < end && VirtualQuery(reinterpret_cast<LPCVOID>(start), &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		if (!(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) && mbi.Protect)
		{
			for (; start < reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize; start += 4096)
			{
				const uint8_t* bytes = reinterpret_cast<const uint8_t*>(start);
				for (size_t i = 0; i < 4096 - patternSize; i++)
				{
					for (size_t j = 0; j < patternSize; j++)
					{
						if (!(mask[j] == '?' || bytes[j] == pattern[j]))
							goto byte_not_match;
					}

					if (start + i != reinterpret_cast<uintptr_t>(pattern))
					{
						address = start + i; //Found match
						finishCount++; //Increase finish count
						return;
					}
				byte_not_match:
					bytes++;
				}
			}
		}

		start = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
	}

	finishCount++;
}