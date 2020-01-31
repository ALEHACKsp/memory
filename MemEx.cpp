#include "MemEx.h"
#include <algorithm>
#include <thread>
#include <cstdint>

#ifdef UNICODE
	#define lstrstr wcsstr
#else
	#define lstrstr strstr
#endif

#define PLACE(type, value) *reinterpret_cast<type*>(buffer) = (type)(value); buffer += sizeof(type)
#define PLACE1(value) *buffer++ = static_cast<uint8_t>(value)
#define PLACE2(value) PLACE(uint16_t, value)
#define PLACE4(value) PLACE(uint32_t, value)
#define PLACE8(value) PLACE(uint64_t, value)
#define PUSH1(value) PLACE1(0x6A); PLACE(uint8_t, value)
#define PUSH4(value) PLACE1(0x68); PLACE(uint32_t, value)

#define CALL_RELATIVE(sourceAddress, functionAddress) PLACE1(0xE8); PLACE(ptrdiff_t, (ptrdiff_t)(functionAddress) - reinterpret_cast<ptrdiff_t>(sourceAddress + 4))

#ifdef _WIN64
	#define HOOK_JUMP_SIZE 12
	#define HOOK_MAX_NUM_REPLACED_BYTES 26
	#define CALL_ABSOLUTE(address) PLACE2(0xB848); PLACE8(address); PLACE2(0xD0FF);
	#define CALCULATE_SAVE_CPU_STATE_BUFFER_SIZE(mask) (static_cast<size_t>(mask ? HOOK_JUMP_SIZE : 0) + (mask & FLAGS ? 2 : 0) + (mask & GPR ? 22 : 0) + (mask & XMMX ? 78 : 0))
#else
	#define HOOK_JUMP_SIZE 5
	#define HOOK_MAX_NUM_REPLACED_BYTES 19
	#define CALCULATE_SAVE_CPU_STATE_BUFFER_SIZE(mask) ((mask ? HOOK_JUMP_SIZE : 0) + (mask & FLAGS ? 2 : 0) + (mask & GPR ? 2 : 0) + (mask & XMMX ? 76 : 0))
#endif

#define X86_MAXIMUM_INSTRUCTION_LENGTH 15

//LDE
#define R (*b >> 4) // Four high-order bits of an opcode to index a row of the opcode table
#define C (*b & 0xF) // Four low-order bits to index a column of the table
static const uint8_t prefixes[] = { 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67 };
static const uint8_t op1modrm[] = { 0x62, 0x63, 0x69, 0x6B, 0xC0, 0xC1, 0xC4, 0xC5, 0xC6, 0xC7, 0xD0, 0xD1, 0xD2, 0xD3, 0xF6, 0xF7, 0xFE, 0xFF };
static const uint8_t op1imm8[] = { 0x6A, 0x6B, 0x80, 0x82, 0x83, 0xA8, 0xC0, 0xC1, 0xC6, 0xCD, 0xD4, 0xD5, 0xEB };
static const uint8_t op1imm32[] = { 0x68, 0x69, 0x81, 0xA9, 0xC7, 0xE8, 0xE9 };
static const uint8_t op2modrm[] = { 0x0D, 0xA3, 0xA4, 0xA5, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF };

inline bool findByte(const uint8_t* arr, const size_t N, const uint8_t x) { for (size_t i = 0; i < N; i++) { if (arr[i] == x) { return true; } }; return false; }

inline void parseModRM(uint8_t** b, const bool addressPrefix)
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
static const uint32_t r[] = { 7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21 };
static const uint32_t k[] = { 0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391 };

typedef PVOID (__stdcall * _MapViewOfFileNuma2)(HANDLE FileMappingHandle, HANDLE ProcessHandle, ULONG64 Offset, PVOID BaseAddress, SIZE_T ViewSize, ULONG AllocationType, ULONG PageProtection, ULONG PreferredNode);
typedef BOOL (__stdcall * _UnmapViewOfFile2)(HANDLE Process, LPCVOID BaseAddress, ULONG UnmapFlags);

const DWORD MemEx::dwPageSize = MemEx::GetPageSize();

MemEx::MemEx()
	: m_hProcess(NULL),
	m_dwProcessId(0),
	m_hFileMapping(NULL), m_hFileMappingDuplicate(NULL),
	m_hThread(NULL),
	m_hEvent1(NULL), m_hEvent2(NULL),
	m_hEventDuplicate1(NULL), m_hEventDuplicate2(NULL),
	m_targetMappedView(NULL), m_thisMappedView(NULL),
	m_numPages(0) {}

MemEx::~MemEx() { Detach(); }

bool MemEx::IsAttached() { return m_hProcess; }

bool MemEx::Attach(const HANDLE hProcess)
{
	DWORD tmp;
	if (m_hProcess || !GetHandleInformation((m_hProcess = hProcess), &tmp))
		return false;

	m_dwProcessId = GetProcessId(hProcess);

	m_numPages = 1;

	return true;
}
bool MemEx::Attach(const DWORD dwProcessId) { return Attach(OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_DUP_HANDLE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION, FALSE, dwProcessId)); }
bool MemEx::Attach(const TCHAR* const processName) { return Attach(MemEx::GetProcessIdByName(processName)); }
bool MemEx::AttachByWindow(const TCHAR* const windowName, const TCHAR* const className) { return Attach(MemEx::GetProcessIdByWindow(windowName, className)); }

void MemEx::WaitAttach(const TCHAR* const processName, const DWORD dwMilliseconds)
{
	while (!Attach(processName))
		Sleep(dwMilliseconds);
}
void MemEx::WaitAttachByWindow(const TCHAR* const windowName, const TCHAR* const className, const DWORD dwMilliseconds)
{
	while (!AttachByWindow(windowName, className))
		Sleep(dwMilliseconds);
}

void MemEx::Detach()
{
	if (!m_hProcess)
		return;

	DeleteRemoteThread();
	
	FreeSharedMemory(m_hFileMapping, m_thisMappedView, m_targetMappedView);
	m_hFileMapping = NULL;

	CloseHandle(m_hProcess);
	m_hProcess = NULL;

	m_dwProcessId = static_cast<DWORD>(0);
}

HANDLE MemEx::GetProcess() const { return m_hProcess; }
DWORD MemEx::GetPid() const { return m_dwProcessId; }

bool MemEx::Read(const uintptr_t address, void* const buffer, const SIZE_T size) const { return ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(address), buffer, size, NULL); }

bool MemEx::Write(uintptr_t address, const void* const buffer, const SIZE_T size) const
{
	MEMORY_BASIC_INFORMATION mbi;
	if (!VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
		return false;

	DWORD oldProtect = 0;
	if (mbi.Protect & (PAGE_READONLY | PAGE_GUARD))
		VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE, &oldProtect);

	bool ret = static_cast<bool>(WriteProcessMemory(m_hProcess, reinterpret_cast<LPVOID>(address), buffer, size, NULL));

	if (oldProtect)
		VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(address), size, oldProtect, &oldProtect);

	return ret;
}

bool MemEx::Patch(const uintptr_t address, const char* const bytes, const size_t size) const { return Write(address, bytes, size) && static_cast<bool>(FlushInstructionCache(m_hProcess, reinterpret_cast<LPCVOID>(address), static_cast<SIZE_T>(size))); }

bool MemEx::Nop(const uintptr_t address, const size_t size, const bool saveBytes)
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

	return Set(address, 0x90, size) && static_cast<bool>(FlushInstructionCache(m_hProcess, reinterpret_cast<LPCVOID>(address), static_cast<SIZE_T>(size)));
}

bool MemEx::Restore(const uintptr_t address)
{
	bool bRet = Patch(address, reinterpret_cast<const char*>(m_Nops[address].buffer.get()), m_Nops[address].size);

	m_Nops.erase(address);

	return bRet && static_cast<bool>(FlushInstructionCache(m_hProcess, reinterpret_cast<LPCVOID>(address), static_cast<SIZE_T>(m_Nops[address].size)));
}

bool MemEx::Copy(const uintptr_t destinationAddress, const uintptr_t sourceAddress, const size_t size) const
{
	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);

	return !Read(sourceAddress, buffer.get(), size) || !Write(destinationAddress, buffer.get(), size);
}

bool MemEx::Set(const uintptr_t address, const int value, const size_t size) const
{
	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(size);
	memset(buffer.get(), value, size);

	return Write(address, buffer.get(), size);
}

bool MemEx::Compare(const uintptr_t address1, const uintptr_t address2, const size_t size) const
{
	std::unique_ptr<uint8_t[]> buffer1 = std::make_unique<uint8_t[]>(size), buffer2 = std::make_unique<uint8_t[]>(size);
	if (!Read(address1, buffer1.get(), size) || !Read(address2, buffer2.get(), size))
		return false;

	return memcmp(buffer1.get(), buffer2.get(), size) == 0;
}

//Credits to: https://gist.github.com/creationix/4710780
bool MemEx::HashMD5(const uintptr_t address, const size_t size, uint8_t* const outHash) const
{
	size_t N = ((((size + 8) / 64) + 1) * 64) - 8;

	std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(N + 64);
	if (!Read(address, buffer.get(), size))
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

uintptr_t MemEx::PatternScan(const char* const pattern, const char* const mask, uintptr_t start, const uintptr_t end, const DWORD protect) const
{
	std::atomic<uintptr_t> address = 0; std::atomic<size_t> finishCount = 0;

#if SCAN_EX_MULTITHREADING
	auto numThreads = std::thread::hardware_concurrency();
	if (!numThreads)
		numThreads = 1;

	size_t chunkSize = (end - start) / numThreads;
	
	for (size_t i = 0; i < numThreads; i++)
		std::thread(&MemEx::PatternScanImpl, this, std::ref(address), std::ref(finishCount), reinterpret_cast<const uint8_t* const>(pattern), mask, start + chunkSize * i, start + chunkSize * (i + 1), protect).detach();

	while (finishCount.load() != numThreads)
		Sleep(1);

#else
	PatternScanImpl(address, finishCount, reinterpret_cast<const uint8_t* const>(pattern), mask, start, end, protect);
#endif	

	return address.load();
}

uintptr_t MemEx::AOBScan(const char* const AOB, const uintptr_t start, const uintptr_t end, const DWORD protect) const
{
	std::string pattern, mask;
	AOBToPattern(AOB, pattern, mask);

	return PatternScan(pattern.c_str(), mask.c_str(), start, end, protect);
}

uintptr_t MemEx::PatternScanModule(const char* const pattern, const char* const mask, const TCHAR* const moduleName, const DWORD protect) const
{
	uintptr_t moduleBase; DWORD moduleSize;
	if (!(moduleBase = GetModuleBase(moduleName, &moduleSize)))
		return 0;

	return PatternScan(pattern, mask, moduleBase, moduleBase + moduleSize, protect);
}

uintptr_t MemEx::AOBScanModule(const char* const AOB, const TCHAR* const moduleName, const DWORD protect) const
{
	std::string pattern, mask;
	AOBToPattern(AOB, pattern, mask);

	return PatternScanModule(pattern.c_str(), mask.c_str(), moduleName, protect);
}

//Credits: https://guidedhacking.com/threads/internal-pattern-scanning-without-know-the-module.13315/
uintptr_t MemEx::PatternScanAllModules(const char* const pattern, const char* const mask, const DWORD protect) const
{
	struct PatternInfo
	{
		const char* const pattern,* const mask;
		const MemEx* mem;
		uintptr_t address;
		DWORD protect;
	};

	PatternInfo pi = { pattern, mask, this, 0, protect};

	EnumModules(m_dwProcessId,
		[](MODULEENTRY32& me, void* param)
		{
			PatternInfo* pi = static_cast<PatternInfo*>(param);
			return !(pi->address = pi->mem->PatternScan(pi->pattern, pi->mask, reinterpret_cast<uintptr_t>(me.modBaseAddr), reinterpret_cast<uintptr_t>(me.modBaseAddr + me.modBaseSize), pi->protect));
		}, &pi);

	return pi.address;
}

uintptr_t MemEx::AOBScanAllModules(const char* const AOB, const DWORD protect) const
{
	std::string pattern, mask;
	AOBToPattern(AOB, pattern, mask);

	return PatternScanAllModules(pattern.c_str(), mask.c_str(), protect);
}

//Based on https://guidedhacking.com/threads/finddmaaddy-c-multilevel-pointer-function.6292/
uintptr_t MemEx::ReadMultiLevelPointer(uintptr_t base, const std::vector<uint32_t>& offsets) const
{
	for (auto& offset : offsets)
	{
		if (!Read(base, &base, sizeof(uintptr_t)))
			return 0;

		base += offset;
	}

	return base;
}

bool MemEx::Hook(const uintptr_t address, const void* const callback, uintptr_t* const trampoline, const DWORD saveCpuStateMask, const HOOK_EX_ALLOCATION_METHOD allocationMethod, void* const data)
{
	size_t size = 0;
	constexpr uint8_t hookMark[12] = { 0xD6, 0xD6, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0x0F, 0xD6, 0xD6 };

	const uint8_t* tmp = static_cast<const uint8_t*>(callback);
	while (memcmp(tmp, hookMark, sizeof(hookMark)) != 0)
		tmp++;

	return HookBuffer(address, callback, static_cast<const size_t>(reinterpret_cast<ptrdiff_t>(tmp) - reinterpret_cast<ptrdiff_t>(callback)), trampoline, saveCpuStateMask);
}

bool MemEx::HookBuffer(const uintptr_t address, const void* const callback, const size_t callbackSize, uintptr_t* const trampoline, const DWORD saveCpuStateMask, const HOOK_EX_ALLOCATION_METHOD allocationMethod, void* const data)
{
	uint8_t originalCode[HOOK_MAX_NUM_REPLACED_BYTES];
	if (!m_hProcess || !Read(address, originalCode, sizeof(originalCode)))
		return false;

	size_t numReplacedBytes = 0;
	while (numReplacedBytes < HOOK_JUMP_SIZE)
		numReplacedBytes += GetInstructionLength(address + numReplacedBytes);

	const size_t saveCpuStateBufferSize = CALCULATE_SAVE_CPU_STATE_BUFFER_SIZE(saveCpuStateMask);
	const size_t trampolineSize = numReplacedBytes + HOOK_JUMP_SIZE;
	const size_t bufferSize = saveCpuStateBufferSize + trampolineSize;

	//Allocate buffer to store the saveCpuStateBuffer and the trampoline
	uintptr_t bufferAddress = NULL, lastAddress; uint8_t codeCaveNullByte = 0;
	switch (allocationMethod)
	{
	case HOOK_EX_ALLOCATION_METHOD::SHARED_MEMORY:
		if (!m_hFileMapping && !(m_hFileMapping = AllocateSharedMemory(m_numPages * dwPageSize, reinterpret_cast<PVOID&>(m_thisMappedView), reinterpret_cast<PVOID&>(m_targetMappedView))))
			return false;

		lastAddress = reinterpret_cast<uintptr_t>(m_thisMappedView + m_numPages * 4096);
		for (auto& hook : m_Hooks)
		{
			if (lastAddress - hook.first >= bufferSize)
			{
				bufferAddress = lastAddress;
				break;
			}

			lastAddress = hook.first;
		}

		if (!bufferAddress)
		{
			if (static_cast<ptrdiff_t>(lastAddress) - reinterpret_cast<ptrdiff_t>(m_thisMappedView + 0x80) >= static_cast<ptrdiff_t>(bufferSize))
				bufferAddress = lastAddress;
			else //Resize shared memory
			{
				std::unique_ptr<uint8_t[]> tmpBuffer = std::make_unique<uint8_t[]>(m_numPages * 4096);
				memcpy(tmpBuffer.get(), m_thisMappedView, m_numPages * 4096);

				m_numPages += (bufferSize > 4096) ? static_cast<uint8_t>(bufferSize >> 12) : static_cast<uint8_t>(1);
				if (!UnmapLocalViewOfFile(m_thisMappedView) || !UnmapRemoteViewOfFile(m_targetMappedView) || !static_cast<bool>(CloseHandle(m_hFileMapping)) ||
					!(m_hFileMapping = AllocateSharedMemory(m_numPages * dwPageSize, reinterpret_cast<PVOID&>(m_thisMappedView), reinterpret_cast<PVOID&>(m_targetMappedView))))
					return false;

				std::map<uintptr_t, HookStruct> oldHooks = m_Hooks;
				m_Hooks.clear();

				uint8_t* nextAddress = m_thisMappedView + m_numPages * 4096;
				for (auto& hook : oldHooks)
				{
					memcpy(nextAddress - (static_cast<size_t>(hook.second.callbackSize) + hook.second.trampolineSize), reinterpret_cast<const void*>(hook.first), static_cast<size_t>(hook.second.callbackSize) + hook.second.trampolineSize);
					m_Hooks[reinterpret_cast<uintptr_t>(nextAddress)] = hook.second;

#ifdef _WIN64
					Write<uintptr_t>(hook.second.address + 2, reinterpret_cast<uintptr_t>(nextAddress));
#else
					Write<ptrdiff_t>(reinterpret_cast<uintptr_t>(nextAddress + hook.second.callbackSize + hook.second.trampolineSize + 1), static_cast<ptrdiff_t>(address + numReplacedBytes) - reinterpret_cast<ptrdiff_t>(nextAddress + hook.second.callbackSize + hook.second.trampolineSize));

					Write<ptrdiff_t>(hook.second.address + hook.second.trampolineSize - 5, reinterpret_cast<ptrdiff_t>(nextAddress) - static_cast<ptrdiff_t>(hook.second.address + hook.second.trampolineSize));
#endif

					nextAddress += static_cast<size_t>(hook.second.callbackSize) + hook.second.trampolineSize;
				}

				bufferAddress = reinterpret_cast<uintptr_t>(nextAddress);
			}
		}

		bufferAddress -= bufferSize;
		break;
	case HOOK_EX_ALLOCATION_METHOD::CODE_CAVE:
		if (data)
			bufferAddress = FindCodeCaveBatch(bufferSize, *reinterpret_cast<const std::vector<uint8_t>*>(data), &codeCaveNullByte);
		else
			bufferAddress = FindCodeCaveBatch(bufferSize, { 0x00, 0xCC }, &codeCaveNullByte);
		break;
	case HOOK_EX_ALLOCATION_METHOD::USER_BUFFER:
		if (callback)
			bufferAddress = reinterpret_cast<uintptr_t>(data);
		else
		{
			*reinterpret_cast<size_t*>(data) = bufferSize;
			return true;
		}
	}

	//The call to memset is here just to prevent the "Using unitialized memory bufferAddress" warning. IKR
	DWORD oldProtect;
	if (!bufferAddress || !memset(reinterpret_cast<void*>(bufferAddress), 0, 1) || !VirtualProtect(reinterpret_cast<LPVOID>(bufferAddress), bufferSize, PAGE_EXECUTE_READWRITE, &oldProtect))
		return false;

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
		{
			PLACE1(0x9C);
		} // pushfd/q
	}

	// execute callback
	memcpy(buffer, callback, callbackSize); buffer += callbackSize;

	if (saveCpuStateMask)
	{
		if (saveCpuStateMask & FLAGS)
		{
			PLACE1(0x9D);
		} // popfd/q
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

	// execute callback
	memcpy(buffer, callback, callbackSize); buffer += callbackSize;

	if (saveCpuStateMask)
	{
		if (saveCpuStateMask & FLAGS)
		{
			PLACE1(0x9D);
		} // popfd/q
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
	memcpy(reinterpret_cast<void*>(buffer), reinterpret_cast<const void*>(originalCode), numReplacedBytes); buffer += numReplacedBytes;

	//Jump back to original function
#ifdef _WIN64
	PLACE2(0xB848); PLACE8(address + numReplacedBytes); PLACE2(0xE0FF);
#else

//#if USE_CODE_CAVE_AS_MEMORY
//	PLACE1(0xE9); PLACE4(static_cast<ptrdiff_t>(address + numReplacedBytes) - static_cast<ptrdiff_t>(bufferAddress + (buffer - bufferPtr.get()) + 4));
//#else
//	PLACE1(0xE9); PLACE4(static_cast<ptrdiff_t>(address + numReplacedBytes) - static_cast<ptrdiff_t>(targetBuffer + (reinterpret_cast<uintptr_t>(buffer) - bufferAddress) + 4));
//#endif

#endif

	//Jump from hooked function to callback
	uint8_t jump[HOOK_JUMP_SIZE]; buffer = reinterpret_cast<uint8_t*>(jump);
#if USE_CODE_CAVE_AS_MEMORY
	if (Write(bufferAddress, bufferPtr.get(), bufferSize, true))
		return false;

#ifdef _WIN64
	PLACE2(0xB848); PLACE8(bufferAddress); PLACE2(0xE0FF);
#else
	PLACE1(0xE9); PLACE4(static_cast<ptrdiff_t>(bufferAddress) - static_cast<ptrdiff_t>(address + 5));
#endif

	if (trampoline)
		*trampoline = bufferAddress + saveCpuStateBufferSize;
#else

	//#ifdef _WIN64
	//	PLACE2(0xB848); PLACE8(targetBuffer); PLACE2(0xE0FF);
	//#else
	//	PLACE1(0xE9); PLACE4(static_cast<ptrdiff_t>(targetBuffer) - static_cast<ptrdiff_t>(address + 5));
	//#endif

		//if (trampoline)
		//	*trampoline = targetBuffer + saveCpuStateBufferSize;
#endif

	if (!Write(address, jump, HOOK_JUMP_SIZE))
		return false;

	HookStruct hook;
	hook.address = address;
	hook.callbackSize = static_cast<uint16_t>(callbackSize);
	hook.saveCpuStateBufferSize = static_cast<uint8_t>(saveCpuStateBufferSize);
	hook.trampolineSize = static_cast<uint8_t>(trampolineSize);
	hook.allocationMethod = allocationMethod;
	hook.codeCaveNullByte = codeCaveNullByte;

	m_Hooks[bufferAddress] = hook;

	return static_cast<bool>(FlushInstructionCache(m_hProcess, reinterpret_cast<LPCVOID>(address), numReplacedBytes));
}

bool MemEx::Unhook(const uintptr_t address)
{
	for (auto& hook : m_Hooks)
	{
		if (hook.second.address == address)
		{
			//Restore original instruction(s)
			Write(address, reinterpret_cast<const void*>(hook.first + + hook.second.saveCpuStateBufferSize + hook.second.callbackSize), hook.second.trampolineSize - HOOK_JUMP_SIZE);

#if USE_CODE_CAVE_AS_MEMORY
			memset(reinterpret_cast<void*>(hook.first), 0xCC, static_cast<size_t>(static_cast<size_t>(hook.second.callbackSize) + hook.second.trampolineSize));
#endif

			m_Hooks.erase(hook.first);
						
			return static_cast<bool>(FlushInstructionCache(m_hProcess, reinterpret_cast<LPCVOID>(address), hook.second.trampolineSize - HOOK_JUMP_SIZE));
		}
	}

	return false;
}

uintptr_t MemEx::FindCodeCave(const size_t size, const uint32_t nullByte, uintptr_t start, const uintptr_t end, const DWORD protection) const
{
	if (nullByte != -1)
	{
		auto pattern = std::make_unique<char[]>(size), mask = std::make_unique<char[]>(size + 1);
		memset(pattern.get(), static_cast<int>(nullByte), size);
		memset(mask.get(), static_cast<int>('x'), size);
		mask.get()[size] = '\0';

		return PatternScan(pattern.get(), mask.get(), start, end, protection);
	}
	else
	{
		std::atomic<uintptr_t> address = 0; std::atomic<size_t> finishCount = 0;

#if SCAN_EX_MULTITHREADING
		auto numThreads = std::thread::hardware_concurrency();
		if (!numThreads)
			numThreads = 1;

		size_t chunkSize = (end - start) / numThreads;

		for (unsigned int i = 0; i < numThreads; i++)
			std::thread(&MemEx::FindCodeCaveImpl, this, std::ref(address), std::ref(finishCount), size, start + chunkSize * i, start + chunkSize * (static_cast<size_t>(i) + 1), protection).detach();

		while (finishCount.load() != numThreads)
			Sleep(1);

#else
		FindCodeCaveImpl(address, finishCount, size, start, end, protection);
#endif	

		return address.load();
	}
}

uintptr_t MemEx::FindCodeCaveBatch(const size_t size, const std::vector<uint8_t>& nullBytes, uint8_t* const pNullByte, uintptr_t start, const uintptr_t end, const DWORD protection) const
{
	for (auto nullByte : nullBytes)
	{
		auto address = FindCodeCave(size, nullByte, start, end, protection);
		if (address)
		{
			if (pNullByte)
				*pNullByte = nullByte;

			return address;
		}
	}

	return 0;
}

uintptr_t MemEx::FindCodeCaveModule(const size_t size, const uint32_t nullByte, const TCHAR* const moduleName, const DWORD protection) const
{
	uintptr_t moduleBase; DWORD moduleSize;
	if (!(moduleBase = GetModuleBase(moduleName, &moduleSize)))
		return 0;

	return FindCodeCave(size, nullByte, moduleBase, moduleBase + moduleSize, protection);
}

uintptr_t MemEx::FindCodeCaveModuleBatch(const size_t size, const std::vector<uint8_t>& nullBytes, const TCHAR* const moduleName, uint8_t* const pNullByte, const DWORD protection) const
{
	for (auto nullByte : nullBytes)
	{
		auto address = FindCodeCaveModule(size, nullByte, moduleName, protection);
		if (address)
		{
			if (pNullByte)
				*pNullByte = nullByte;

			return address;
		}
	}

	return 0;
}

uintptr_t MemEx::FindCodeCaveAllModules(const size_t size, const uint32_t nullByte, const DWORD protection) const
{
	struct CodeCaveInfo
	{
		size_t size;
		uint32_t nullByte;
		DWORD protection;
		const MemEx* pThis;
		uintptr_t address;
	};

	CodeCaveInfo cci = { size, nullByte, protection, this };

	EnumModules(m_dwProcessId, [](MODULEENTRY32& me, void* param) {
		CodeCaveInfo* pcci = reinterpret_cast<CodeCaveInfo*>(param);
		return (pcci->address = pcci->pThis->FindCodeCave(pcci->size, pcci->nullByte, reinterpret_cast<uintptr_t>(me.modBaseAddr), reinterpret_cast<uintptr_t>(me.modBaseAddr) + me.modBaseSize, pcci->protection)) == NULL;
		}, &cci);

	return cci.address;
}

uintptr_t MemEx::FindCodeCaveAllModulesBatch(const size_t size, const std::vector<uint8_t>& nullBytes, uint8_t* const pNullByte, const DWORD protection) const
{
	for (auto nullByte : nullBytes)
	{
		auto address = FindCodeCaveAllModules(size, nullByte, protection);
		if (address)
		{
			if (pNullByte)
				*pNullByte = nullByte;

			return address;
		}
	}

	return 0;
}

PVOID MemEx::MapLocalViewOfFile(const HANDLE hFileMapping) { return MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS | FILE_MAP_WRITE, 0, 0, 0); }

bool MemEx::UnmapLocalViewOfFile(LPCVOID localAddress) { return static_cast<bool>(UnmapViewOfFile(localAddress)); }

PVOID MemEx::MapRemoteViewOfFile(const HANDLE hFileMapping) const
{
	auto lib = LoadLibrary(TEXT("Api-ms-win-core-memory-l1-1-5.dll"));
	_MapViewOfFileNuma2 mapViewOfFileNuma2;
	if (lib && (mapViewOfFileNuma2 = reinterpret_cast<_MapViewOfFileNuma2>(GetProcAddress(lib, "MapViewOfFileNuma2"))))
	{
		FreeLibrary(lib);

		return mapViewOfFileNuma2(hFileMapping, m_hProcess, 0, nullptr, 0, 0, PAGE_EXECUTE_READWRITE, -1);
	}
	else
	{
		LPVOID address = VirtualAllocEx(m_hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!address)
			return false;

		//Construct shellcode and copy it to the target process
		uint8_t shellcode[96]; uint8_t* buffer = shellcode;

		//Duplicate the handle to the file mapping object
		HANDLE hFileMappingDuplicate, hProcessDuplicate;
		if (!DuplicateHandle(GetCurrentProcess(), hFileMapping, m_hProcess, &hFileMappingDuplicate, NULL, FALSE, DUPLICATE_SAME_ACCESS) || !DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), m_hProcess, &hProcessDuplicate, NULL, FALSE, DUPLICATE_SAME_ACCESS))
		{
			VirtualFreeEx(m_hProcess, address, 0, MEM_RELEASE);
			return false;
		}

		PVOID targetAddress = nullptr;

#ifdef _WIN64
		PLACE1(0xB9); PLACE4(reinterpret_cast<uintptr_t>(m_hFileMappingDuplicate)); // mov ecx, m_hFileMappingDuplicate
		PLACE1(0xBA); PLACE4(FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE); //mov edx, FILE_MAP_ALL_ACCESS
		PLACE4(0x45C03345); PLACE2(0xC933); // (xor r8d, r8d) & (xor r9d, r9d)
		PUSH1(0);
		CALL_ABSOLUTE(MapViewOfFile);

		PLACE1(0x50);

		PLACE1(0xB9); PLACE4(reinterpret_cast<uintptr_t>(hProcessDuplicate));
		PLACE1(0xBA); PLACE8(&m_targetMappedView);
		PLACE1(0x4C); PLACE2(0xC48B); // mov r8, rax
		PLACE2(0xB941); PLACE4(sizeof(uintptr_t)); // mov r9d, sizeof(HANDLE)
		PUSH1(0);
		CALL_ABSOLUTE(WriteProcessMemory);

		PLACE2(0xC358); // pop esp & ret
#else
		PUSH1(0);
		PUSH1(0);
		PUSH1(0);
		PUSH4(FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE);
		PUSH4(hFileMappingDuplicate);
		CALL_RELATIVE(reinterpret_cast<uint8_t*>(address) + (buffer - shellcode), MapViewOfFile);

		PLACE1(0x50); //push eax

		PUSH1(0);
		PUSH1(sizeof(uintptr_t));
		PLACE4(0x0824448D); // lea eax, dword ptr ss:[esp + 8]
		PLACE1(0x50); // push eax
		PUSH4(&targetAddress);
		PUSH4(hProcessDuplicate);
		CALL_RELATIVE(reinterpret_cast<uint8_t*>(address) + (buffer - shellcode), WriteProcessMemory);

		PLACE2(0xC358); // pop esp & ret
#endif

		WriteProcessMemory(m_hProcess, address, shellcode, sizeof(shellcode), NULL);

		CreateRemoteThread(m_hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(address), NULL, NULL, NULL);

		Sleep(2);

		DuplicateHandle(m_hProcess, hProcessDuplicate, NULL, NULL, NULL, FALSE, DUPLICATE_CLOSE_SOURCE);

		VirtualFreeEx(m_hProcess, address, 0, MEM_RELEASE);

		return targetAddress;
	}
}

bool MemEx::UnmapRemoteViewOfFile(LPCVOID remoteAddress) const
{
	auto lib = LoadLibrary(TEXT("kernelbase.dll"));
	_UnmapViewOfFile2 unmapViewOfFile2;
	if (lib && (unmapViewOfFile2 = reinterpret_cast<_UnmapViewOfFile2>(GetProcAddress(lib, "UnmapViewOfFile2"))))
	{
		FreeLibrary(lib);

		return static_cast<bool>(unmapViewOfFile2(m_hProcess, remoteAddress, 0));
	}
	else
		CreateRemoteThread(m_hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(UnmapViewOfFile), const_cast<LPVOID>(remoteAddress), NULL, NULL);

	return true;
}

DWORD MemEx::GetProcessIdByName(const TCHAR* processName)
{
	const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
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

DWORD MemEx::GetProcessIdByWindow(const TCHAR* windowName, const TCHAR* className)
{
	DWORD dwProcessId;
	GetWindowThreadProcessId(FindWindow(className, windowName), &dwProcessId);

	return dwProcessId;
}

uintptr_t MemEx::GetModuleBase(const TCHAR* const moduleName, DWORD* const pModuleSize) const { return MemEx::GetModuleBase(m_dwProcessId, moduleName, pModuleSize); }

uintptr_t MemEx::GetModuleBase(const DWORD dwProcessId, const TCHAR* const moduleName, DWORD* const pModuleSize)
{
	struct ModuleInfo { const TCHAR* const name; uintptr_t base; DWORD* const size; };
	ModuleInfo mi = { moduleName, NULL, pModuleSize};

	EnumModules(dwProcessId,
		[](MODULEENTRY32& me, void* param)
		{
			ModuleInfo* mi = static_cast<ModuleInfo*>(param);
			std::transform(std::begin(me.szModule), std::end(me.szModule), me.szModule, tolower);

			TCHAR moduleNameLowerCase[MAX_MODULE_NAME32 + 1] = { TEXT('\0') };
			if(mi->name)
				std::transform(mi->name, mi->name + lstrlen(mi->name) + 1, moduleNameLowerCase, tolower);
			
			if ((mi->name) ? (!lstrcmp(me.szModule, moduleNameLowerCase)) : (lstrstr(me.szModule, TEXT(".exe")) != nullptr))
			{
				mi->base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
				if(mi->size)
					*mi->size = me.modBaseSize;
				return false;
			}
			return true; 
		}, &mi);

	return mi.base;
}

//https://github.com/Nomade040/length-disassembler
size_t MemEx::GetInstructionLength(const uintptr_t address)
{
	uint8_t buffer[X86_MAXIMUM_INSTRUCTION_LENGTH];
	if (!Read(address, buffer, X86_MAXIMUM_INSTRUCTION_LENGTH))
		return 0;

	size_t offset = 0;
	bool operandPrefix = false, addressPrefix = false, rexW = false;
	uint8_t* b = (uint8_t*)(buffer);

	//Parse legacy prefixes & REX prefixes
#if UINTPTR_MAX == UINT64_MAX
	for (int i = 0; i < 14 && findByte(prefixes, sizeof(prefixes), *b) || (R == 4); i++, b++)
#else
	for (int i = 0; i < 14 && findByte(prefixes, sizeof(prefixes), *b); i++, b++)
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

void MemEx::EnumModules(const DWORD processId, bool (*callback)(MODULEENTRY32& me, void* param), void* param)
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
void MemEx::AOBToPattern(const char* const AOB, std::string& pattern, std::string& mask)
{
	if (!AOB)
		return;

	auto ishex = [](const char c) -> bool { return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F'); };
	auto hexchartoint = [](const char c) -> uint8_t { return (c >= 'A') ? (c - 'A' + 10) : (c - '0'); };

	const char* bytes = AOB;
	for (; *bytes != '\0'; bytes++)
	{
		if (ishex(*bytes))
			pattern += static_cast<char>((ishex(*(bytes + 1))) ? hexchartoint(*bytes) | (hexchartoint(*(bytes++)) << 4) : hexchartoint(*bytes)), mask += 'x';
		else if (*bytes == '?')
			pattern += '\x00', mask += '?', (*(bytes + 1) == '?') ? (bytes++) : (bytes);
	}
}

DWORD MemEx::GetPageSize()
{
	SYSTEM_INFO si;
	GetSystemInfo(&si);

	return si.dwPageSize;
}

HANDLE MemEx::CreateSharedMemory(const size_t size) { return CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, static_cast<DWORD>(static_cast<uint64_t>(size) >> 32), static_cast<DWORD>(size & 0xFFFFFFFF), nullptr); }

HANDLE MemEx::AllocateSharedMemory(const size_t size, PVOID& localView, PVOID& remoteView) const
{
	HANDLE hFileMapping = CreateSharedMemory(size);
	if (hFileMapping)
	{
		localView = MapLocalViewOfFile(hFileMapping);
		remoteView = MapRemoteViewOfFile(hFileMapping);
	} 
	
	return hFileMapping;
}

bool MemEx::FreeSharedMemory(HANDLE hFileMapping, LPCVOID localView, LPCVOID remoteView) const { return UnmapLocalViewOfFile(localView) && UnmapRemoteViewOfFile(remoteView) && static_cast<bool>(CloseHandle(hFileMapping)); }

bool MemEx::Inject(const TCHAR* const dllPath)
{
	LPVOID lpAddress = NULL; HANDLE hThread = NULL;
	return (lpAddress = VirtualAllocEx(m_hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) &&
		WriteProcessMemory(m_hProcess, lpAddress, dllPath, (lstrlen(dllPath) + 1) * sizeof(TCHAR), nullptr) &&
		(hThread = CreateRemoteThreadEx(m_hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibrary), lpAddress, NULL, NULL, NULL)) &&
		WaitForSingleObject(hThread, INFINITE) &&
		VirtualFreeEx(m_hProcess, lpAddress, 0x1000, MEM_FREE);
}

//Inspired by https://github.com/cheat-engine/cheat-engine/blob/ac072b6fae1e0541d9e54e2b86452507dde4689a/Cheat%20Engine/ceserver/native-api.c
void MemEx::PatternScanImpl(std::atomic<uintptr_t>& address, std::atomic<size_t>& finishCount, const uint8_t* const pattern, const char* const mask, uintptr_t start, const uintptr_t end, const DWORD protect) const
{
	MEMORY_BASIC_INFORMATION mbi;
	uint8_t buffer[4096];
	const size_t patternSize = strlen(mask);

	while (!address.load() && start < end && VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(start), &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		if (mbi.Protect & protect)
		{
			for (; start < reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize; start += 4096)
			{
				SIZE_T bufferSize;
				if (!ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(start), buffer, 4096, &bufferSize))
					break;

				const uint8_t* bytes = buffer;
				for (size_t i = 0; i < bufferSize - patternSize; i++)
				{
					for (size_t j = 0; j < patternSize; j++)
					{
						if (!(mask[j] == '?' || bytes[j] == pattern[j]))
							goto byte_not_match;
					}

					address = start + i; //Found match
					finishCount++; //Increase finish count
					return;
				byte_not_match:
					bytes++;
				}
			}
		}

		start = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
	}

	finishCount++;
}

void MemEx::FindCodeCaveImpl(std::atomic<uintptr_t>& address, std::atomic<size_t>& finishCount, const size_t size, uintptr_t start, const uintptr_t end, const DWORD protect) const
{
	MEMORY_BASIC_INFORMATION mbi;
	uint8_t buffer[4096];
	size_t count = 0;

	while (!address.load() && start < end && VirtualQueryEx(m_hProcess, reinterpret_cast<LPCVOID>(start), &mbi, sizeof(MEMORY_BASIC_INFORMATION)))
	{
		if (mbi.Protect & protect)
		{
			while(start < reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize)
			{
				SIZE_T bufferSize;
				if (!ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(start), buffer, 4096, &bufferSize))
					break;

				uint8_t* b = buffer, lastByte = *b;
				while (b < buffer + bufferSize)
				{
					if (*b++ == lastByte)
					{
						if (++count == size)
						{
							address = start + (b - buffer) - count; //Found match
							finishCount++; //Increase finish count
							return;
						}
					}
					else
						count = 0;
				}
			}
		}

		start = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
	}

	finishCount++;
}

void* MemEx::CallImpl(const CConv cConv, const bool isReturnFloat, const bool isReturnDouble, const size_t returnSize, const uintptr_t functionAddress, std::vector<Arg>& args)
{
	size_t returnOffset = 0;
#ifdef _WIN64
	uint8_t* buffer = m_thisMappedView + 35;
	size_t offset = static_cast<size_t>(62) + (isReturnFloat || isReturnDouble) ? 6 : 4 + returnSize > 8 ? 4 : 0;

	//Calculate offset(arguments)
	size_t paramCount = 0;
	for (auto arg : args)
	{
		if (paramCount <= 4)
			offset += (arg.isFloat) ? 6 : 10;
		else if (arg.size <= 8)
			offset += 11;
		else
			offset += 5;
	}

	//mov r15, m_targetMappedView
	PLACE2(0xBF49); PLACE8(m_targetMappedView);

	if (returnSize > 8) // sub rsp, ((returnSize >> 4) + 1) * 8)
		{ PLACE1(0x48); PLACE2(0xEC81); PLACE4(((returnSize >> 4) + 1) * 8); }

	//Handle parameters
	uint16_t intMovOpcodes[4] = { 0xB948, 0xBA48, 0xB849, 0xB949 };
	paramCount = 0;
	for (auto arg : args)
	{
		if (returnSize > 8 && cConv == CConv::THIS_PTR_RET_SIZE_OVER_8 && paramCount == 1)
			{ PLACE1(0x49); PLACE2(0x8F8D); PLACE4(offset); returnOffset = offset; }
		else if(returnSize > 8 && cConv != CConv::THIS_PTR_RET_SIZE_OVER_8 && paramCount == 0)
			{ PLACE1(0x49); PLACE2(0x978D); PLACE4(offset); returnOffset = offset;  }
		else if (paramCount < 4)
		{
			if (arg.isFloat)
			{
				memcpy(m_thisMappedView + offset, arg.data, arg.size);
				PLACE4(0x7E0F41F3); PLACE1(0x47 + 0x8 * paramCount); PLACE1(offset); // movq xmm(paramCount), qword ptr ds:[r15 + offset]
				offset += arg.size;
			}
			else if(arg.immediate && arg.size <= 8)
				{ PLACE2(intMovOpcodes[paramCount]); PLACE8(0); memcpy(buffer - 8, arg.data, arg.size); /*mov (rcx,rdx,r8,r9), arg.data*/ }
			else
			{
				memcpy(m_thisMappedView + offset, arg.data, arg.size);
				PLACE2(intMovOpcodes[paramCount]); PLACE8(m_targetMappedView + offset);
				offset += arg.size;
			}
		}
		else if (arg.size <= 8)
			{ PLACE2(0xB848); PLACE8(0); memcpy(buffer - 8, arg.data, arg.size); PLACE1(0x50); }
		else
		{
			memcpy(m_thisMappedView + offset, arg.data, arg.size);
			PLACE1(0x49); PLACE2(0x478D); PLACE1(offset); PLACE1(0x50);
			offset += arg.size;
		}

		paramCount++;
	}
	
	CALL_ABSOLUTE(functionAddress);

	if (isReturnFloat || isReturnDouble) //movaps xmmword ptr ds:[r15 + offset], xmm0
		{ PLACE1(0x66); PLACE4(0x47D60F41); }
	else //mov qword ptr ds:[r15 + offset], rax
		{ PLACE1(0x49); PLACE2(0x4789); }

	PLACE1(offset);

#else
	uint8_t* buffer = m_thisMappedView + 19;
	size_t offset = 19;

	//Calculate offset
	for (auto& arg : args)
		offset += (arg.immediate) ? (((arg.size > 4) ? arg.size >> 2 : 1) * 5) : 5;

	offset += ((cConv == CConv::_CDECL || cConv == CConv::DEFAULT && args.size()) ? 6 : 0) + 5 + 5; //stack cleanup + CALL + jump

	if (isReturnFloat || isReturnDouble) //Return value
		offset += 6; //float/double
	else if (returnSize <= 4 || returnSize > 8)
		offset += 5; //0-4, 9-...
	else //5-8
		offset += 10;

	//Handle parameters
	size_t nPushes = 0;
	int skipArgs[2]; skipArgs[0] = -1; skipArgs[1] = -1;
	auto pushArg = [&](Arg& arg)
	{
		if (arg.immediate)
		{
			size_t argNumPushes = (arg.size > 4 ? arg.size >> 2 : 1);
			nPushes += argNumPushes;
			for (size_t j = 0; j < argNumPushes; j++)
				{ PUSH4(*reinterpret_cast<const uint32_t*>(static_cast<const uint8_t*>(arg.data) + (argNumPushes - 1) * 4 - (j * 4))); }
		}
		else
		{
			memcpy(m_thisMappedView + offset, arg.data, arg.size);

			arg.volatileBuffer = m_thisMappedView + offset;
			PUSH4(m_targetMappedView + offset); offset += arg.size;
			nPushes++;
		}
	};

	if (cConv == CConv::_FASTCALL)
	{
		for (size_t i = 0; i < args.size(); i++)
		{
			if (args[i].size <= 4 || args[i].isString)
			{
				if (skipArgs[0] == -1)
					skipArgs[0] = i;
				else if (skipArgs[1] == -1)
					skipArgs[1] = i;
				else
					break;
			}
		}

		for (size_t i = 0; i < 2; i++)
		{
			if (skipArgs[i] != -1)
			{
				PUSH1(static_cast<uint8_t>((i == 0) ? 0xB9 : 0xBA)); // mov ecx|edx, value

				if (args[skipArgs[i]].isString)
				{
					memcpy(m_thisMappedView + offset, args[skipArgs[i]].data, args[skipArgs[i]].size);
					PLACE4(m_targetMappedView + offset); offset += args[skipArgs[i]].size;
				}
				else
					{ PLACE4(*static_cast<const uint32_t*>(args[skipArgs[i]].data)); }
			}
		}
	}
	else if (cConv == CConv::_THISCALL)
	{
		if (args.size() < 1)
			return 0;

		skipArgs[0] = 0;
		PLACE1(0xB9); PLACE4(*static_cast<const uint32_t*>(args[0].data)); // mov ecx, this
	}

	for (int i = args.size() - 1; i >= 0; i--)
	{
		if (skipArgs[0] == i || skipArgs[1] == i)
			continue;

		pushArg(args[i]);
	}

	//Handle the return value greater than 8 bytes. 
	if (returnSize > 8) //Push pointer to buffer that the return value will be copied to.
		{ PUSH4(m_targetMappedView + offset + ((cConv == CConv::_CDECL && nPushes) ? 6 : 0)); }

	CALL_RELATIVE(m_targetMappedView + (buffer - m_thisMappedView), functionAddress);

	//Clean up the stack if the calling convention is cdecl
	if ((cConv == CConv::_CDECL || cConv == CConv::DEFAULT) && nPushes)
		{ PLACE2(0xC481); PLACE4(nPushes * 4); }

	//Handle the return value less or equal to eight bytes
	if (isReturnFloat) //ST(0) ; mov dword ptr ds:[Address], ST(0)
		{ PLACE2(0x1DD9); PLACE4(m_targetMappedView + offset); }
	else if (isReturnDouble) //ST(0) ; mov qword ptr ds:[Address], ST(0)
		{ PLACE2(0x1DDD); PLACE4(m_targetMappedView + offset); }
	else if (returnSize <= 4) //EAX ; mov dword ptr ds:[Address], eax
		{ PLACE1(0xA3); PLACE4(m_targetMappedView + offset); }
	else if (returnSize <= 8) //EAX:EDX
	{
		//mov dword ptr ds:[Address], eax
		PLACE1(0xA3); PLACE4(m_targetMappedView +  offset);

		//mov dword ptr ds:[Address], edx
		PLACE2(0x1589); PLACE4(m_targetMappedView +  offset + 5);
	}
#endif
	
	//Place jump. When the target thread finishes its task, go into wait mode..
	PLACE1(0xE9); PLACE4(m_thisMappedView - buffer - 4);

	//Resume execution of target thread
	SignalObjectAndWait(m_hEvent1, m_hEvent2, INFINITE, FALSE);
	
	for (auto& arg : args)
	{
		if (!arg.constant && !arg.immediate)
			memcpy(const_cast<void*>(arg.data), arg.volatileBuffer, arg.size);
	}

	return m_thisMappedView + (returnOffset ? returnOffset : offset);
}

bool MemEx::SetupRemoteThread()
{
	if (m_hThread)
		return true;

	if(!m_hProcess || !m_hFileMapping && !(m_hFileMapping = CreateSharedMemory(m_numPages * dwPageSize)) || !(m_thisMappedView = reinterpret_cast<uint8_t*>(MapLocalViewOfFile(m_hFileMapping))) || !(m_targetMappedView = reinterpret_cast<uint8_t*>(MapRemoteViewOfFile(m_hFileMapping))))
		return false;

	//Creates handles to event objects that are valid on this process
	if (!(m_hEvent1 = CreateEventA(nullptr, FALSE, FALSE, nullptr)) || !(m_hEvent2 = CreateEventA(nullptr, FALSE, FALSE, nullptr)))
		return false;

	//Duplicate handles to the previously created event objects that will be valid on the target process
	if (!DuplicateHandle(GetCurrentProcess(), m_hEvent1, m_hProcess, &m_hEventDuplicate1, NULL, FALSE, DUPLICATE_SAME_ACCESS) || !DuplicateHandle(GetCurrentProcess(), m_hEvent2, m_hProcess, &m_hEventDuplicate2, NULL, FALSE, DUPLICATE_SAME_ACCESS))
		return false;

	uint8_t* buffer = m_thisMappedView;

#ifdef _WIN64
	//Theoratically the size of a HANDLE is 8 bytes but I've never seen one use more than 4 bytes.
	PLACE4(0x28EC8348); //Allocate shadow space & perform stack alignment ; sub rsp, 0x28
	PLACE1(0xB9); PLACE4(reinterpret_cast<uintptr_t>(m_hEventDuplicate2)); // mov edx, m_hEventDuplicate2
	PLACE1(0xBA); PLACE4(reinterpret_cast<uintptr_t>(m_hEventDuplicate1)); // mov ecx, m_hEventDuplicate1
	PLACE2(0xB841); PLACE4(INFINITE); // mov r8d, INFINITE
	PLACE1(0x45); PLACE2(0xC933); // xor r9d, r9d
	CALL_ABSOLUTE(SignalObjectAndWait);
#else
	PUSH1(0);
	PUSH1(0xFF); // INIFITE(-1)
	PUSH4(m_hEventDuplicate1);
	PUSH4(m_hEventDuplicate2);
	CALL_RELATIVE(m_targetMappedView + (buffer - m_thisMappedView), SignalObjectAndWait);
#endif

	if (!(m_hThread = CreateRemoteThreadEx(m_hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(m_targetMappedView), nullptr, 0, nullptr, nullptr)))
		return false;

	//Wait for the created thread to signal m_hEvent2, so it will be set to an unsignaled state.
	if (WaitForSingleObject(m_hEvent2, INFINITE) == WAIT_FAILED)
	{
		m_hThread = NULL;
		return false;
	}

	return true;
}

void MemEx::DeleteRemoteThread()
{
	if (!m_hThread)
		return;

#ifdef _WIN64
	m_thisMappedView[31] = static_cast<uint8_t>(0xC3); //ret
#else
	m_thisMappedView[19] = static_cast<uint8_t>(0xC3); //ret

#endif

	SetEvent(m_hEvent1);
	Sleep(1);
	
	CloseHandle(m_hEvent1);
	CloseHandle(m_hEvent2);

	DuplicateHandle(m_hProcess, m_hEventDuplicate1, NULL, NULL, NULL, FALSE, DUPLICATE_CLOSE_SOURCE);
	DuplicateHandle(m_hProcess, m_hEventDuplicate2, NULL, NULL, NULL, FALSE, DUPLICATE_CLOSE_SOURCE);

	CloseHandle(m_hThread);
	m_hThread = NULL;
}