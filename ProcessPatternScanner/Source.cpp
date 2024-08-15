#include "MemoryHacker.h"
#include "SharedStuffLib.h"
#include <easylogging++.h>

INITIALIZE_EASYLOGGINGPP

#define PRODUCT_NAME L"ProcessPatternScanner"
#define DEFAULT_BUFLEN 512

int GetPattern(BYTE* aDest, SIZE_T cbDestLen, const WCHAR* wszcStr)
{
	DWORD Byte = { 0 };
	INT iStr = 0;
	INT iDest = 0;
	while (iStr < wcslen(wszcStr) && iDest < cbDestLen) {
		swscanf_s(wszcStr + iStr, L"%X", &Byte);
		aDest[iDest] = (BYTE)Byte;
		iStr += 3;
		iDest++;
	}
	return iDest;
}

void PrintPattern(BYTE* aPattern, SIZE_T cbPatternLen)
{
	puts("Pattern: ");
	for (int i = 0; i < cbPatternLen; i++) {
		printf("%02X ", aPattern[i]);
	}
	puts("");
}

void PrintPatternMatchesAddresses(
	LPCVOID pBaseOfDll,
	LPCVOID pBuffer,
	SIZE_T cbBufferLen,
	LPCVOID pPattern,
	SIZE_T cbPatternLen)
{
	for (int i = 0; i < cbBufferLen - cbPatternLen; i++) {
		if (memcmp((const char*)pBuffer + i, pPattern, cbPatternLen) == 0) {
			printf("%p\n", (const char*)pBaseOfDll + i);
		}
	}
}

/*F+F+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

  Args:     ProcessPatternScanner.exe <WindowName> <TargetModuleName> <Pattern>

-----------------------------------------------------------------F-F*/
int wmain(int argc, wchar_t* argv[])
{
	WCHAR* wszWindowName = NULL;
	WCHAR* wszTargetModuleName = NULL;
	HANDLE hProcess = { 0 };
	HMODULE hTargetModule = { 0 };
	MODULEINFO TargetModuleInfo = { 0 };
	void* pBuffer = NULL;
	size_t cbBufferLen = 0;
	size_t cbRead = { 0 };
	BYTE aPattern[DEFAULT_BUFLEN] = { 0 };
	size_t cbPatternLen = { 0 };

#ifdef NDEBUG
	ConfigureLoggers(PRODUCT_NAME, false);
#else
	ConfigureLoggers(PRODUCT_NAME, true);
#endif
	// Command line arguments receiving
	LOG_IF(argv[1] == NULL, FATAL) << "`WindowName` is not specified";
	LOG_IF(argv[2] == NULL, FATAL) << "`TargetModuleName` is not specified";
	LOG_IF(argv[3] == NULL, FATAL) << "`Pattern` is not specified";
	wszWindowName = argv[1];
	wszTargetModuleName = argv[2];
	cbPatternLen = GetPattern(aPattern, sizeof(aPattern), argv[3]);
	LOG(INFO) << "wszWindowName: '" << (const WCHAR*)wszWindowName << "'";
	LOG(INFO) << "wszTargetModuleName: '" << (const WCHAR*)wszTargetModuleName << "'";
#ifdef _DEBUG
	PrintPattern(aPattern, cbPatternLen);
#endif

	//	Searching for process and its target module
	hProcess = GetProcessByWindowName(wszWindowName);
	LOG_IF(hProcess == NULL, FATAL);
	hTargetModule = GetProcessTargetModule(hProcess, wszTargetModuleName);
	LOG_IF(hTargetModule == NULL, FATAL);
	GetModuleInformation(hProcess, hTargetModule, &TargetModuleInfo, sizeof(TargetModuleInfo));
	LOG(INFO) << "TargetModuleInfo.lpBaseOfDll: 0x" << std::hex << TargetModuleInfo.lpBaseOfDll;

	//	Reading process memory to buffer
	pBuffer = malloc(TargetModuleInfo.SizeOfImage);
	LOG_IF(pBuffer == NULL, FATAL);
	cbBufferLen = TargetModuleInfo.SizeOfImage;
	ReadProcessMemory(
		hProcess,
		TargetModuleInfo.lpBaseOfDll,
		pBuffer,
		TargetModuleInfo.SizeOfImage,
		&cbRead);
	LOG(INFO) << "Read from process (bytes count): " << std::dec << cbRead;

	//  Printing to stdout matched addresses
	PrintPatternMatchesAddresses(
		TargetModuleInfo.lpBaseOfDll,
		pBuffer,
		cbBufferLen,
		aPattern,
		cbPatternLen);

	//	Cleaning
	free(pBuffer);
	CloseHandle(hTargetModule);
	CloseHandle(hProcess);

	return 0;
}