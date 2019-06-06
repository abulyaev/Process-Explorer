#define _CRT_SECURE_NO_WARNINGS
#ifndef UNICODE
#define UNICODE
#endif

#define errors 0 // 1 to enable it



#include <windows.h>
#include <stdio.h>
#include <string>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <Aclapi.h>
#include <WinError.h>
#include <Sddl.h>
#include <tchar.h>
//#include <DbgHelp.h>
#include <winnt.h>
#include<Imagehlp.h>
#include <vector>
#include <algorithm>

#pragma comment(lib, "Imagehlp.lib")

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2
/* типы функций для подргузки из длл */



typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

/* объявление функций для однозначного экспорта */
extern "C"
{
	__declspec(dllexport) int __cdecl GetHandlesByPID(int _pid, const wchar_t ** result, unsigned int size);
	__declspec(dllexport) int __cdecl GetProcessIntegrityLevel(int _pid);
	__declspec(dllexport) int __cdecl GetFileIntegrityLevel(char* filepath);
	__declspec(dllexport) int __cdecl SetFileIntegrityLevel(int level, char* FilePath);
	__declspec(dllexport) int __cdecl SetProcessIntegrityLevel(int PID, int NewProcessIntegrityLevel);
	__declspec(dllexport) int __cdecl GetASLR(char* filepath);
	__declspec(dllexport) int __cdecl GetDEP(char* filepath);
}

#define EXPORT_VOID __declspec(dllexport) void __cdecl
#define EXPORT_INT __declspec(dllexport) int __cdecl
#define EXPORT_STRING  __declspec(dllexport) std::string __cdecl

/*системные структуры*/
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;



typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

/*подгрузка ф-ий из ntdll*/
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

/*получение доступных хэндлов для процесса, рез-т в result -> C#*/
EXPORT_INT GetHandlesByPID(int _pid, const wchar_t ** result, unsigned int size)
{
	std::wstringstream output;
	std::wstring tmp_str;
	/*поулчаем С-функции из библиотек*/
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)
		GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)
		GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)
		GetLibraryProcAddress("ntdll.dll", "NtQueryObject");
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	ULONG pid;
	HANDLE processHandle;
	ULONG i;

	pid = _pid;
	/*открываем процесс*/
	if (!(processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid)))
	{
		return 0;
	}

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	/* NtQuerySystemInformation won't give us the correct buffer size,
	so we guess by doubling the buffer size. */
	while ((status = NtQuerySystemInformation(
		SystemHandleInformation,
		handleInfo,
		handleInfoSize,
		NULL
	)) == STATUS_INFO_LENGTH_MISMATCH)
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

	/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
	if (!NT_SUCCESS(status))
	{
		return 0;

	}

	/*для всех хэндлов проверяем их принадлежность по пиду*/
	for (i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;

		/* Check if this handle belongs to the PID the user specified. */
		if (handle.ProcessId != pid)
			continue;
		/*если хэндл октрыт процессом, получить его информацию*/

		/* Duplicate the handle so we can query it. */
		if (!NT_SUCCESS(NtDuplicateObject(
			processHandle,
			(HANDLE)handle.Handle,
			GetCurrentProcess(),
			&dupHandle,
			0,
			0,
			0
		)))
		{
#if errors == 1 /*вывод ошибки только при дефайне еррор, выключено и не выводится*/
			output << "[0x" << std::hex << handle.Handle << "]" << " error!\n";
#endif

			//printf("[%#x] Error!\n", handle.Handle);
			continue;
		}

		/* Query the object type. */
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
		)))
		{

#if errors == 1 /*аналогично*/
			output << "[0x" << std::hex << handle.Handle << "]" << " error!\n";
#endif
			// printf("[%#x] Error!\n", handle.Handle);
			CloseHandle(dupHandle);
			continue;
		}

		/* Query the object name (unless it has an access of
		0x0012019f, on which NtQueryObject could hang. */
		if (handle.GrantedAccess == 0x0012019f)
		{/*попытка получить больше информации, в данном случае - какой-либо тип хэндла*/
			tmp_str = objectTypeInfo->Name.Buffer;
			output << "[0x" << std::hex << handle.Handle << "]" << tmp_str << " Unknown\n";
			/* We have the type, so display that. */

			/*
			printf(
			"[%#x] %.*S: (did not get name)\n",
			handle.Handle,
			objectTypeInfo->Name.Length / 2,
			objectTypeInfo->Name.Buffer
			);
			*/
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}

		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectNameInformation,
			objectNameInfo,
			0x1000,
			&returnLength
		)))
		{
			/* Reallocate the buffer and try again. */
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(
				dupHandle,
				ObjectNameInformation,
				objectNameInfo,
				returnLength,
				NULL
			)))
			{
				/*аналогично: тип хэндла*/
				tmp_str = objectTypeInfo->Name.Buffer;
				output << "[0x" << std::hex << handle.Handle << "]" << tmp_str << " Unknown\n";
				/* We have the type name, so just display that. */
				/*
				printf(
				"[%#x] %.*S: (could not get name)\n",
				handle.Handle,
				objectTypeInfo->Name.Length / 2,
				objectTypeInfo->Name.Buffer
				);
				*/
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}

		/* Cast our buffer into an UNICODE_STRING. */
		objectName = *(PUNICODE_STRING)objectNameInfo;

		/* Print the information! */
		if (objectName.Length)
		{
			/*аналогично:
			у объекта удалось получить и тип и имя хндла - выводим все*/
			tmp_str = objectTypeInfo->Name.Buffer;
			output << "[0x" << std::hex << handle.Handle << "]" << tmp_str << " : ";
			tmp_str = objectName.Buffer;
			output << tmp_str << " \n";
			/* The object has a name. */
			/*
			printf(
			"[%#x] %.*S: %.*S\n",
			handle.Handle,
			objectTypeInfo->Name.Length / 2,
			objectTypeInfo->Name.Buffer,
			objectName.Length / 2,
			objectName.Buffe+
			"[%#x] %.*S: (unnamed)\n",
			handle.Handle,
			objectTypeInfo->Name.Length / 2,
			objectTypeInfo->Name.Buffer
			);
			*/
		}

		free(objectTypeInfo);
		free(objectNameInfo);
		CloseHandle(dupHandle);
	}

	free(handleInfo);
	CloseHandle(processHandle);

	static auto x = output.str(); /*wstringstring -> wstring*/
	*result = x.data(); /* выделение памяти для прямого досутпа по указателю*/
	return 0;
}

/* ф-я получения уровня целостности,
возвращает число, соотв-щее текущему уровню*/
EXPORT_INT GetProcessIntegrityLevel(int _pid)
{
	HANDLE hToken;
	HANDLE hProcess;

	DWORD dwLengthNeeded;
	DWORD dwError = ERROR_SUCCESS;

	PTOKEN_MANDATORY_LABEL pTIL = NULL;
	LPWSTR pStringSid;
	DWORD dwIntegrityLevel;

	/*открываем процессом с ИД*/
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, _pid);
	/*открываем токен процесса*/
	if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		// Get the Integrity level.
		if (!GetTokenInformation(hToken, TokenIntegrityLevel,
			NULL, 0, &dwLengthNeeded))
		{
			/*куча всяких проверок*/
			dwError = GetLastError();
			if (dwError == ERROR_INSUFFICIENT_BUFFER)
			{
				pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0,
					dwLengthNeeded);
				if (pTIL != NULL)
				{
					/*получаем информацию токена, для сида*/
					if (GetTokenInformation(hToken, TokenIntegrityLevel,
						pTIL, dwLengthNeeded, &dwLengthNeeded))
					{
						/*извлекаем информацию из сида*/
						dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
							(DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
						/*определяем уровень цел-ти по маске, возвращаем рез-т*/
						if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID)
						{
							// Low Integrity
							return 1;
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
							dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID)
						{
							// Medium Integrity
							return 2;
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID)
						{
							// High Integrity
							return 3;
						}
						else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
						{
							// System Integrity
							return 4;
						}
					}
					LocalFree(pTIL);
				}
			}
		}
		CloseHandle(hToken);
	}
}

/* ф-я определения уровня целостности у файла */
/* вход - char -> вероятно, не будут работать русские пути*/
EXPORT_INT GetFileIntegrityLevel(char* filepath)
{
	int error;

	PSECURITY_DESCRIPTOR pSecDis = NULL;
	PACL pSACL = 0;
	/*считать дескриптор безопаснсоти файла*/
	error = GetNamedSecurityInfoA(filepath, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, &pSACL, &pSecDis);

	DWORD size;

#ifdef _UNICODE
	LPWSTR* strSecDis = new LPWSTR;
#else
	LPSTR* strSecDis = new LPSTR;
#endif

	/*сконвертировать Дескрипт Безоп в строку*/
	error = ConvertSecurityDescriptorToStringSecurityDescriptor(pSecDis, SDDL_REVISION_1, LABEL_SECURITY_INFORMATION, strSecDis, &size);

	DWORD IntegrityLevel = 0;
	/*определяем целостность по маске*/
	if (_tcsstr(*strSecDis, SDDL_ML_LOW))
		IntegrityLevel = 1;
	else if (_tcsstr(*strSecDis, SDDL_ML_HIGH))
		IntegrityLevel = 3;
	else if (_tcsstr(*strSecDis, SDDL_ML_SYSTEM))
		IntegrityLevel = 4;
	else IntegrityLevel = 2;

	return IntegrityLevel;
}

/*установить уровень целостности файла*/
EXPORT_INT SetFileIntegrityLevel(int level, char* FilePath)
{
	LPCTSTR strNewIntLevel;
	/*в соответствии с желаемым уровнем собрать стркоу*/
	switch (level)
	{
	case 1:
		strNewIntLevel = TEXT("S:(ML;;NW;;;LW)");
		break;

	case 2:
		strNewIntLevel = TEXT("S:(ML;;NW;;;ME)");
		break;

	case 3:
		strNewIntLevel = TEXT("S:(ML;;NW;;;HI)");
		break;

	default:
		return 0;
	}

	int error;

	/*строка в ДБ*/
	PSECURITY_DESCRIPTOR secDis;
	error = ConvertStringSecurityDescriptorToSecurityDescriptor(strNewIntLevel, SDDL_REVISION_1, &secDis, NULL);

	BOOL isSaclPresent;
	BOOL isSaclDefaulted;
	PACL pSACL;
	/*получить ук-ль на сацл*/
	error = GetSecurityDescriptorSacl(secDis, &isSaclPresent, &pSACL, &isSaclDefaulted);
	/*уст-ть сацл*/
	error = SetNamedSecurityInfoA(FilePath, SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION, 0, 0, 0, pSACL);
	return 0;
}

EXPORT_INT GetASLR(char* filepath)
{
	LOADED_IMAGE PE;
	MapAndLoad(filepath, 0, &PE, 1, 1);
	if (PE.FileHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
		return 1;
	else return 0;
}

EXPORT_INT GetDEP(char* filepath)
{
	LOADED_IMAGE PE;
	MapAndLoad(filepath, 0, &PE, 1, 1);
	if (PE.FileHeader->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		return 1;
	else return 0;
}
/*ф-я установки ур-ня целостности процесса*/
EXPORT_INT SetProcessIntegrityLevel(int PID, int NewProcessIntegrityLevel)
{
	HANDLE ProcHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, PID);
	if (ProcHandle == NULL)
		return GetLastError();

	HANDLE ProcSecToken;
	OpenProcessToken(ProcHandle, TOKEN_QUERY | TOKEN_ADJUST_DEFAULT, &ProcSecToken);

	int error = GetLastError();
	if (ProcSecToken == NULL || error == 5)
	{
		CloseHandle(ProcHandle);
		return error;
	}

	DWORD MLabel_size;
	GetTokenInformation(ProcSecToken, TokenIntegrityLevel, NULL, 0, &MLabel_size);

	error = GetLastError();
	if (error != ERROR_INSUFFICIENT_BUFFER && error != ERROR_SUCCESS)
	{
		CloseHandle(ProcSecToken);
		CloseHandle(ProcHandle);
		return error;
	}

	TOKEN_MANDATORY_LABEL* MLabel = (TOKEN_MANDATORY_LABEL*)malloc(MLabel_size);

	GetTokenInformation(ProcSecToken, TokenIntegrityLevel, MLabel, MLabel_size, &MLabel_size);

	error = GetLastError();
	if (error != ERROR_INSUFFICIENT_BUFFER && error != ERROR_SUCCESS)
	{
		free(MLabel);
		CloseHandle(ProcSecToken);
		CloseHandle(ProcHandle);
		return error;
	}

	DWORD dwIntegrityLevel = *GetSidSubAuthority(MLabel->Label.Sid, (DWORD)(UCHAR)*GetSidSubAuthorityCount(MLabel->Label.Sid) - 1);

	char* strSID = new char[30];

	ConvertSidToStringSidA(MLabel->Label.Sid, &strSID);

	switch (NewProcessIntegrityLevel)
	{
	case 1:
		NewProcessIntegrityLevel = SECURITY_MANDATORY_LOW_RID;
		break;
	case 2:
		NewProcessIntegrityLevel = SECURITY_MANDATORY_MEDIUM_RID;
		break;
	case 3:
		NewProcessIntegrityLevel = SECURITY_MANDATORY_HIGH_RID;
		break;
	case 4:
		NewProcessIntegrityLevel = SECURITY_MANDATORY_SYSTEM_RID;
		break;
	default:
		LocalFree(strSID);
		free(MLabel);
		CloseHandle(ProcSecToken);
		CloseHandle(ProcHandle);
		return 1;
	}

	char* strIntLevel = new char[7];

	_ltoa(dwIntegrityLevel, strIntLevel, 10);// ïåðåâîä äåéñòâóþùåãî óðîâíÿ öåëîñòíîñòè â ñòðîêó

	char* IntegrityLevelPtr = strstr(strSID, strIntLevel);// ïîèñê äåéñòâóþùåãî óðîâíÿ öåëîñòíîñòè â SID

	_ltoa(NewProcessIntegrityLevel, strIntLevel, 10);// ïåðåâîä çàïðàøèâàåìîãî óðîâíÿ öåëîñòíîñòè â ñòðîêó

	strcpy(IntegrityLevelPtr, strIntLevel);// çàìåíà óðîâíÿ öåëîñòíîñòè â SID

	ConvertStringSidToSidA(strSID, &(MLabel->Label.Sid));// ïåðåâîä SID â ÷èñëîâîå çíà÷åíèå

	SetTokenInformation(ProcSecToken, TokenIntegrityLevel, MLabel, MLabel_size);

	delete[] strIntLevel;
	LocalFree(strSID);
	free(MLabel);
	CloseHandle(ProcSecToken);
	CloseHandle(ProcHandle);
	return GetLastError();
}

/*можно пересобрать в ехе для отладки*/
void main()
{
	int p = 0;
	const wchar_t * res = nullptr;
	std::cin >> p;
	GetHandlesByPID(p, &res, 0);
}
/*целостности не мои*/
/*целостность может быть только понижена, в соответствии с процесс-хакером*/
