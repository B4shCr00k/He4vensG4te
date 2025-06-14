#pragma once
#include <Windows.h>

/*--------------------------------------------------------------------
  STRUCTURES
--------------------------------------------------------------------*/

typedef struct ret
{
	BYTE* buf;
	long filesize;
}ret;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);       \
    (p)->RootDirectory = r;                        \
    (p)->Attributes = a;                           \
    (p)->ObjectName = n;                           \
    (p)->SecurityDescriptor = s;                   \
    (p)->SecurityQualityOfService = NULL;          \
}

typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, * PLSA_UNICODE_STRING, UNICODE_STRING, * PUNICODE_STRING, * PUNICODE_STR;

typedef struct __CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;
