#pragma once
#include "adaptix.h"
#include "ApiLoader.h"

typedef struct _BOF_STOMP_CTX {
    HMODULE          hModule;       // Method 0: handle from LoadLibraryEx
    PVOID            mappedView;    // Method 1: base from NtMapViewOfSection
    SIZE_T           viewSize;      // Method 1: size of the mapped view
    int              method;        // 0 = LoadLibraryEx, 1 = NtCreateSection
    PVOID            textBase;      // address of .text inside this view
    SIZE_T           textSize;      // size of .text
    PVOID            savedBytes;    // saved copy of original .text content
    DWORD            savedSize;     // == textSize
    PVOID            pdataBase;     // address of .pdata inside this view
    DWORD            pdataSize;
    PVOID            savedPdata;    // saved copy of original .pdata
    DWORD            pdataCapacity; // max RUNTIME_FUNCTIONs that fit
    PVOID            moduleBase;    // == mappedView or hModule cast to PVOID
    BOOL             pdataStomped;
    PVOID            cursorBase;    // start of the region written for this BOF
    DWORD            cursorSize;    // bytes written for this BOF
    BOOL             inUse;
    BOOL             initialised;
    PVOID            fakeLdrEntry;  // Method 1: synthetic PEB LDR entry
    BOOL             pooled;        // TRUE = pertenece al pool, CleanupSections NO destruye
} BOF_STOMP_CTX;

BOF_STOMP_CTX* BofStompCreate(const char* sacrificialDll, int method);

// Release all resources owned by ctx and free the struct itself.
void BofStompDestroy(BOF_STOMP_CTX* ctx);
