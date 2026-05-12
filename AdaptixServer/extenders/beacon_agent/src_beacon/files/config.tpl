#if defined(BUILD_SVC)
char* getServiceName()
{
	return (char*) SERVICE_NAME;
}
#endif

char* getProfile()
{
	return (char*) PROFILE;
}

unsigned int getProfileSize()
{
	return PROFILE_SIZE;
}

int isIatHidingEnabled()
{
#if defined(IAT_HIDING)
	return 1;
#else
	return 0;
#endif
}

int isBofStompEnabled()
{
#if defined(USE_BOF_STOMP)
	return 1;
#else
	return 0;
#endif
}

char* getBofStompDll()
{
#if defined(BOF_STOMP_DLL_NAME)
	return (char*) BOF_STOMP_DLL_NAME;
#else
	return (char*)"wmp.dll";
#endif
}

// getBofStompDllsAsync — devuelve el pool de DLLs async como array de char*.
// BOF_STOMP_DLL_NAME_ASYNC contiene los nombres separados por '|', p.ej.
// "xpsservices.dll|Hydrogen.dll|wmp.dll".  Los tokens se parsean en runtime
// usando un buffer estático; la función es idempotente (se puede llamar varias
// veces; el parse se hace solo la primera vez).
int getBofStompDllsAsync(const char*** outArray)
{
#if defined(BOF_STOMP_DLL_NAME_ASYNC)
    static const char* parsed[32];
    static int         count      = 0;
    static bool        initialised = false;
    static char        buf[512];

    if (!initialised) {
        initialised = true;
        const char* src = BOF_STOMP_DLL_NAME_ASYNC;
        int bpos = 0, idx = 0;
        parsed[idx++] = buf;
        for (int i = 0; src[i] && bpos < 510 && idx < 32; i++) {
            if (src[i] == '|') {
                buf[bpos++] = '\0';
                parsed[idx++] = buf + bpos;
            } else {
                buf[bpos++] = src[i];
            }
        }
        buf[bpos] = '\0';
        count = idx;
    }
    if (outArray) *outArray = parsed;
    return count;
#else
    static const char* fallback[] = { "xpsservices.dll", "Hydrogen.dll", "actxprxy.dll" };
    if (outArray) *outArray = fallback;
    return 1;
#endif
}

int getBofStompMethod()
{
#if defined(BOF_STOMP_METHOD)
	return BOF_STOMP_METHOD;
#else
	return 0;
#endif
}
