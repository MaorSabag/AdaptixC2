#pragma once

#if defined(BUILD_SVC)
char* getServiceName();
#endif

char* getProfile();

unsigned int getProfileSize();

int isIatHidingEnabled();

int isBofStompEnabled();

char* getBofStompDll();
char* getBofStompDllAsync();

int getBofStompMethod();