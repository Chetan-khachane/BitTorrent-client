#pragma once
#define WIN32_LEAN_AND_MEAN  
#pragma comment(lib, "Ws2_32.lib")
#include <windows.h>
#include <wincrypt.h>

bool sha1_wincrypt(
    const unsigned char* data,
    DWORD dataLen,
    unsigned char out[20]
);