#ifndef SHA1_H
#define SHA1_H

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <string>

#pragma comment(lib, "ws2_32.lib")

#define DIGEST_LEN 20

int sha1_compute(const char *msg, size_t len, char digest[DIGEST_LEN]);

#endif
