#ifndef PEER_H
#define PEER_H

#if defined(_MSC_VER)
#include <WinSock2.h>
#include <WS2tcpip.h> // for sockaddr_in6
#else
#include <netinet/ip.h>
#endif

typedef struct peer
{
	char peer_id[20];
	union
	{
		struct sockaddr_storage sas;
		struct sockaddr sa;
		struct sockaddr_in sa_in;
		struct sockaddr_in6 sa_in6;
	}addr;
}peer_t;

#endif
