#ifndef PEER_H
#define PEER_H

// #include <netinet/ip.h>
#include <WinSock2.h>
#include <WS2tcpip.h> // for sockaddr_in6

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
