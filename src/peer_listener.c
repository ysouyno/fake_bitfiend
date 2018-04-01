#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include "peer_listener.h"
#include "log.h"
#include "peer.h"
#include "peer_connection.h"
#include "bitfiend_internal.h"

#define LISTEN_QUEUE_SIZE 50

#if defined(_MSC_VER)

static int bind_listener(const uint16_t port)
{
	int sockfd = 0;
	struct addrinfo hints, *listener, *head;

	memset(&hints, 0, sizeof(hints));

	// accept will fail and return error 10014, because IPv6 struct size is too large
	// so set ai_family as AF_INET, please check below for more information
	// https://stackoverflow.com/questions/31658944/calling-accept-causes-wsaefault-10014-bad-address
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;

	char port_str[5];
	snprintf(port_str, sizeof(port_str), "%04u", port);
	port_str[4] = '\0';

	WORD ver = MAKEWORD(2, 2);
	WSADATA wsa;

	int rt = WSAStartup(ver, &wsa);
	if (rt != 0)
    {
      printf("WSAStartup failed with error: %d\n", rt);
      return -1;
    }

	rt = getaddrinfo(NULL, port_str, &hints, &head);
	if (rt != 0)
		goto fail_getaddrinfo;

	for (listener = head; listener; listener = listener->ai_next)
    {
      if ((sockfd = socket(listener->ai_family, listener->ai_socktype, listener->ai_protocol)) < 0)
        {
          continue;
        }

      int itrue = 1;
      if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&itrue, sizeof(int)) < 0)
        {
          closesocket(sockfd);
          continue;
        }

      if (bind(sockfd, listener->ai_addr, listener->ai_addrlen) < 0)
        {
          closesocket(sockfd);
          continue;
        }

      break;
    }

	if (!listener)
		goto fail_bind;

	freeaddrinfo(head);
	log_printf(LOG_LEVEL_INFO, "Successfully bound peer listener socket (fd: %d) on port %hd\n",
             sockfd, port);
	return sockfd;

 fail_bind:
	freeaddrinfo(head);
 fail_getaddrinfo:
	return -1;
}

#else

static int bind_listener(const uint16_t port)
{
  int sockfd;
  struct addrinfo hints, *listener, *head;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  char port_str[5];
  snprintf(port_str, sizeof(port_str), "%04u", port);
  port_str[4] = '\0';

  if(getaddrinfo(NULL, port_str, &hints, &head) < 0)
    goto fail_getaddrinfo;

  for(listener = head; listener; listener = listener->ai_next) {
    if((sockfd = socket(listener->ai_family, listener->ai_socktype,
                        listener->ai_protocol)) < 0) {
      continue;
    }

    int itrue = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &itrue, sizeof(int)) < 0) {
      close(sockfd);
      continue;
    }

    if(bind(sockfd, listener->ai_addr, listener->ai_addrlen) < 0) {
      close(sockfd);
      continue;
    }

    break;
  }

  if(!listener)
    goto fail_bind;

  freeaddrinfo(head);
  log_printf(LOG_LEVEL_INFO, "Successfully bound peer listener socket (fd: %d) on port %hd\n",
             sockfd, port);
  return sockfd;

 fail_bind:
  freeaddrinfo(head);
 fail_getaddrinfo:
  return -1;
}

#endif

static void peer_listen_cleanup(void *arg)
{
	int sockfd = *(int*)arg;
	log_printf(LOG_LEVEL_INFO, "Closing peer listener socket (fd: %d)\n", sockfd);
#if defined(_MSC_VER)
	closesocket(sockfd);
#else
  close(sockfd);
#endif
}

static int create_peer_connection(peer_t *peer, int sockfd)
{
	peer_arg_t *arg = (peer_arg_t *)malloc(sizeof(peer_arg_t));
	if (!arg)
		goto fail_alloc;

	arg->has_torrent = false;
	arg->has_sockfd = true;
	arg->sockfd = sockfd;
	arg->peer = *peer;

	pthread_t newthread;
	if (peer_connection_create(&newthread, arg))
		goto fail_create;

	bitfiend_add_unassoc_peer(newthread);

	free(peer);
	return 0;

 fail_create:
	free(arg);
 fail_alloc:
	free(peer);
	log_printf(LOG_LEVEL_ERROR, "Failed to create peer thread\n");
	return -1;
}

static void *peer_listen(void *arg)
{
	int sockfd;
	char errbuff[64];

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	if ((sockfd = bind_listener(*(const uint16_t*)arg)) < 0)
		goto fail_bind;

	if (listen(sockfd, LISTEN_QUEUE_SIZE) < 0)
		goto fail_listen;

	pthread_cleanup_push(peer_listen_cleanup, (void*)&sockfd);

	while (true)
    {
      log_printf(LOG_LEVEL_INFO, "Listening for incoming peer connections...\n");

      struct sockaddr peersock;
      socklen_t len = sizeof(peersock);
      int peer_sockfd;

      pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
      /* Cancellation point */
      peer_sockfd = accept(sockfd, &peersock, &len);
      pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

      if (peer_sockfd < 0)
        {
          // printf("accept error: %d\n", WSAGetLastError());
          continue;
        }

      log_printf(LOG_LEVEL_INFO, "Peer connection accepted (sockfd: %d)\n", peer_sockfd);

      peer_t *peer = (peer_t *)malloc(sizeof(peer_t));
      memset(peer->peer_id, 0, sizeof(peer->peer_id));
      peer->addr.sa = peersock;

      create_peer_connection(peer, peer_sockfd);
    }

	pthread_cleanup_pop(0);

 fail_listen:
 fail_bind:
	if (errno)
    {
      // strerror_s(errbuff, sizeof(errbuff), errno);
      // log_printf(LOG_LEVEL_ERROR, "%s\n", errbuff);
    }
	pthread_exit(NULL);

	return NULL;
}

int peer_listener_create(pthread_t *thread, const uint16_t *port)
{
	if (pthread_create(thread, NULL, peer_listen, (void*)port))
		goto fail_create_thread;

	return 0;

 fail_create_thread:
	log_printf(LOG_LEVEL_ERROR, "Failed to create peer listener thread\n");
	return -1;
}
