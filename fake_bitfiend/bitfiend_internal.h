#ifndef BITFIEND_INTERNAL_H
#define BITFIEND_INTERNAL_H

#include <pthread.h>
#include "torrent.h"

torrent_t *bitfiend_assoc_peer(peer_conn_t *peer, char infohash[20]);
void bitfiend_add_unassoc_peer(pthread_t thead);

#endif
