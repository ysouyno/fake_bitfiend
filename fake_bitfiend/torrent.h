#ifndef TORRENT_H
#define TORRENT_H

#include <pthread.h>
#include "list.h"
#include "tracker_connection.h"
#include "bencode.h"

#define DEFAULT_PRIORITY 3

typedef enum
{
	TORRENT_STATE_LEECHING,
	TORRENT_STATE_SEEDING,
	TORRENT_STATE_PAUSED
}torrent_state_t;

typedef enum
{
	PIECE_STATE_NOT_REQUESTED,
	PIECE_STATE_REQUESTED,
	PIECE_STATE_HAVE
}piece_state_t;

typedef struct torrent
{
	dict_t *pieces;
	unsigned piece_len;
	list_t *files;
	char info_hash[20];
	char *announce;
	char *comment;
	char *created_by;
	uint32_t create_date;
	pthread_t tracker_thread;
	struct
	{
		torrent_state_t state;
		char *piece_states;
		list_t *peer_connections;
		unsigned priority;   /* [0-6] */
		float progress;      /* [0-1] */
		float upspeed;       /* bits/sec */
		float downspeed;     /* bits/sec */
		unsigned uploaded;   /* bytes */
		unsigned downloaded; /* bytes */
		bool completed;
	}sh;
	pthread_mutex_t sh_lock;
}torrent_t;

torrent_t *torrent_init(bencode_obj_t *meta, const char *destdir);
void torrent_free(torrent_t *torrent);
unsigned torrent_left_to_download(torrent_t *torrent);
unsigned char *torrent_make_bitfield(const torrent_t *torrent);
bool torrent_sha1_verify(const torrent_t *torrent, unsigned index);

#endif
