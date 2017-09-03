#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include "peer_msg.h"
#include "log.h"
#include "peer_id.h"
#include "peer_connection.h"
#include "lbitfield.h"

int peer_send_buff(int sockfd, const char *buff, size_t len)
{
	long long tot_sent = 0;
	while (tot_sent < len)
	{
		long long sent = send(sockfd, buff, len - tot_sent, 0);
		if (sent < 0)
		{
			free((char *)buff);
			return -1;
		}

		tot_sent += sent;
		buff += sent;
	}

	return 0;
}

int peer_recv_buff(int sockfd, char *buff, size_t len)
{
	unsigned tot_recv = 0;
	long long nb;

	if (len == 0)
		return 0;

	do
	{
		assert(len - tot_recv > 0);

		nb = recv(sockfd, buff + tot_recv, len - tot_recv, 0);
		if (nb < 0)
		{
			// error 10060: A connection attempt failed because the connected party
			// did not properly respond after a period of time, or established connection
			// failed because connected host has failed to respond.
			// after commout setsockopt, will return error code 10054: An existing
			// connection was forcibly closed by the remote host.
			/*printf("recv error: %d, line: %d\n", WSAGetLastError(), __LINE__);*/
			return -1;
		}

		tot_recv += nb;
	} while (nb > 0 && tot_recv < len);

	if (tot_recv == len)
		return 0;
	else
		return -1;
}

int peer_recv_handshake(int sockfd, char outhash[20], char outpeerid[20], bool peer_id)
{
	const char *pstr = "BitTorrent protocol";
	unsigned char pstrlen = strlen(pstr);
	const char reserved[8] = { 0 };

	size_t bufflen = 1 + pstrlen + sizeof(reserved) + 20
		+ (peer_id ? sizeof(g_local_peer_id) : 0);

	char *buff = (char *)malloc(bufflen);
	if (peer_recv_buff(sockfd, buff, bufflen))
	{
		/*printf("peer_recv_buff error line: %d\n", __LINE__);*/
		free(buff);
		return -1;
	}

	off_t off = 0;
	if (buff[off] != pstrlen)
	{
		free(buff);
		return -1;
	}

	off++;
	if (strncmp(buff + off, pstr, pstrlen))
	{
		free(buff);
		return -1;
	}

	off += pstrlen;

	/*Skip checking the reserved bits for now*/
	off += 8;

	memcpy(outhash, buff + off, 20);
	if (peer_id)
	{
		off += 20;
		memcpy(outpeerid, buff + off, sizeof(g_local_peer_id));
	}

	free(buff);

	return 0;
}

int peer_send_handshake(int sockfd, char infohash[20])
{
	const char *pstr = "BitTorrent protocol";
	unsigned char pstrlen = strlen(pstr);
	const char reserved[8] = { 0 };

	size_t bufflen = 1 + pstrlen + sizeof(reserved) + 20 + sizeof(g_local_peer_id);

	off_t off = 0;
	char buff[HANDSHAKE_LEN] = { 0 };

	buff[0] = pstrlen;
	off++;

	memcpy(buff + off, pstr, pstrlen);
	off += pstrlen;
	assert(off == 20);

	memcpy(buff + off, reserved, sizeof(reserved));
	off += sizeof(reserved);
	assert(off == 28);

	memcpy(buff + off, infohash, 20);

	off += 20;
	memcpy(buff + off, g_local_peer_id, sizeof(g_local_peer_id));

	return peer_send_buff(sockfd, buff, bufflen);
}

static uint32_t msgbuff_len(msg_type_t type, const torrent_t *torrent)
{
	uint32_t ret;

	switch (type)
	{
	case MSG_KEEPALIVE:
		ret = 0;
		break;
	case MSG_PIECE:
		ret = 1 + 2 * sizeof(uint32_t) + PEER_REQUEST_SIZE;
		break;
	case MSG_BITFIELD:
		ret = 1 + LBITFIELD_NUM_BYTES(list_get_size(torrent->pieces));
		break;
	case MSG_REQUEST:
		ret = 1 + 3 * sizeof(uint32_t);
		break;
	case MSG_HAVE:
	case MSG_PORT:
		ret = 1 + sizeof(uint32_t);
		break;
	default:
		ret = 1;
	}

	return ret;
}

static inline bool valid_len(msg_type_t type, const torrent_t *torrent, uint32_t len)
{
	return (len == msgbuff_len(type, torrent));
}

static int peer_msg_recv_pastlen(int sockfd, peer_msg_t *out, const torrent_t *torrent, uint32_t len)
{
	if (len == 0)
	{
		out->type = MSG_KEEPALIVE;
		return 0;
	}

	unsigned char type;
	if (peer_recv_buff(sockfd, (char *)&type, 1))
		return -1;

	if (type >= MSG_MAX)
		return -1;

	if (!valid_len((msg_type_t)type, torrent, len))
		return -1;

	out->type = (msg_type_t)type;
	unsigned left = len - 1;

	switch (type)
	{
		/* When we get a piece, write it to the mmap'd file directly */
	case MSG_PIECE:
	{
		assert(left > 0);
		uint32_t u32;

		if (peer_recv_buff(sockfd, (char*)&u32, sizeof(u32)))
			return -1;
		out->payload.piece.index = ntohl(u32);
		left -= sizeof(uint32_t);

		if (peer_recv_buff(sockfd, (char*)&u32, sizeof(u32)))
			return -1;
		out->payload.piece.begin = ntohl(u32);
		left -= sizeof(uint32_t);

		char *piecebuff = torrent_get_filemem(torrent, out->payload.piece.index,
			out->payload.piece.blocklen);
		if (!piecebuff)
			return -1;

		out->payload.piece.blocklen = left;
		if (peer_recv_buff(sockfd, piecebuff + out->payload.piece.begin, left))
		{
			//free piecebuff 
			return -1;
		}

		break;
	}
	case MSG_BITFIELD:
	{
		char *buff = (char *)malloc(left);
		memset(buff, 0, left);
		if (peer_recv_buff(sockfd, buff, left))
		{
			free(buff);
			return -1;
		}

		out->payload.bitfield = byte_str_new(left, (const unsigned char *)"");
		if (!out->payload.bitfield)
		{
			free(buff);
			return -1;
		}

		memcpy(out->payload.bitfield->str, buff, left);
		free(buff);

		break;
	}
	case MSG_REQUEST:
	{
		char *buff = (char *)malloc(left);
		memset(buff, 0, left);

		if (peer_recv_buff(sockfd, buff, left))
		{
			free(buff);
			return -1;
		}

		assert(sizeof(buff) == 4 * sizeof(uint32_t));
		uint32_t u32;
		memcpy(&u32, buff, sizeof(uint32_t));
		out->payload.request.index = ntohl(u32);

		memcpy(&u32, buff + sizeof(uint32_t), sizeof(uint32_t));
		out->payload.request.begin = ntohl(u32);

		memcpy(&u32, buff + 2 * sizeof(uint32_t), sizeof(uint32_t));
		out->payload.request.length = ntohl(u32);

		free(buff);
		break;
	}
	case MSG_HAVE:
	{
		uint32_t u32;
		assert(left == sizeof(uint32_t));
		if (peer_recv_buff(sockfd, (char*)&u32, left))
			return -1;
		out->payload.have = ntohl(u32);
		break;
	}
	case MSG_PORT:
	{
		uint32_t u32;
		assert(left == sizeof(uint32_t));
		if (peer_recv_buff(sockfd, (char*)&u32, left))
			return -1;
		out->payload.listen_port = ntohl(u32);
		break;
	}
	default:
		return -1;
	}

	log_printf(LOG_LEVEL_DEBUG, "Successfully received message from peer, Type: %hhu\n", type);
	return 0;

}

int peer_msg_send(int sockfd, peer_msg_t *msg, const torrent_t *torrent)
{
	uint32_t len = msgbuff_len(msg->type, torrent);
	len = htonl(len);

	log_printf(LOG_LEVEL_INFO, "Sending message of type: %d\n", msg->type);

	if (peer_send_buff(sockfd, (char*)&len, sizeof(uint32_t)))
		return -1;

	if (msg->type == MSG_KEEPALIVE)
		return 0;

	char out = msg->type;
	if (peer_send_buff(sockfd, &out, 1))
		return -1;

	switch (msg->type)
	{
	case MSG_CHOKE:
	case MSG_UNCHOKE:
	case MSG_INTERESTED:
	case MSG_NOT_INTERESTED:
	case MSG_CANCEL:
	{
		assert(len == 1);
		return 0;
	}
	case MSG_PIECE:
	{
		const char *piecebuff = torrent_get_filemem(torrent, msg->payload.piece.index,
			msg->payload.piece.begin);
		if (!piecebuff)
			return -1;
		if (peer_send_buff(sockfd, piecebuff + msg->payload.piece.begin, msg->payload.piece.blocklen))
			return -1;

		return 0;
	}
	case MSG_BITFIELD:
	{
		assert(msg->payload.bitfield);
		if (peer_send_buff(sockfd, (const char *)(msg->payload.bitfield->str), msg->payload.bitfield->size))
			return -1;

		return 0;
	}
	case MSG_REQUEST:
	{
		uint32_t u32;
		u32 = htonl(msg->payload.request.index);
		if (peer_send_buff(sockfd, (char*)&u32, sizeof(uint32_t)))
			return -1;
		u32 = htonl(msg->payload.request.begin);
		if (peer_send_buff(sockfd, (char*)&u32, sizeof(uint32_t)))
			return -1;
		u32 = htonl(msg->payload.request.length);
		if (peer_send_buff(sockfd, (char*)&u32, sizeof(uint32_t)))
			return -1;

		return 0;
	}
	case MSG_HAVE:
	{
		uint32_t u32;
		u32 = htonl(msg->payload.have);
		if (peer_send_buff(sockfd, (char*)&u32, sizeof(uint32_t)))
			return -1;

		return 0;
	}
	case MSG_PORT:
	{
		uint32_t u32;
		u32 = htonl(msg->payload.listen_port);
		if (peer_send_buff(sockfd, (char*)&u32, sizeof(uint32_t)))
			return -1;

		return 0;
	}
	default:
		return -1;
	}
}

int peer_msg_recv(int sockfd, peer_msg_t *out, const torrent_t *torrent)
{
	uint32_t len;
	if (peer_recv_buff(sockfd, (char*)&len, sizeof(uint32_t)))
		return -1;
	len = ntohl(len);

	return peer_msg_recv_pastlen(sockfd, out, torrent, len);
}

int peer_msg_waiton_recv(int sockfd, peer_msg_t *out, const torrent_t *torrent, unsigned timeout)
{
	struct timeval new_time, saved;
	new_time.tv_sec = timeout;
	new_time.tv_usec = 0;
	int old_cancelstate;
	uint32_t len;

	socklen_t timelen = sizeof(struct timeval);
	getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&saved, &timelen);
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&new_time, sizeof(timeout));

	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &old_cancelstate);
	/* The initial recv is a cancellation point, and has a custom timeout of "timeout" */
	long long r;
	if ((r = recv(sockfd, (char *)&len, sizeof(uint32_t), 0)) <= 0)
		return -1;

	assert(r <= sizeof(uint32_t));
	setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&saved, sizeof(struct timeval));

	pthread_setcancelstate(old_cancelstate, NULL);

	if (peer_recv_buff(sockfd, ((char*)&len) + r, sizeof(uint32_t) - r))
		return -1;

	len = ntohl(len);

	return peer_msg_recv_pastlen(sockfd, out, torrent, len);
}

bool peer_msg_buff_nonempty(int sockfd)
{
	uint32_t len;
	u_long mode = 1; // 0 - blocking is enabled, nonzero - non-blocking mode is enabled

	int rt = ioctlsocket(sockfd, FIONBIO, &mode);
	if (rt != NO_ERROR)
	{
		printf("replace MSG_DONTWAIT with ioctlsocket error\n");
		return false;
	}

	// MSG_DONTWAIT just for each call, use ioctlsocket here shoule be wrong, but that's the only way i know
	int n = recv(sockfd, (char*)&len, sizeof(uint32_t), MSG_PEEK/* | MSG_DONTWAIT*/);

	mode = 0;
	rt = ioctlsocket(sockfd, FIONBIO, &mode);
	if (rt != NO_ERROR)
	{
		printf("replace MSG_DONTWAIT with ioctlsocket error\n");
		return false;
	}

	if (n < sizeof(uint32_t))
		return false;

	return true;
}
