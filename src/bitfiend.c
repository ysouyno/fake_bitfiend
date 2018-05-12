#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#if defined(_MSC_VER)
#else
#include <mqueue.h>
#endif
#include "bitfiend.h"
#include "list.h"
#include "peer_id.h"
#include "peer_listener.h"
#include "bencode.h"
#include "torrent.h"
#include "torrent_file.h"
#include "log.h"
#include "peer_connection.h"
#include "thread_reaper.h"

static pthread_t s_peer_listener;
static pthread_t s_reaper;
static const uint16_t s_port = 6889;
static pthread_mutex_t s_torrents_lock = PTHREAD_MUTEX_INITIALIZER;
static list_t *s_torrents;
/* Threads for incoming peer connections which have been created but not yet associated
 * with a particular torrent, which can't be done until after handshaking. Store their handles
 * here for now, until a torrent_t associates with it and removes the handle from this list */
static pthread_mutex_t s_unassoc_peerthreads_lock = PTHREAD_MUTEX_INITIALIZER;
static list_t *s_unassoc_peerthreads;
static bool s_shutdown = false;

int bitfiend_init(void)
{
  log_set_lvl(LOG_LEVEL_DEBUG);
  log_set_logfile(stdout);

  peer_id_create(g_local_peer_id);

  s_torrents = list_init();
  s_unassoc_peerthreads = list_init();

  if (peer_listener_create(&s_peer_listener, &s_port))
    goto fail_init;

  reaper_arg_t *arg = malloc(sizeof(reaper_arg_t));
  if (!arg) {
    goto fail_init;
  }

  arg->reap_interval = 5;
  arg->torrents = s_torrents;
  arg->torrents_lock = &s_torrents_lock;
  arg->unassoc_peers = s_unassoc_peerthreads;
  arg->unassoc_peer_lock = &s_unassoc_peerthreads_lock;
  if (thread_reaper_create(&s_reaper, arg)) {
    free(arg);
    goto fail_init;
  }

  log_printf(LOG_LEVEL_INFO, "BitFiend init successful\n");
  return BITFIEND_SUCCESS;

 fail_init:
  log_printf(LOG_LEVEL_ERROR, "BitFiend init error\n");
  return BITFIEND_FAILURE;
}

static int shutdown_torrent(torrent_t *torrent)
{
  if (pthread_cancel(torrent->tracker_thread))
    goto fail_stop_tracker;

  const unsigned char *entry;
  void *tret;
  pthread_join(torrent->tracker_thread, &tret);
  assert(tret == PTHREAD_CANCELED);

  pthread_mutex_lock(&torrent->sh_lock);
  const list_iter_t *iter = list_iter_first(torrent->sh.peer_connections);
  pthread_mutex_unlock(&torrent->sh_lock);

  while (iter) {
    peer_conn_t *conn = *(peer_conn_t **)(list_iter_get_value(iter));
    void *ret;

    pthread_cancel(conn->thread);

    /* Interrupt any blocking call the peer thread may be waiting on while they
     * should time out, this results in consistently shutdown of the client */
    pthread_kill(conn->thread, SIGINT);
    pthread_join(conn->thread, &ret);

    pthread_mutex_lock(&torrent->sh_lock);
    iter = list_iter_next(iter);
    pthread_mutex_unlock(&torrent->sh_lock);
  }

  torrent_free(torrent);
  return BITFIEND_SUCCESS;

 fail_stop_peer:
 fail_stop_tracker:
  return BITFIEND_FAILURE;
}

int bitfiend_shutdown(void)
{
  int ret = BITFIEND_SUCCESS;
  const unsigned char *entry;
  void *tret;

  /* Thread join order matters here.
   * First, join the peer_listener so no new unassociated peers can be added.
   * Next, join unassociated peers, after which a torrent's peer_connections
   * list can only grow if its' tracker_thread gives it peers. Now, iterate
   * over all torrents. Join the tracker thread first. Now no new peer threads
   * can be spawned which can touch the torrent. Join the torrent's peers last.
   */

  if (pthread_cancel(s_reaper))
    ret = BITFIEND_FAILURE;

  pthread_join(s_reaper, &tret);
  assert(tret == PTHREAD_CANCELED);

  if (pthread_cancel(s_peer_listener))
    ret = BITFIEND_FAILURE;

  pthread_join(s_peer_listener, &tret);
  assert(tret == PTHREAD_CANCELED);

  pthread_mutex_lock(&s_unassoc_peerthreads_lock);
  size_t listsize = 0;
  listsize = list_get_size(s_unassoc_peerthreads);
  pthread_mutex_unlock(&s_unassoc_peerthreads_lock);

  log_printf(LOG_LEVEL_DEBUG,
             "Cancelling and joining unassociated peer threads. There are %zu\n", listsize);

  const list_iter_t *iter = NULL;
  pthread_t curr;
  do {
    /* Remove one entry at a time from the list head. This is so we are not holding the
     * list lock while we are joining the thread in the list, since the thread being
     * joined can also hold the lock and remove an entry from the list */
    pthread_mutex_lock(&s_unassoc_peerthreads_lock);
    iter = list_iter_first(s_unassoc_peerthreads);
    if (iter) {
      curr = *(pthread_t *)list_iter_get_value(iter);
      list_remove(s_unassoc_peerthreads, (unsigned char *)&curr);
    }
    pthread_mutex_unlock(&s_unassoc_peerthreads_lock);

    if (iter) {
      pthread_cancel(curr);
      pthread_join(curr, NULL);
    }
  }
  while (iter);

  pthread_mutex_lock(&s_unassoc_peerthreads_lock);
  list_free(s_unassoc_peerthreads);
  pthread_mutex_unlock(&s_unassoc_peerthreads_lock);

  pthread_mutex_lock(&s_torrents_lock);
  FOREACH_ENTRY(entry, s_torrents) {
    shutdown_torrent(*(torrent_t **)entry);
  }
  list_free(s_torrents);
  pthread_mutex_unlock(&s_torrents_lock);

  if (ret == BITFIEND_SUCCESS)
    log_printf(LOG_LEVEL_INFO, "BitFiend shutdown successful\n");
  else
    log_printf(LOG_LEVEL_INFO, "BitFiend shutdown error\n");

  return ret;
}

torrent_t *bitfiend_add_torrent(const char *metafile, const char *destdir)
{
  bencode_obj_t *obj = torrent_file_parse(metafile);
  if (!obj)
    goto fail_parse;

  torrent_t *torrent = torrent_init(obj, destdir);
  extern void print_torrent(torrent_t *torrent);
  print_torrent(torrent);

  bencode_free_obj_and_data_recursive(obj);
  if (!torrent)
    goto fail_create;

  tracker_arg_t *arg = (tracker_arg_t *)malloc(sizeof(tracker_arg_t));
  arg->torrent = torrent;
  arg->port = s_port;
  if (tracker_connection_create(&torrent->tracker_thread, arg))
    goto fail_create;

  pthread_mutex_lock(&s_torrents_lock);
  list_add(s_torrents, (unsigned char *)&torrent, sizeof(torrent_t *));
  pthread_mutex_unlock(&s_torrents_lock);

  log_printf(LOG_LEVEL_INFO, "Torrent added successfully: %s\n", metafile);
  return torrent;

 fail_create:
 fail_parse:
  log_printf(LOG_LEVEL_ERROR, "Error adding torrent: %s\n", metafile);
  return NULL;
}

int bitfiend_start_torrent(torrent_t *torrent)
{
  return 0;
}

int bitfiend_pause_torrent(torrent_t *torrent)
{
  return 0;
}

int bitfiend_set_priority(torrent_t *torrent)
{
  return 0;
}

int bitfiend_remove_torrent(torrent_t *torrent)
{
  return 0;
}

torrent_t *bitfiend_assoc_peer(peer_conn_t *peer, char infohash[20])
{
  const unsigned char *entry;
  torrent_t *ret = NULL;

  pthread_mutex_lock(&s_torrents_lock);
  FOREACH_ENTRY(entry, s_torrents) {
    torrent_t *torrent = *(torrent_t **)entry;

    if (!memcmp(torrent->info_hash, infohash, sizeof(torrent->info_hash))) {
      pthread_mutex_lock(&torrent->sh_lock);
      unsigned num_conns = list_get_size(torrent->sh.peer_connections);
      if (num_conns == torrent->max_peers) {
        pthread_mutex_unlock(&torrent->sh_lock);
        ret = NULL;
        break;
      }
      pthread_mutex_unlock(&torrent->sh_lock);

      pthread_mutex_lock(&s_unassoc_peerthreads_lock);
      /* Handle the case if we've already been "chosen" to be joined by the main thread */
      if (!list_contains(s_unassoc_peerthreads, (unsigned char *)&peer->thread)) {
        pthread_mutex_unlock(&s_unassoc_peerthreads_lock);
        break;
      }
      list_remove(s_unassoc_peerthreads, (unsigned char *)&peer->thread);
      pthread_mutex_unlock(&s_unassoc_peerthreads_lock);

      pthread_mutex_lock(&torrent->sh_lock);
      list_add(torrent->sh.peer_connections, (unsigned char *)&peer, sizeof(peer_conn_t *));
      ret = torrent;
      pthread_mutex_unlock(&torrent->sh_lock);

      log_printf(LOG_LEVEL_INFO, "Associated incoming peer connection with torrent\n");
      break;
    }
  }
  pthread_mutex_unlock(&s_torrents_lock);

  return ret;
}

void bitfiend_add_unassoc_peer(pthread_t thread)
{
  pthread_mutex_lock(&s_unassoc_peerthreads_lock);
  list_add(s_unassoc_peerthreads, (unsigned char *)&thread, sizeof(pthread_t));
  pthread_mutex_unlock(&s_unassoc_peerthreads_lock);
}

#if defined(_MSC_VER)
HANDLE mq_open(const char *name, DWORD flags)
{
  HANDLE hPipe = CreateFileA(
                             name,          // pipe name
                             GENERIC_READ | // read and write access
                             GENERIC_WRITE,
                             0,             // no sharing
                             NULL,          // default security attributes
                             OPEN_EXISTING, // opens existing pipe
                             0,             // default attributes
                             NULL);         // no template file

  if (hPipe == INVALID_HANDLE_VALUE) {
    printf("CreateFileA named pipe %s failed: %d\n", name, GetLastError());
    return NULL;
  }
  else {
    printf("CreateFileA named pipe %s ok: %d\n", name);
    return hPipe;
  }
}

int mq_send(HANDLE queue, const char *pipe_name, const char *msg_ptr, size_t msg_len, unsigned int msg_prio)
{
  if (!WaitNamedPipeA(pipe_name, 20000)) {
    printf("Could not open pipe: 20 second wait timed out\n");
    CloseHandle(queue);
    return -1;
  }

  DWORD cbWritten = 0;
  BOOL bRet = WriteFile(
                        queue,      // pipe handle
                        msg_ptr,    // message
                        msg_len,    // message length
                        &cbWritten, // bytes written
                        NULL);      // not overlapped

  if (!bRet) {
    printf("WriteFile to pipe %s failed: %d\n", pipe_name, GetLastError());
    CloseHandle(queue);
    return -1;
  }
  else {
    printf("WriteFile sent to pipe %s ok\n", pipe_name);
    return 0;
  }
}
#endif

int bitfiend_notify_peers_have(torrent_t *torrent, unsigned have_index)
{
  int ret = 0;
  const unsigned char *entry;
  pthread_mutex_lock(&torrent->sh_lock);

  FOREACH_ENTRY(entry, torrent->sh.peer_connections) {
    peer_conn_t *conn = *(peer_conn_t **)entry;

    if (0 == pthread_equal(conn->thread, pthread_self()))
      continue;

    char queue_name[64];
    peer_connection_queue_name(conn->thread, queue_name, sizeof(queue_name));
#if defined(_MSC_VER)
    HANDLE queue = mq_open(queue_name, 0);
#else
    mqd_t queue = mq_open(queue_name, O_WRONLY | O_NONBLOCK);
#endif
    if (queue != NULL) {
      // errno! = EAGAIN talk about later
#if defined(_MSC_VER)
      if (mq_send(queue, queue_name, (char *)&have_index, sizeof(unsigned), 0)/* && errno != EAGAIN*/)
#else
        if (mq_send(queue, (char *)&have_index, sizeof(unsigned), 0) && errno != EAGAIN)
#endif
          log_printf(LOG_LEVEL_ERROR, "Failed to send have event to peer threads\n");
#if defined(_MSC_VER)
      CloseHandle(queue);
#else
      mq_close(queue);
#endif
    }
    else {
      ret = -1;
      log_printf(LOG_LEVEL_ERROR, "Could not open queue for sending: %s\n", queue_name);
    }
  }

  pthread_mutex_unlock(&torrent->sh_lock);

  return ret;
}
