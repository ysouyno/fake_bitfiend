#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined(_MSC_VER)
#include <Windows.h>
#include <io.h>
#else
#include <sys/mman.h>
#endif
#include "dl_file.h"
#include "log.h"

#if defined(_MSC_VER)
#pragma warning(disable: 4996)
#else
#endif

struct dl_file {
  pthread_mutex_t file_lock;
  size_t size;
  unsigned char *data;
  char path[];
};

#if defined(_MSC_VER)

dl_file_t *dl_file_create_and_open(size_t size, const char *path)
{
  unsigned char *mem;
  int fd;
  struct stat stats;

  char newpath[512];
  strcpy(newpath, path);
  strcat(newpath, ".incomplete");

  fd = open(path, O_CREAT | O_RDWR, 0777);
  if (fd < 0)
    goto fail_open;

  /*
    if(ftruncate(fd, size))
    goto fail_truncate;*/

  if (_chsize(fd, size)) {
    goto fail_truncate;
  }

  fstat(fd, &stats);
  assert(stats.st_size == size); // temp

  HANDLE file_handle = CreateFileA(path,
                                   GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE,
                                   NULL,
                                   OPEN_EXISTING,
                                   FILE_ATTRIBUTE_NORMAL,
                                   NULL);
  if (INVALID_HANDLE_VALUE == file_handle) {
    printf("CreateFileA error: %d\n", GetLastError());
    goto fail_open;
  }

  // mem = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  HANDLE h = CreateFileMapping(file_handle, NULL, PAGE_READWRITE, 0, 0, NULL);
  if (NULL == h) {
    printf("CreateFileMapping error: %d\n", GetLastError());
  }

  mem = (unsigned char *)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, stats.st_size);
  if (!mem)
    goto fail_map;

  dl_file_t *file = (dl_file_t *)malloc(sizeof(dl_file_t) + strlen(newpath) + 1);
  if (!file)
    goto fail_alloc;

  pthread_mutex_init(&file->file_lock, NULL);
  file->size = size;
  file->data = mem;
  memcpy(file->path, newpath, strlen(newpath));
  file->path[strlen(newpath)] = '\0';

  rename(path, newpath);

  close(fd);
  CloseHandle(file_handle);
  log_printf(LOG_LEVEL_INFO, "Successfully (created and) opened file at: %s\n", path);
  return file;

 fail_alloc:
  // munmap(mem, stats.st_size);
  UnmapViewOfFile(mem);
  CloseHandle(file_handle);
  CloseHandle(h);
 fail_map:
 fail_truncate:
  close(fd);
 fail_open:
  log_printf(LOG_LEVEL_ERROR, "Unable to (create and) open file at:%s\n", path);
  return NULL;
}

int dl_file_close_and_free(dl_file_t *file)
{
  int ret = 0;
  /*if(munmap(file->data, file->size))
    ret = -1;*/

  if (UnmapViewOfFile(file->data)) {
    return -1;
  }

  pthread_mutex_destroy(&file->file_lock);
  free(file);

  return ret;
}

#else

dl_file_t *dl_file_create_and_open(size_t size, const char *path)
{
  unsigned char *mem;
  int fd;
  struct stat stats;
  char errbuff[64];

  char newpath[512];
  strcpy(newpath, path);
  strcat(newpath, ".incomplete");

  fd = open(path, O_CREAT | O_RDWR, 0777);
  if(fd < 0)
    goto fail_open;

  if(ftruncate(fd, size))
    goto fail_truncate;

  fstat(fd, &stats);
  assert(stats.st_size == size); // temp

  mem = mmap(NULL, stats.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if(!mem)
    goto fail_map;

  dl_file_t *file = malloc(sizeof(dl_file_t) + strlen(newpath) + 1);
  if(!file)
    goto fail_alloc;

  pthread_mutex_init(&file->file_lock, NULL);
  file->size = size;
  file->data = mem;
  memcpy(file->path, newpath, strlen(newpath));
  file->path[strlen(newpath)] = '\0';

  rename(path, newpath);

  close(fd);
  log_printf(LOG_LEVEL_INFO, "Successfully (created and) opened file at: %s\n", path);
  return file;

 fail_alloc:
  munmap(mem, stats.st_size);
 fail_map:
 fail_truncate:
  close(fd);
 fail_open:
  log_printf(LOG_LEVEL_ERROR, "Unable to (create and) open file at:%s\n", path);
  return NULL;
}

int dl_file_close_and_free(dl_file_t *file)
{
  int ret = 0;
  if(munmap(file->data, file->size))
    ret = -1;

  pthread_mutex_destroy(&file->file_lock);
  free(file);

  return ret;
}

#endif

void dl_file_getfilemem(const dl_file_t *file, filemem_t *out)
{
  out->mem = file->data;
  out->size = file->size;
}
