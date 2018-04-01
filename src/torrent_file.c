#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if defined(_MSC_VER)
#include <io.h>
#include <Windows.>
#else
#include <sys/mman.h>
#endif
#include "torrent_file.h"
#include <stdio.h>

#if defined(_MSC_VER)

#pragma warning(disable: 4996)

typedef struct torrent_file
{
	HANDLE fd; // file handle
	size_t size; // file size
	unsigned char *data;
}torrent_file_t;

#else

typedef struct torrent_file{
  int fd;
  size_t size;
  unsigned char *data;
}torrent_file_t;

#endif

#if defined(_MSC_VER)

static torrent_file_t *torrent_file_open(const char *path)
{
	unsigned char *mem;
	int fd;
	struct stat stats;

	fd = open(path, O_RDWR);
	if (fd < 0)
		goto fail_open;
	fstat(fd, &stats);

	HANDLE file_handle = CreateFileA(path, GENERIC_READ | GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (INVALID_HANDLE_VALUE == file_handle)
    {
      printf("CreateFileA error: %d\n", GetLastError());
      goto fail_open;
    }

	// mem = mmap(NULL, stats.st_size, PROT_READ, MAP_SHARED, fd, 0);
	HANDLE h = CreateFileMapping(file_handle, NULL, PAGE_READWRITE, 0, 0, NULL);
	if (NULL == h)
    {
      printf("CreateFileMapping error: %d\n", GetLastError());
      goto fail_map;
    }

	mem = (unsigned char *)MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, stats.st_size);
	if (!mem)
		goto fail_map;

	torrent_file_t *file = (torrent_file_t *)malloc(sizeof(torrent_file_t));
	if (!file)
		goto fail_alloc;

	file->fd = file_handle;
	file->size = stats.st_size;
	file->data = mem;

	return file;

 fail_alloc:
	// munmap(file->data, file->size);
	UnmapViewOfFile(mem);
	CloseHandle(file_handle);
	CloseHandle(h);
 fail_map:
	close(fd);
 fail_open:
	return NULL;
}

static int torrent_file_close_and_free(torrent_file_t *file)
{
	/*if(munmap(file->data, file->size))
    goto fail;*/

	// If UnmapViewOfFile succeeds, the return value is nonzero.
	if (!UnmapViewOfFile(file->data))
    {
      goto fail;
    }

	if (!CloseHandle(file->fd))
		goto fail;

	free(file);
	return 0;

 fail:
	free(file);
	return -1;
}

#else

static torrent_file_t *torrent_file_open(const char *path)
{
  unsigned char *mem;
  int fd;
  struct stat stats;

  fd = open(path, O_RDWR);
  if(fd < 0)
    goto fail_open;
  fstat(fd, &stats);

  mem = mmap(NULL, stats.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if(!mem)
    goto fail_map;

  torrent_file_t *file = malloc(sizeof(torrent_file_t));
  if(!file)
    goto fail_alloc;

  file->fd = fd;
  file->size = stats.st_size;
  file->data = mem;

  return file;

 fail_alloc:
  munmap(file->data, file->size);
 fail_map:
  close(fd);
 fail_open:
  return NULL;
}

static int torrent_file_close_and_free(torrent_file_t *file)
{
  if(munmap(file->data, file->size))
    goto fail;

  if(!close(file->fd))
    goto fail;

  free(file);
  return 0;

 fail:
  free(file);
  return -1;
}

#endif

bencode_obj_t *torrent_file_parse(const char *path)
{
	torrent_file_t *file;
	bencode_obj_t *ret;

	// get file.torrent info
	file = torrent_file_open(path);
	if (!file)
		goto fail_open;

	const char *endptr;
	ret = bencode_parse_object((const char *)(file->data), &endptr);
	assert(endptr == (const char *)(file->data) + file->size);

	torrent_file_close_and_free(file);
	return ret;

 fail_open:
	return NULL;
}
