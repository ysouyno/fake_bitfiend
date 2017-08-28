#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <io.h>
#include "torrent_file.h"
#include <Windows.h>
#include <stdio.h>

#pragma warning(disable: 4996)

typedef struct torrent_file
{
	HANDLE fd;
	size_t size;
	unsigned char *data;
}torrent_file_t;

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

	if (UnmapViewOfFile(file->data))
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

bencode_obj_t *torrent_file_parse(const char *path)
{
	torrent_file_t *file;
	bencode_obj_t *ret;

	file = torrent_file_open(path);
	if (!file)
		goto fail_open;

	const char *endptr;
	ret = bencode_parse_object((const char *)(file->data), &endptr);
	assert(endptr = (const char *)(file->data) + file->size);

	torrent_file_close_and_free(file);
	return ret;

fail_open:
	return NULL;
}
