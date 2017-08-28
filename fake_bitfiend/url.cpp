#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "url.h"

#pragma warning(disable: 4996)

url_t *url_from_str(const char *str)
{
	char *buff = (char *)malloc(strlen(str) + 1);
	char *saveptr;

	strcpy(buff, str);

	url_t *ret = (url_t *)malloc(sizeof(url_t));
	if (!ret)
		return NULL;

	if (!strncmp(buff, "http:", 5))
		ret->protocol = PROTOCOL_HTTP;
	else if (!strncmp(buff, "https:", 6))
		ret->protocol = PROTOCOL_HTTPS;
	else if (!strncmp(buff, "udp://", 6))
		ret->protocol = PROTOCOL_UDP;
	else
		ret->protocol = PROTOCOL_UNKNOWN;

	const char *hostname = strtok_s(buff, ":/", &saveptr);
	hostname = strtok_s(NULL, ":/", &saveptr);
	ret->hostname = (char *)malloc(strlen(hostname) + 1);
	if (!ret->hostname)
		goto fail_alloc_hostname;
	strcpy(ret->hostname, hostname);
	str += strlen(hostname) + (hostname - buff);

	if (strstr(str, ":"))
	{
		const char *port = strtok_s(NULL, ":/", &saveptr);
		ret->port = (uint16_t)strtoul(port, NULL, 0);
	}
	else if (ret->protocol == PROTOCOL_HTTP)
	{
		ret->port = 80;
	}
	else if (ret->protocol == PROTOCOL_HTTPS)
	{
		ret->port = 443;
	}

	const char *path = strtok_s(NULL, ":/", &saveptr);
	ret->path = (char *)malloc(strlen(path) + 1);
	if (!ret->path)
		goto fail_alloc_path;
	strcpy(ret->path, path);

	return ret;

fail_alloc_path:
	free(ret->hostname);
fail_alloc_hostname:
	free(ret);
	free(buff);
	return NULL;
}

void url_free(url_t *url)
{
	free(url->hostname);
	free(url->path);
	free(url);
}
