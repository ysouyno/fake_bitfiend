#include <signal.h>
#include <stdbool.h>
#include "bitfiend.h"

#pragma comment(lib, "ws2_32.lib")

static volatile bool running = true;

static void sig_handler(int signum)
{
	running = false;
}

int main(int argc, char **argv)
{
	/*signal(SIGPIPE, SIG_IGN);*/

	bitfiend_init();
	bitfiend_add_torrent("C:\\Users\\ysouyno\\Desktop\\debian.torrent", "C:\\Users\\ysouyno\\Desktop");

	signal(SIGINT, sig_handler);
	while (running)
		;

	bitfiend_shutdown();
}
