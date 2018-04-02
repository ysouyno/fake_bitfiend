#include <signal.h>
#include <stdbool.h>
#include "bitfiend.h"

#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#else
#endif

static volatile bool running = true;

static void sig_handler(int signum)
{
  running = false;
}

int main(int argc, char **argv)
{
  signal(SIGPIPE, SIG_IGN);

  bitfiend_init();
  bitfiend_add_torrent("/home/ysouyno/dnld/spacemacs.tar.gz.torrent", "/home/ysouyno/dnld");

  signal(SIGINT, sig_handler);
  while (running)
    ;

  bitfiend_shutdown();
}
