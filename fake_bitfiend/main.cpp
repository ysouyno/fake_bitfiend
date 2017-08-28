#include <iostream>
#include <pthread.h>

void *pthread_thread_proc(void *arg)
{
	std::cout << "hello pthread!" << std::endl;

	return NULL;
}

int main()
{
	pthread_t tid;

	pthread_create(&tid, NULL, pthread_thread_proc, NULL);
	pthread_join(tid, NULL);

	return 0;
}
