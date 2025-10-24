#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

unsigned long long size = 128 * 1024 * 1024;
unsigned long long total_size;
unsigned char *buf[1024];
int idx, cnt;
int flag = 1;
int interval = -1;
char *cmd;

int add_memory(void)
{
	total_size += size;
	printf("total size = %llu MB\n", total_size / 1024 / 1024);
	fflush(stdout);
	buf[idx] = (unsigned char *)malloc(size);
	if (!buf[idx]) {
		fprintf(stderr, "could not allocate memory\n");
		return -1;
	} else
		idx++;
	flag = 1;
	return 0;
}

void sighandler(int sig)
{
	add_memory();
}

int main(int argc, char *argv[])
{
	unsigned long long i, j;
	unsigned int init_alloc_num = 1, elapsed_time = 0;
	int c;
	const char *optstring = "a:c:f:i:s:";
	char *file;
	char cmd_arg[256];
	int loop_cnt = 0;

	opterr = 0;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'a':
			init_alloc_num = atoi(optarg);
			break;
		case 'c':
			cmd = optarg;
			break;
		case 'i':
			interval = atoi(optarg);
			break;
		case 's':
			size = atoll(optarg);
			break;
		}
	}

	signal(SIGUSR1, SIG_IGN);
	signal(SIGUSR2, sighandler);

	for (i = 0; i < init_alloc_num; i++) {
		buf[idx] = (unsigned char *)malloc(size);
		if (!buf[idx]) {
			fprintf(stderr, "could not allocate memory\n");
			return -1;
		}
		idx++;
		total_size += size;
	}
	printf("total size = %llu MB\n", total_size / 1024 / 1024);
	fflush(stdout);

	while (1) {
		for (i = 0; i < idx; i++) {
			for (j = 0; j < size; j += 4096) {
				buf[i][j] = cnt++;
			}
		}
		if (flag) {
			printf("accessed\n");
			fflush(stdout);
			if (cmd) {
				sprintf(cmd_arg, "%s %d", cmd, loop_cnt);
				system(cmd_arg);
				loop_cnt++;
			}
			flag = 0;
		}
		sleep(1);
		elapsed_time++;
		if (interval != -1 && elapsed_time % interval == 0)
			add_memory();
	}

	return 0;
}
