#include <linux/unistd.h>
#include <linux/bpf.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <bpf/bpf.h>
#include "xdp_ssl_parser_common.h"

int main(int argc, char **argv) {
	int fd = -1;
	int key = 0;
	const char *map_filename = "/sys/fs/bpf/xdp/globals/snimap";
	struct sslsni_wrapper wrapper = {};

	fd = bpf_obj_get(map_filename);
	if (fd < 0) {
		perror("unable to get map obj");
		return 1;
	}

	if (bpf_map_lookup_elem(fd, &key, &wrapper) < 0) {
		perror("unable to do map lookup");
		return 1;
	}

	printf("sni %s\n", wrapper.sslsni);
	return 0;
}
