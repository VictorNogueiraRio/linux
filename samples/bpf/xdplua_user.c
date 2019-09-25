#include <linux/bpf.h>
#include <linux/if_link.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>

#include "bpf_util.h"
#include "bpf/bpf.h"
#include "bpf/libbpf.h"

static int ifindex;

static void usage(const char *prog) {
	fprintf(stderr,
			"usage: %s [OPTS] IFACE\n"
			"\nOPTS:\n"
			"    -L LUAFILE     load lua script to XDP\n"
			"    -d             detach program\n",
			prog);
}

static char *extract_lua_prog(const char *path)
{
	FILE *f;
	long prog_size;
	char *lua_prog;

	f = fopen(path, "r");
	if (f == NULL) {
		perror("unable to open lua file");
		return NULL;
	}

	fseek(f, 0 , SEEK_END);
	prog_size = ftell(f);
	rewind(f);

	lua_prog = (char *) malloc(prog_size + 1);
	if (fread(lua_prog, 1, prog_size, f) < 0) {
		perror("unable to read lua file");
		return NULL;
	}

	lua_prog[prog_size] = '\0';
	return lua_prog;
}

static int do_attach(int idx, int fd, const char *name, char *lua_prog)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, fd, 0);
	if (err < 0)
		printf("ERROR: failed to attach program to %s\n", name);

	err = bpf_set_link_xdp_lua(idx, lua_prog);
	if (err < 0)
		printf("ERROR: failed to attach lua script to %s\n", name);

	return err;
}

static int do_detach(int idx, const char *name)
{
	int err;

	err = bpf_set_link_xdp_fd(idx, -1, 0);
	if (err < 0)
		printf("ERROR: failed to detach program from %s\n", name);

	return err;
}

int main(int argc, char *argv[])
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	const char *optstr = "L:d";
	int prog_fd, opt;
	struct bpf_object *obj;
	char filename[256];
	char lua_filename[256];
	char *lua_prog;
	int attach = 1;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
			case 'L':
				snprintf(lua_filename, sizeof(lua_filename),
						"%s", optarg);
				break;
			case 'd':
				attach = 0;
				break;
			default:
				usage(basename(argv[0]));
				return 1;
		}
	}

	if (optind == argc) {
		usage(basename(argv[0]));
		return 1;
	}

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK)");
		return 1;
	}

	ifindex = if_nametoindex(argv[optind]);
	if (!ifindex) {
		perror("if_nametoindex");
		return 1;
	}

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = filename;

	if (attach) {
		if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
			return 1;

		if (!prog_fd) {
			printf("load_bpf_file: %s\n", strerror(errno));
			return 1;
		}

		lua_prog = extract_lua_prog(lua_filename);
		if (!lua_prog)
			return 1;

		if (do_attach(ifindex, prog_fd, lua_filename, lua_prog) < 0)
			return 1;
	} else {
		if (do_detach(ifindex, lua_filename) < 0)
			return 1;
	}
	return 0;
}
