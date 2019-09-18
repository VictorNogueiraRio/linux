#include <linux/if_link.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/resource.h>
#include <net/if.h>

#include "bpf/libbpf.h"

static int ifindex;

static void usage(const char *prog) {
	fprintf(stderr,
			"usage: %s [OPTS] IFACE\n"
			"\nOPTS:\n"
			"    -L LUAFILE     load lua script to XDP\n"
			"    -d             detach program\n"
			"    -F             func name\n",
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

static int do_attach_prog(int idx, char *lua_prog)
{
	int err = 0;

	err = bpf_set_link_xdp_lua_prog(idx, lua_prog);
	if (err < 0)
		printf("ERROR: failed to attach lua script\n");

	return err;
}

static int do_attach_func(int idx, char *lua_funcname)
{
	int err = 0;

	err = bpf_set_link_xdp_lua_func(idx, lua_funcname);
	if (err < 0)
		printf("ERROR: failed to attach lua function\n");

	return err;
}

static int do_detach(int idx)
{
	int err;

	err = bpf_set_link_xdp_lua_func(idx, NULL);
	if (err < 0)
		printf("ERROR: failed to detach program\n");

	return err;
}

int main(int argc, char *argv[])
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	const char *optstr = "F:L:d";
	int opt;
	char lua_filename[256];
	char lua_funcname[256];
	char *lua_prog = NULL;
	int attach = 1;

	memset(lua_funcname, 0, 256);
	memset(lua_filename, 0, 256);
	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
			case 'L':
				snprintf(lua_filename, sizeof(lua_filename),
						"%s", optarg);
				break;
			case 'F':
				snprintf(lua_funcname, sizeof(lua_funcname),
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

	if (attach) {
		if (strlen(lua_filename)) {
			lua_prog = extract_lua_prog(lua_filename);
			if (do_attach_prog(ifindex, lua_prog) < 0)
				return 1;
		}

		if (strlen(lua_funcname)) {
			if (do_attach_func(ifindex, lua_funcname) < 0)
				return 1;
		}
	} else {
		if (do_detach(ifindex) < 0)
			return 1;
	}
	return 0;
}
