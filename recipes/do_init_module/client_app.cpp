#define _GNU_SOURCE
#include "ExecFlat.hpp"
#include "unflatten.hpp"
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define finit_module(fd, param_values, flags) syscall(__NR_finit_module, fd, param_values, flags)
#define delete_module(name, flags) syscall(__NR_delete_module, name, flags)

int trigger() {
    int fd = open("../random_read/random_read.ko", O_RDONLY);
    int ret = finit_module(fd, "", 0);
    if (!ret) {
        ret = delete_module("random_read", O_NONBLOCK);
    }
    close(fd);

    return ret;
}

enum module_state {
	MODULE_STATE_LIVE,	/* Normal state. */
	MODULE_STATE_COMING,	/* Full formed, running module_init. */
	MODULE_STATE_GOING,	/* Going away. */
	MODULE_STATE_UNFORMED,	/* Still setting it up. */
};

struct kernfs_node {
	int		count;
	int		active;
	struct kernfs_node	*parent;
	const char		*name;
};

struct kobject {
	const char		*name;
	char list_head[0x10];
	struct kobject		*parent;
	void		*kset;
	void	*ktype;
	struct kernfs_node	*sd; /* sysfs directory entry */
};

struct module {
    enum module_state state;
    char list_head[0x10];
    char name[0x38];
    char mkobj[0x60];
    void *modinfo_attr;
    const char *version;
    const char *srcversion;
    struct kobject *holders_dir;
    const void *syms;
	const void *crcs;
    unsigned int num_syms;
};



const char *get_mod_status(enum module_state stat) {
    switch (stat) {
        case MODULE_STATE_LIVE:
            return "MODULE_STATE_LIVE";
        case MODULE_STATE_COMING:
            return "MODULE_STATE_COMING";
        case MODULE_STATE_GOING:
            return "MODULE_STATE_GOING";
        case MODULE_STATE_UNFORMED:
            return "MODULE_STATE_UNFORMED";
    }
    return "UNKNOWN";
}

#define READ_OF_TYPE(addr_, type_) (*(type_ *) (addr_))

int main(int argc, char const *argv[])
{
    try {
        ExecFlat kflat(1024 * 1024, ExecFlatOpts::DEBUG);
        kflat.run_recipe_custom_target(trigger, "do_init_module", "dump.kflat");

        Unflatten flatten;

        FILE* f = fopen("dump.kflat", "r");
        flatten.load(f, NULL);

        struct module *m = (struct module *) flatten.get_next_root();

        printf("Module name = %s\nModule state = %s\nHolder dir name = %s\nNum Syms = %d\nKernfs_node name = %s\n", m->name + 4, get_mod_status(m->state), m->holders_dir->name, m->num_syms, m->holders_dir->sd->name);
    }
    catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}