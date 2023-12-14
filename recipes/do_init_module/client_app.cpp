#define _GNU_SOURCE
#include "ExecFlat.hpp"
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>

#define finit_module(fd, param_values, flags) syscall(__NR_finit_module, fd, param_values, flags)
#define delete_module(name, flags) syscall(__NR_delete_module, name, flags)

int trigger() {
    int fd = open("../random_read/random_read_recipe.ko", O_RDONLY);
    int ret = finit_module(fd, "", 0);
    if (!ret) {
        ret = delete_module("random_read_recipe", O_NONBLOCK);
    }
    close(fd);

    return ret;
}


int main(int argc, char const *argv[])
{
    try {
        ExecFlat kflat(1024 * 1024, ExecFlatOpts::DEBUG);
        kflat.run_recipe_custom_target(trigger, "do_init_module", "dump.kflat");
    }
    catch (const std::exception &e) {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}