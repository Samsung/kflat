#include <iostream>
#include <stdio.h>
#include "ExecFlat.hpp"
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

struct array_element {
    int l;
};

struct inner_struct {
    int k;
    char str[256];
    struct array_element *tab;
    int array_size;
};

struct outer_struct {
    int a;
    int b;
    struct inner_struct *inner;
};

int trigger() {
    struct array_element array[10];

    for (int i = 0; i < 10; i++) {
        array[i].l = i;
    }

    struct inner_struct inner = {
        .k = 5,
        .tab = array,
        .array_size = 10,
    };

    strcpy(inner.str, "Test String\n");

    struct outer_struct outer = {
        .a = 5,
        .b = 10,
        .inner = &inner,
    };



    int fd = open("/sys/kernel/debug/test_ioctl", O_RDONLY);

    if (fd < 0)
        return 1;

    int ret = ioctl(fd, 0, &outer);
    return ret;
}


int main() {
    try {
        ExecFlat flat(2048, ExecFlatOpts::DEBUG);
        bool debug = false;
        bool stop = true;
        flat.run_recipe_custom_target(trigger, "test_ioctl", "dump.kflat", stop, debug, false, false, 0, 0);
    }
    catch (const std::exception &e){
        std::cerr << e.what() << std::endl;
    }
}