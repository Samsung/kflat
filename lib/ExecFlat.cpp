/**
 * @file ExecFlat.cpp
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief ExecFlat library created to provide an easy API for running KFLAT recipes.
 * 
 */

#include "ExecFlat.hpp"

// Mapping of interface enum to handlers
const std::map<ExecFlatInterface, std::function<int (int)>> ExecFlat::interface_mapping = {
    {READ, ExecFlat::interface_read},
    {SHOW, ExecFlat::interface_read},
    {WRITE, ExecFlat::interface_write},
    {STORE, ExecFlat::interface_write},
    {IOCTL, ExecFlat::interface_ioctl},
    {COMPAT_IOCTL, ExecFlat::interface_ioctl},
};


static inline const char* ExecFlatInterface_to_string(ExecFlatInterface v) {
    switch (v)
    {
        case READ: return "READ";
        case SHOW: return "SHOW";
        case WRITE: return "WRITE";
        case STORE: return "STORE";
        case IOCTL: return "IOCTL";
        case COMPAT_IOCTL: return "COMPAT_IOCTL";
        default: return "UNKNOWN";
    }
}


int ExecFlat::interface_read(int fd) {
    char buffer[512];
    return read(fd, buffer, sizeof(buffer));
}

int ExecFlat::interface_write(int fd) {
    char buffer[512] = {'a', 0};
    return write(fd, buffer, sizeof(buffer));
}

int ExecFlat::interface_ioctl(int fd) {
    return ioctl(fd, 0, 0);
}

void ExecFlat::sigalrm_handler(int signum) { }

ExecFlat::ExecFlat(size_t dump_size, ExecFlatVerbosity log_level) : dump_size(dump_size), log_level(log_level) {
    out_size = 0;
    start_time = std::chrono::system_clock::now();
    LOG(INFO) << "Initializing ExecFlat...";
    open_kflat_node();
    mmap_kflat();

    // We need to make sure that the execution stays on the same CPU
    getcpu(&current_cpu, NULL);

    cpu_set_t cpu_mask;
    CPU_ZERO(&cpu_mask);
    CPU_SET(current_cpu, &cpu_mask);

    sched_setaffinity(0, sizeof(cpu_mask), &cpu_mask);

    governor_filepath = get_governor_path();

    set_governor("performance");
}

ExecFlat::~ExecFlat() {
    restore_governor();
    munmap(shared_memory, dump_size);
    close(kflat_fd);
    LOG(INFO) << "Quitting ExecFlat...";
}

void ExecFlat::do_enable(
        const std::string &recipe, 
        bool use_stop_machine, 
        bool debug, 
        bool skip_func_body,
        bool run_recipe_now,
        int pid
    ) {
        out_size = 0;

        struct kflat_ioctl_enable opts = { 0, };
        
        opts.pid = pid;
        opts.debug_flag = debug;
        opts.use_stop_machine = use_stop_machine;
        opts.skip_function_body = skip_func_body;
        opts.run_recipe_now = run_recipe_now;

        strncpy(opts.target_name, recipe.c_str(), sizeof(opts.target_name) - 1);

        LOG(INFO) << "Starting KFLAT for " << recipe;
        
        kflat_ioctl_enable(&opts);
    }

void ExecFlat::run_recipe(
        ExecFlatInterface interface, 
        const fs::path &target, 
        const std::string &recipe, 
        const fs::path &outfile,
        bool use_stop_machine, 
        bool debug, 
        bool skip_func_body, 
        bool run_recipe_now,
        unsigned int target_timeout,
        int poll_timeout
    ) {    
    do_enable(
        recipe, 
        use_stop_machine, 
        debug, 
        skip_func_body, 
        run_recipe_now,
        getpid()
    );

    start_alarm(target_timeout);
    execute_interface(target, interface);
    stop_alarm();

    disable(outfile, poll_timeout);
}

void ExecFlat::run_recipe_no_target(
        const std::string &recipe, 
        const fs::path &outfile,
        bool use_stop_machine,  
        bool debug, 
        bool skip_func_body, 
        bool run_recipe_now,
        int poll_timeout
    ) {
    
    do_enable(
        recipe, 
        use_stop_machine, 
        debug, 
        skip_func_body, 
        run_recipe_now,
        -1
    );

    LOG(INFO) << "Waiting for the recipe to be externally triggered.";

    disable(outfile, poll_timeout);
}

void ExecFlat::run_recipe_custom_target(
        std::function<int ()> custom_trigger, 
        const std::string &recipe, 
        const fs::path &outfile, 
        bool use_stop_machine, 
        bool debug, 
        bool skip_func_body,
        bool run_recipe_now,
        unsigned int target_timeout,
        int poll_timeout
    ) {
        do_enable(
        recipe, 
        use_stop_machine, 
        debug, 
        skip_func_body, 
        run_recipe_now,
        getpid()
    );

    start_alarm(target_timeout);

    int ret = custom_trigger();
    LOG(DEBUG) << "Custom trigger function returned " << ret;

    stop_alarm();

    disable(outfile, poll_timeout);
    }

void ExecFlat::start_alarm(unsigned int time) {
    if (!time)
        return;

    struct sigaction act = {0, };
    act.sa_handler = sigalrm_handler;
    int ret = sigaction(SIGALRM, &act, NULL);
    if (ret) {
        LOG(WARNING) << "Failed to start alarm";
    }
    alarm(time);
}

void ExecFlat::stop_alarm() {
    alarm(0);
}

void ExecFlat::disable(const fs::path &outfile, int poll_timeout) {
    struct pollfd kflat_poll;
    kflat_poll.fd = kflat_fd;
    kflat_poll.events = POLLIN | POLLRDNORM;

    int ret_poll = poll(&kflat_poll, 1, (poll_timeout ? poll_timeout : -1));

    if (ret_poll == 0) {
        throw std::runtime_error("Recipe failed to execute before the poll timeout");
    }
    if (ret_poll == -1) {
        ERRNO_TO_EXCEPTION("Poll failed");
    }

    struct kflat_ioctl_disable ret = {0};
    kflat_ioctl_disable(&ret);

    if (!ret.invoked) {
        errno = ret.error;
        ERRNO_TO_EXCEPTION("KFLAT_PROC_DISABLE IOCTL returned: recipe not invoked. KFLAT flattening engine reported an error while processing selected recipe.");
    }

    out_size = ret.size;
    if (out_size > dump_size) {
        std::stringstream ss;
        ss << "KFLAT produced image larger than the mmaped memory (kernel bug?).\nKernel size: " << out_size << " User size: " << dump_size;
        throw std::runtime_error(ss.str());
    }
    std::ofstream file(outfile, std::ofstream::binary);
    file.write(shared_memory, out_size);

    if (file.bad()) {
        throw std::runtime_error("Failed to save memory dump to a file.");
    }

    file.close();

    LOG(INFO) << "Recipe successfully executed. Dump saved to " << outfile;
}

std::vector<std::string> ExecFlat::get_loaded_recipes() {
    char buf[4096];
    std::vector<std::string> recipes;
    std::string str;
    int ret = ioctl(kflat_fd, KFLAT_GET_LOADED_RECIPES, buf);
    if (ret < 0) 
        throw std::runtime_error("KFLAT_GET_LOADED_RECIPES failed.");
    
    for(const char* p = buf; p < buf + ret; p += recipes.back().size() + 1) {
        recipes.push_back(p);
    }

    return recipes;
}

void ExecFlat::open_kflat_node() {
    kflat_fd = open(KFLAT_NODE, O_RDONLY);

    if (kflat_fd < 0 && errno == ENOENT) {
        ERRNO_TO_EXCEPTION("Failed to open KLAT node. Make sure debugfs is mounted and kflat_code.ko is loaded into the kernel.");
    }
    else if (kflat_fd < 0) {
        ERRNO_TO_EXCEPTION("Failed to open KFLAT node.");
    }

    LOG(DEBUG) << "Successfully opened " << KFLAT_NODE;
}

void ExecFlat::mmap_kflat() {
    shared_memory = static_cast<char *> (mmap(0, dump_size, PROT_READ, MAP_SHARED, kflat_fd, 0));
    if (shared_memory == MAP_FAILED){
        ERRNO_TO_EXCEPTION("Failed to mmap kflat memory");
    }

    LOG(DEBUG) << "Kflat memory mapped at " << (void *) shared_memory;
}


void ExecFlat::kflat_ioctl_enable(struct kflat_ioctl_enable *opts) {    
    int r = ioctl(kflat_fd, KFLAT_PROC_ENABLE, opts);

    if (r != 0 && errno == ENOENT) {
        ERRNO_TO_EXCEPTION("Recipe with given name couldn't be found. Please make sure that the module with desired recipe was loaded. The name of the recipe is the name of the function that KFLAT attaches to.");
    } else if (r != 0) {
        ERRNO_TO_EXCEPTION("Failed to enable flattening.");
    }
    
    LOG(DEBUG) << "KFLAT_PROC_ENABLE ioctl returned " << r;
}

void ExecFlat::kflat_ioctl_disable(struct kflat_ioctl_disable *ret) {
    int r = ioctl(kflat_fd, KFLAT_PROC_DISABLE, ret);
    if (r != 0)
         ERRNO_TO_EXCEPTION("Failed to disable flattening");

    LOG(DEBUG) << "KFLAT_PROC_DISABLE ioctl returned " << r;
}

void ExecFlat::execute_interface(const fs::path &target, ExecFlatInterface interface) {
    int flags = O_RDONLY | O_NONBLOCK;

    if (interface == WRITE || interface == STORE)
        flags |= O_WRONLY;

    int fd = open(target.c_str(), flags);

    if (fd < 0) {
        switch (errno) {
            case ENOENT:
                ERRNO_TO_EXCEPTION("Failed to open provided device node. Verify that provided path is correct and exists on the device.");
            case EINTR:
                ERRNO_TO_EXCEPTION("Timeout when trying to open the target file. File is unresponsive.");
            case EPERM:
                ERRNO_TO_EXCEPTION("Permission to the provided device node was denied. Verify that current user has neccessary permissions to access it.");
            default:
                ERRNO_TO_EXCEPTION("Failed to open the target file.");
        }
    }


    std::function interface_executor = interface_mapping.at(interface);
    int ret = interface_executor(fd);

    auto logger_stream = ret == -1 ? LOG(WARNING) : LOG(INFO);

    logger_stream << ExecFlatInterface_to_string(interface) << " called on " << target << " returned " << ret;
}


fs::path ExecFlat::get_governor_path() {
    std::stringstream ss;
    ss << "cpu" << current_cpu; 
    fs::path path = fs::path("/sys/devices/system/cpu/") / ss.str() / "cpufreq/scaling_governor";

    return path;
}


void ExecFlat::set_governor(const std::string &targetGovernor) {
    saved_governor.clear();
    
    std::fstream governor_file(governor_filepath);
    if (governor_file) {
        if(!(governor_file >> saved_governor)) {
            LOG(WARNING) << "Failed to read the current CPU governor";
            governor_file.close();
            return;
        }
        LOG(DEBUG) << "Saved current CPU governor \"" << saved_governor << "\""; 

        governor_file.clear();
        governor_file.seekg(0);

        if (!(governor_file << targetGovernor)){
            LOG(WARNING) << "Failed to set the CPU governor";
            saved_governor.clear(); // Clear because we don't need to restore it later.
            governor_file.close();
            return;
        }
        LOG(DEBUG) << "Set the CPU governor to \"" << targetGovernor << "\"";
    }
    else {
        LOG(WARNING) << "Failed to open " << governor_filepath;
    }
    governor_file.close();
}
 
void ExecFlat::restore_governor() {
    if (saved_governor.empty())
        return;
    
    std::fstream governor_file(governor_filepath);
    if (!governor_file) {
        LOG(WARNING) << "Failed to open " << governor_filepath;
        return; 
    }

    if (!(governor_file << saved_governor)) {
        LOG(WARNING) << "Failed to restore the CPU governor";
    } 
    else {
        LOG(DEBUG) << "Restored the CPU governor to \"" << saved_governor << "\"";
    }

    governor_file.close();
    return;
}



