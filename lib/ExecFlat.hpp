/**
 * @file ExecFlat.hpp
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief ExecFlat library created to provide an easy API for running KFLAT recipes.
 * 
 */

#ifndef EXECFLAT_HDR
#define EXECFLAT_HDR

#include <sched.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstddef>
#include <poll.h>
#include <signal.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <errno.h>

#include <string>
#include <map>
#include <stdexcept>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <vector>
#include <functional>
#include <system_error>
#include <chrono>
#include <ctime> 
#include <iomanip>

#include "kflat_uapi.h"


#define ERRNO_TO_EXCEPTION(_comment) {                                          \
    std::stringstream __ss;                                                     \
    __ss << "KFLAT: " << (_comment) << "\nERRNO";                              \
    throw std::system_error(errno, std::generic_category(), __ss.str());        \
}                                                                                               
#define LOG(msg_level) ExecFlatLogger((msg_level), log_level, start_time)

namespace fs = std::filesystem;

namespace ExecFlatOpts{
    /**
     * @brief Used as a ExecFlat contructor parameter \n
     * that determines the verbosity level of the ExecFlat library.
     * 
     */
    enum ExecFlatVerbosity {
        SUPRESS,
        ERROR,
        WARNING,
        INFO,
        DEBUG,
    };

    /**
     * @brief Supported types of interfaces for automatic recipe trigger.
     * 
     */
    enum ExecFlatInterface {
        READ,
        SHOW,
        WRITE,
        STORE,
        IOCTL,
        COMPAT_IOCTL,
    };
}

using namespace ExecFlatOpts;

class TermColor {
public:
    enum ColorCode {
        FG_RED      = 31,
        FG_YELLOW   = 33,
        FG_GREEN    = 32,
        FG_BLUE     = 34,
        FG_CYAN     = 36, 
        FG_DEFAULT  = 39,
    };

    static std::string set(ColorCode code) {
        std::stringstream s;
        s << "\033[" << code << "m";
        return s.str();
    }
    
    static std::string clear() {
        std::stringstream s;
        s << "\033[" << FG_DEFAULT << "m";
        return s.str();
    }
};

class ExecFlatLogger {
public:
    ExecFlatLogger( ExecFlatVerbosity msg_level, 
                    ExecFlatVerbosity log_level, 
                    std::chrono::system_clock::time_point start
                    ) : msg_level(msg_level), log_level(log_level), start_time(start) { }

    ~ExecFlatLogger() {
        if (opened)
            std::cerr << std::endl;
        opened = false;
    }

    template<class T>
    ExecFlatLogger &operator<<(const T &msg) {
        if (log_level >= msg_level) {
            if (!opened) {
                std::chrono::duration<double> elapsed = std::chrono::system_clock::now() - start_time;

                std::cerr 
                << TermColor::set(TermColor::FG_GREEN)
                    << "[ExecFlat] [" << std::fixed << elapsed.count() << "] "
                << TermColor::set(get_level_color())
                    << std::setw(8) << get_level_str() << ": "
                << TermColor::clear();
            }
            opened = true;
            std::cerr << msg;
        }

        return *this;
    }

private:
    ExecFlatVerbosity msg_level, log_level;
    bool opened = false; 
    std::chrono::system_clock::time_point start_time;
    
    inline std::string get_level_str() {
        switch (msg_level)
        {
            case WARNING:   return "WARNING";
            case INFO:      return "INFO";
            case DEBUG:     return "DEBUG";    
            case ERROR:     return "ERROR";
            default:        return "UNKNOWN";
        }
    }

    inline TermColor::ColorCode get_level_color() {
        switch (msg_level)
        {
            case WARNING:   return TermColor::FG_YELLOW;
            case INFO:      return TermColor::FG_CYAN;
            case DEBUG:     return TermColor::FG_DEFAULT;    
            case ERROR:     return TermColor::FG_RED;    
            default:        return TermColor::FG_DEFAULT;
        }
    }
};

/**
 * @brief Allow to easily execute KFLAT recipes and save dumps to files.
 * 
 */
class ExecFlat {
public:
    /**
     * @brief Construct and initialize a new ExecFlat object.
     * 
     * @param dump_size Max size of kflat memory dump.
     * @param log_level One of ExecFlatVerbosity enum members.
     */
    ExecFlat(size_t dump_size, ExecFlatVerbosity log_level);
    ~ExecFlat();

    /**
     * @brief Run a KFLAT recipe with a given target file. After enabling KFLAT, chosen file operation will be called on the target.   
     * 
     * @param interface One of ExecFlatInterface. The type of file operation to perform on TARGET.
     * @param target Path to the file to call INTERFACE on.
     * @param recipe Name of the KFLAT recipe. 
     * @param outfile Path to the file where the dump will be saved.
     * @param use_stop_machine Execute the KFLAT recipe under kernel's stop_machine mode.
     * @param debug Enable KFLAT LKM logging to dmesg.
     * @param skip_func_body Skip executing function body after the recipe finishes flattening.
     * @param run_recipe_now Execute KFLAT recipe directly from IOCTL without attaching to any kernel function.
     * @param target_timeout In seconds. Timeout for INTERFACE call on TARGET.
     * @param poll_timeout In miliseconds. Timeout for recipe execution.
     */
    void run_recipe(
        ExecFlatInterface interface, 
        const fs::path &target, 
        const std::string &recipe, 
        const fs::path &outfile, 
        bool use_stop_machine=false, 
        bool debug=true, 
        bool skip_func_body=false,
        bool run_recipe_now=false,
        unsigned int target_timeout=0,
        int poll_timeout=-1
    );

    /** 
     * @brief Run a KFLAT recipe without any specified target. The recipe will wait for an external trigger (e.g. user can manually trigger the target function).
     * 
     * @param recipe Name of the KFLAT recipe. 
     * @param outfile Path to the file where the dump will be saved.
     * @param use_stop_machine Execute the KFLAT recipe under kernel's stop_machine mode.
     * @param debug Enable KFLAT LKM logging to dmesg.
     * @param skip_func_body Skip executing function body after the recipe finishes flattening.
     * @param run_recipe_now Execute KFLAT recipe directly from IOCTL without attaching to any kernel function.
     * @param poll_timeout In miliseconds. Timeout for recipe execution.
     */
    void run_recipe_no_target(
        const std::string &recipe, 
        const fs::path &outfile, 
        bool use_stop_machine=false, 
        bool debug=true, 
        bool skip_func_body=false,
        bool run_recipe_now=false,
        int poll_timeout=-1
    );

    /**
     * @brief Run a KFLAT recipe with a custom trigger function.
     * 
     * @param custom_trigger Function with signature int (). Function that will be executed after enabling KFLAT. \n
                             Executing this should trigger the kernel function with recipe attached.   
     * @param recipe Name of the KFLAT recipe. 
     * @param outfile Path to the file where the dump will be saved.
     * @param use_stop_machine Execute the KFLAT recipe under kernel's stop_machine mode.
     * @param debug Enable KFLAT LKM logging to dmesg.
     * @param skip_func_body Skip executing function body after the recipe finishes flattening.
     * @param run_recipe_now Execute KFLAT recipe directly from IOCTL without attaching to any kernel function.
     * @param target_timeout In seconds. Timeout for INTERFACE call on TARGET.
     * @param poll_timeout In miliseconds. Timeout for recipe execution. 
     */
    void run_recipe_custom_target(
        std::function<int ()> custom_trigger, 
        const std::string &recipe, 
        const fs::path &outfile, 
        bool use_stop_machine=false, 
        bool debug=false, 
        bool skip_func_body=false,
        bool run_recipe_now=false,
        unsigned int target_timeout=0,
        int poll_timeout=-1
    );

    /**
     * @brief Read all KFLAT recipes available to execute.
     * 
     * @return std::vector<std::string> Vector of strings with names of loaded recipes
     */
    std::vector<std::string> get_loaded_recipes();

private:
    // Consts
    const char *KFLAT_NODE = "/sys/kernel/debug/kflat";
    fs::path governor_filepath;
    unsigned int current_cpu;
    static const std::map<ExecFlatInterface, std::function<int (int)>> interface_mapping;

    // Variables
    size_t dump_size;
    ExecFlatVerbosity log_level;
    int kflat_fd;
    size_t out_size; // Actual size returned by KFLAT LKM
    char *shared_memory;
    std::chrono::system_clock::time_point start_time;
    std::string saved_governor;

    // Interfaces
    static int interface_read(int fd);
    static int interface_write(int fd);
    static int interface_ioctl(int fd);

    // Trigger function timeout
    static void sigalrm_handler(int signum);
    void start_alarm(unsigned int time);
    void stop_alarm();

    // Initialization steps
    void open_kflat_node();
    void mmap_kflat();

    // Running recipes
    void kflat_ioctl_enable(struct kflat_ioctl_enable *opts);
    void kflat_ioctl_disable(struct kflat_ioctl_disable *ret);
    void execute_interface(const fs::path &target, ExecFlatInterface interface);
    void do_enable(
        const std::string &recipe, 
        bool use_stop_machine, 
        bool debug, 
        bool skip_func_body,
        bool run_recipe_now,
        int pid
    );
    void disable(const fs::path &outfile, int poll_timeout);

    // CPU governor stuff
    fs::path get_governor_path();
    void set_governor(const std::string &targetGovernor);
    void restore_governor();
};


#endif // EXECFLAT_HDR