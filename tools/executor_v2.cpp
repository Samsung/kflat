/**
 * @file executor_v2.cpp
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief User application that uses ExecFlat to easily execute KFLAT recipes.
 *
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include <filesystem>

#include "ExecFlat.hpp"
#include "argparse.hpp"

namespace fs = std::filesystem;

static std::string format_info(const std::string &str) {
    std::stringstream s;
    s   << TermColor::set(TermColor::FG_BLUE)
        << "[Executor_v2] "
        << TermColor::clear()
        << str << std::endl;
    return s.str();
}


static std::string format_err(const std::runtime_error &e) {
    std::stringstream s;
    s   << TermColor::set(TermColor::FG_BLUE)
        << "[Executor_v2] "
        << TermColor::set(TermColor::FG_RED)
        << "[ERROR] " << TermColor::clear()
        << e.what() << std::endl;
    return s.str();
}

static bool ichar_equals(char a, char b) {
    return std::tolower(static_cast<unsigned char>(a)) ==
           std::tolower(static_cast<unsigned char>(b));
}

static bool iequals(const std::string& a, const std::string& b) {
    return std::equal(a.begin(), a.end(), b.begin(), b.end(), ichar_equals);
}


static ExecFlatOpts::ExecFlatVerbosity get_v_level(const std::string &level) {
    if (iequals(level, "SUPRESS"))
        return ExecFlatOpts::SUPRESS;
    if (iequals(level, "ERROR"))
        return ExecFlatOpts::ERROR;
    if (iequals(level, "WARNING"))
        return ExecFlatOpts::WARNING;
    if (iequals(level, "INFO"))
        return ExecFlatOpts::INFO;
    if (iequals(level, "DEBUG"))
        return ExecFlatOpts::DEBUG;

    return ExecFlatOpts::WARNING;
}


static ExecFlatOpts::ExecFlatInterface get_interface(const std::string &s) {
    if (iequals(s, "READ"))
        return ExecFlatOpts::READ;
    if (iequals(s, "SHOW"))
        return ExecFlatOpts::SHOW;
    if (iequals(s, "WRITE"))
        return ExecFlatOpts::WRITE;
    if (iequals(s, "STORE"))
        return ExecFlatOpts::STORE;
    if (iequals(s, "IOCTL"))
        return ExecFlatOpts::IOCTL;
    if (iequals(s, "COMPAT_IOCTL"))
        return ExecFlatOpts::COMPAT_IOCTL;

    throw std::runtime_error("INTERFACE should be one of READ, SHOW, WRITE, STORE, IOCTL, COMPAT_IOCTL");
}


static int run_executor_v2_32(char **argv, char **envp) {
    int ret = execve("executor_v2_32", argv, envp);

    if (ret != 0 && errno == ENOENT)
        throw std::system_error(errno, std::generic_category(), "Failed to locate 'executor_32' binary needed to execute compat_ioctl.");
    else
        throw std::system_error(errno, std::generic_category(), "Failed to spawn 32-bit executor app");

    return ret;
}


int main(int argc, char **argv, char **envp) {
    // Common options for both modes
    argparse::ArgumentParser program(argv[0], "1.0", argparse::default_arguments::none);
    program.add_description("Userspace interface for triggering KFLAT recipes.");

    program.add_argument("-o", "--output")
        .help("File to save the kflat dump.")
        .required()
        .default_value(std::string("dump.kflat"))
        .metavar("PATH")
        .nargs(1);

    program.add_argument("-d", "--debug")
        .help("Enable KFLAT debug logging to dmesg.")
        .flag();

    program.add_argument("-f", "--run_recipe_now")
        .help("Execute KFLAT recipe directly from the IOCTL without attachking to any kernel function.")
        .flag();

    program.add_argument("-n", "--skip_function_body")
        .help("Do not execute target function body after flattening memory.")
        .flag();

    program.add_argument("-s", "--stop_machine")
        .help("Execute KFLAT recipe under kernel's stop_machine mode.")
        .flag();

    program.add_argument("-p", "--poll_timeout")
        .help("In miliseconds. Timeout for recipe execution")
        .scan<'i', int>()
        .required()
        .default_value(5000)
        .metavar("TIMEOUT")
        .nargs(1);

    program.add_argument("-u", "--dump_size")
        .help("Max dump size of the kflat image - effectively the size of mmaped kflat memory.")
        .required()
        .default_value<unsigned int>(100 * 1024 * 1024)
        .scan<'i', unsigned int>()
        .metavar("DUMP_SIZE")
        .nargs(1);

    program.add_argument("-y", "--verbosity")
        .help("Verbosity level of ExecFlat library.")
        .default_value<std::string>("INFO")
        .required()
        .metavar("VERBOSITY_LEVEL")
        .nargs(1);

    // Run with a predefined interface and target
    argparse::ArgumentParser auto_trigger("AUTO");

    auto_trigger.add_description("Enable flattening and automatically trigger a recipe via one of available interfaces.");
    auto_trigger.add_argument("recipe")
        .help("Recipe to be run");
    auto_trigger.add_argument("interface")
        .help("Select interface type (READ, SHOW, WRITE, STORE, IOCTL, COMPAT_IOCTL).");
    auto_trigger.add_argument("target")
        .help("File that the INTERFACE will be called on.");
    auto_trigger.add_argument("-t", "--io_timeout")
        .help("In seconds. Timeout for waiting on the I/O interface operation.")
        .scan<'i', int>()
        .default_value(2)
        .metavar("TIMEOUT")
        .nargs(1);

    // User has to trigger the recipe manually
    argparse::ArgumentParser manual_trigger("MANUAL");
    manual_trigger.add_description("Enable flattening but you need to trigger a recipe by yourself.");
    manual_trigger.add_argument("recipe")
        .help("Recipe to be run");


    // Listing all loaded KFLAT recipes
    argparse::ArgumentParser lister("LIST");
    lister.add_description("List all recipe modules.");

    program.add_subparser(auto_trigger);
    program.add_subparser(manual_trigger);
    program.add_subparser(lister);


    try {
        program.parse_args(argc, argv);
    }
    catch (const std::exception& err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        return 1;
    }

    auto debug =        program.get<bool>("--debug");
    auto output =       program.get<std::string>("--output");
    auto run_now =      program.get<bool>("--run_recipe_now");
    auto skip_body =    program.get<bool>("--skip_function_body");
    auto stop_machine = program.get<bool>("--stop_machine");
    auto poll_timeout = program.get<int>("--poll_timeout");
    if (poll_timeout <= 0)
        poll_timeout = -1;
    auto dump_size =    program.get<unsigned int>("--dump_size");
    auto verbosity =    get_v_level(program.get<std::string>("--verbosity"));

    try {
        /* ===================== AUTO MODE ======================== */
        if (program.is_subcommand_used(auto_trigger)) {
            auto interface = get_interface(program.at<argparse::ArgumentParser>("AUTO").get<std::string>("interface"));
#ifndef ENV_32
            // Check for special case if user is invoking compat_ioctl
            if (interface == ExecFlatOpts::COMPAT_IOCTL) {
                return run_executor_v2_32(argv, envp);
            }
#endif // ENV_32
            std::cout << format_info("Starting executor_v2 in AUTO mode...");
            auto io_timeout = program.at<argparse::ArgumentParser>("AUTO").get<int>("--io_timeout");
            auto recipe = program.at<argparse::ArgumentParser>("AUTO").get<std::string>("recipe");
            auto target = program.at<argparse::ArgumentParser>("AUTO").get<std::string>("target");

            ExecFlat kflat(dump_size, verbosity);
            kflat.run_recipe(interface, target, recipe, output, stop_machine, debug, skip_body, run_now, io_timeout, poll_timeout);
        }
        /* ===================== MANUAL MODE ======================== */
        else if (program.is_subcommand_used(manual_trigger)) {
            std::cout << format_info("Starting executor_v2 in MANUAL mode...");
            auto recipe = program.at<argparse::ArgumentParser>("MANUAL").get<std::string>("recipe");

            ExecFlat kflat(dump_size, verbosity);
            kflat.run_recipe_no_target(recipe, output, stop_machine, debug, skip_body, run_now, poll_timeout);
        }
        /* ===================== LIST MODE ======================== */
        else if (program.is_subcommand_used(lister)) {
            std::cout << format_info("Starting executor_v2 in LIST mode...");
            ExecFlat kflat(dump_size, verbosity);
            std::cout << format_info("Listing available recipes:");
            int i = 0;
            for (const auto &recipe : kflat.get_loaded_recipes()) {
                std::cout << i++ << ": " << recipe << std::endl;
            }
        }
        /* ===================== ERROR ======================== */
        else {
            std::cerr << program;
            return 1;
        }
    }
    catch (const std::runtime_error& err) {
        std::cerr << format_err(err);
        return 1;
    }
    std::cout << format_info("Executor exiting...");
    return 0;
}
