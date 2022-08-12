/*
 * Samsung R&D Poland - Mobile Security Group
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>


/*******************************************************
 * LOGGING FUNCTIONS
 *******************************************************/
#define LOG_DEFAULT_COLOR       "\x1b[0m"
#define LOG_ERR_COLOR           "\x1b[31m"
#define LOG_INFO_COLOR          "\x1b[32m"
#define LOG_TIME_COLOR          "\x1b[36m"
#define LOG_FUNC_COLOR          "\x1b[33m"

static bool supports_colors = false;
static double start_time = 0;


static double log_time(void) {
    struct timeval time;
    gettimeofday(&time, NULL);

    return (double)time.tv_sec + time.tv_usec / 1000000.0 - start_time;
}

static void _log_generic(FILE* stream, const char* color, const char* prefix, 
                        const char* func, const char* fmt, va_list args) {
    if(supports_colors)
        fprintf(stdout, "[%s%s" LOG_DEFAULT_COLOR "][" 
                        LOG_TIME_COLOR "%7.3lf" LOG_DEFAULT_COLOR "] "
                        LOG_FUNC_COLOR "%-*s|" LOG_DEFAULT_COLOR " ",
                        color, prefix, log_time(), 15 - (int) strlen(prefix), func);
    else
        fprintf(stdout, "[%s][%7.3lf] %-10s| ", prefix, log_time(), func);

    vfprintf(stdout, fmt, args);
    fputs("\n", stdout);
}

void log_generic(const char* color, const char* prefix, const char* func, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    _log_generic(stdout, color, prefix, func, fmt, args);
    va_end(args);
}

void _log_abort(const char* func, const char* fmt, ...) {
    va_list args;
    char* err_msg;

    va_start(args, fmt);
    _log_generic(stdout, LOG_ERR_COLOR, "X", func, fmt, args);
    va_end(args);

    if(supports_colors)
        err_msg = "---|  " LOG_ERR_COLOR "Program aborted" LOG_DEFAULT_COLOR "  |---\n";
    else
        err_msg = "---|  Program aborted  |---\n";
    fputs(err_msg, stdout);

    exit(1);
}


void init_logging(void) {
    // Check whether we're attached to tty terminal
    //  If so, enable colorful logs
    if(isatty(fileno(stdout)))
        supports_colors = true;

    start_time = log_time();
}
