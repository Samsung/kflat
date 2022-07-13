/*
 * Samsung R&D Poland - Mobile Security Group
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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
                        LOG_FUNC_COLOR "%-10s|" LOG_DEFAULT_COLOR " ",
                        color, prefix, log_time(), func);
    else
        fprintf(stdout, "[%s][%7.3lf] %-10s| ", prefix, log_time(), func);

    vfprintf(stdout, fmt, args);
    fputs("\n", stdout);
}


void init_logging(void) {
    // Check whether we're attached to tty terminal
    //  If so, enable colorful logs
    if(isatty(fileno(stdout)))
        supports_colors = true;

    start_time = log_time();
}

void log_info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    _log_generic(stdout, LOG_INFO_COLOR, "+", __func__, fmt, args);
    va_end(args);
}

void log_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    _log_generic(stderr, LOG_ERR_COLOR, "!", __func__, fmt, args);
    va_end(args);
}

void log_abort(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    _log_generic(stderr, LOG_ERR_COLOR, "ABORT", __func__, fmt, args);
    va_end(args);

    exit(1);
}
