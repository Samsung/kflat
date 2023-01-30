/**
 * @file common.h
 * @author Samsung R&D Poland - Mobile Security Group
 * @brief Logging library
 * 
 */

#include <stdbool.h>

#undef noreturn

// Coloring macros
#define LOG_DEFAULT_COLOR       "\x1b[0m"
#define LOG_ERR_COLOR           "\x1b[31m"
#define LOG_INFO_COLOR          "\x1b[32m"
#define LOG_WARN_COLOR          "\x1b[1;33m"
#define LOG_TIME_COLOR          "\x1b[36m"
#define LOG_FUNC_COLOR          "\x1b[33m"

#define OUTPUT_COLOR(COLOR)     (is_color_capable() ? COLOR : "")

// Exported functions
void init_logging(void);
void log_generic(const char* color, const char* prefix, const char* func, bool new_line, const char* fmt, ...);
void _log_abort(const char* func, const char* fmt, ...) __attribute__ ((noreturn));
bool is_color_capable(void);

// Macros for setting verbosity level
#define log_info_continue(fmt, ...) log_generic(LOG_INFO_COLOR, "+", __func__, false, fmt, ##__VA_ARGS__)
#define log_info(fmt, ...)          log_generic(LOG_INFO_COLOR, "+", __func__, true, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...)         log_generic(LOG_ERR_COLOR, "!", __func__, true, fmt, ##__VA_ARGS__)
#define log_abort(fmt, ...)         _log_abort(__func__, fmt, ##__VA_ARGS__)
