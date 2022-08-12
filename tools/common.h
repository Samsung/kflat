/**
 * @file common.h
 * @author Samsung R&D Poland - Mobile Security Group
 * @brief Logging library
 * 
 */

#undef noreturn

#define LOG_ERR_COLOR           "\x1b[31m"
#define LOG_INFO_COLOR          "\x1b[32m"

void init_logging(void);
void log_generic(const char* color, const char* prefix, const char* func, const char* fmt, ...);
void _log_abort(const char* func, const char* fmt, ...) __attribute__ ((noreturn));

#define log_info(fmt, ...)      log_generic(LOG_INFO_COLOR, "+", __func__, fmt, ##__VA_ARGS__)
#define log_error(fmt, ...)     log_generic(LOG_ERR_COLOR, "!", __func__, fmt, ##__VA_ARGS__)
#define log_abort(fmt, ...)     _log_abort(__func__, fmt, ##__VA_ARGS__)
