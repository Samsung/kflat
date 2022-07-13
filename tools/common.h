/*
 * Samsung R&D Poland - Mobile Security Group
 */

/*******************************************************
 * LOGGING FUNCTIONS
 *******************************************************/
void init_logging(void);
void log_info(const char* fmt, ...);
void log_error(const char* fmt, ...);
void log_abort(const char* fmt, ...);
