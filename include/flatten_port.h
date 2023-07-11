/**
 * @file flatten_port.h
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Include file responsible solely for selecting proper BSP header
 * 
 */

#ifndef FLATTEN_PORT_H
#define FLATTEN_PORT_H


/*************************************
 * BSP
 *************************************/
#if defined(FLATTEN_KERNEL_BSP)
/* Include kernel module specific header*/
#include "kflat_bsp.h"

#elif defined(FLATTEN_USERSPACE_BSP)
/* Include userspace library specific header */
#include "uflat_bsp.h"

#else /* No BSP selected */
#error "No BSP selected - select proper include path in flatten_port.h"

#endif /* FLATTEN_*_BSP */


/*************************************
 * CONFIGURATION CHECKS
 *************************************/
#if !defined(FLATTEN_LOG_ERROR) || !defined(FLATTEN_LOG_INFO) || !defined(FLATTEN_LOG_DEBUG) || !defined(FLATTEN_LOG_CLEAR)
#error "Missing logging macros (FLATTEN_LOG_*)"
#endif

#if !defined(ADDR_VALID) || !defined(ADDR_RANGE_VALID) || !defined(TEXT_ADDR_VALID) || !defined(STRING_VALID_LEN)
#error "Missing address validation macros (ADDR_*_VALID)"
#endif

#if !defined(FLATTEN_BSP_ZALLOC) || !defined(FLATTEN_BSP_FREE)
#error "Missing allocation macros (flat_zalloc/flat_free)"
#endif

#if !defined(EXPORT_FUNC)
#error "Missing macro for marking exported functions"
#endif


/*************************************
 * DECLs FOR EXTERNAL FUNCS
 *************************************/
size_t flatten_func_to_name(char* name, size_t size, void* func_ptr);
bool flatten_get_object(void* ptr, void** start, void** end);

#endif /* FLATTEN_PORT_H */
