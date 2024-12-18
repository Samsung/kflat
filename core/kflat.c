/**
 * @file kflat.c
 * @author Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)
 * @brief Collection of driver's entry points for userspace
 *
 * File operations have been slightly inspired by Linux KCOV
 */
#include "kflat.h"
#include "probing.h"
#include "tests/kflat_tests_list.h"

#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/stop_machine.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/list.h>
#include <linux/poll.h>

#if defined(CONFIG_KASAN)
#include <linux/kasan.h>
#endif

/*******************************************************
 * MODULE PARAMETERS
 *******************************************************/
static int dbg_buffer_size = 50 * 1024 * 1024; // 50MB
module_param(dbg_buffer_size, int, 0660);
MODULE_PARM_DESC(dbg_buffer_size, "size of dbg buf used when flattening with debug flag enabled");

/*******************************************************
 * NON-EXPORTED FUNCTIONS
 *******************************************************/
int kflat_ioctl_test(struct kflat* kflat, unsigned int cmd, unsigned long arg);

/*******************************************************
 * REFCOUNTS
 *******************************************************/
void kflat_get(struct kflat* kflat) {
    atomic_inc(&kflat->refcount);
}

void kflat_put(struct kflat* kflat) {
    if(atomic_dec_and_test(&kflat->refcount)) {
        kflat_recipe_put(kflat->recipe);
        kflat->recipe = NULL;
        vfree(kflat->flat.area);
        kfree(kflat);
    }
}

/*******************************************************
 * DEBUG AREA
 *  When running kflat with debug flag enabled it is necessary
 *  to dump a lot of data describing what's going on under the
 *  hood. Here is a simple implementation of printk-like function
 *  using buffer of an arbitrary size
 *******************************************************/
static struct {
    void* mem;
    size_t size;
    size_t offset;
} _dbg_buffer;

// Use spinlock: kflat_dbg_printf can be run in atomic context
DEFINE_SPINLOCK(kflat_dbg_lock);

static int kflat_dbg_buf_init(const size_t buffer_size) {
    void* mem_to_release = NULL;
    void* new_memory;
    unsigned long flags;

    // Check whether fine memory is already allocated
    spin_lock_irqsave(&kflat_dbg_lock, flags);
    if(_dbg_buffer.mem != NULL)
        if(_dbg_buffer.size == buffer_size) {
            _dbg_buffer.offset = 0;
            goto exit;
        }
    spin_unlock_irqrestore(&kflat_dbg_lock, flags);

    // New buffer need to be allocated
    new_memory = vmalloc(buffer_size);
    if(new_memory == NULL) {
        WARN_ONCE(1, "Failed to allocate buffer for kflat debug logs");
        return -ENOMEM;
    }

    spin_lock_irqsave(&kflat_dbg_lock, flags);
    if(_dbg_buffer.mem != NULL) {
        if(_dbg_buffer.size == buffer_size) {
            // This buffer is just fine - release new_memory
            _dbg_buffer.offset = 0;
            mem_to_release = new_memory;
            goto exit;
        }
        // Release old memory
        mem_to_release = _dbg_buffer.mem;
    }

    _dbg_buffer.mem = new_memory;
    _dbg_buffer.size = buffer_size;
    _dbg_buffer.offset = 0;

exit:
    spin_unlock_irqrestore(&kflat_dbg_lock, flags);
    vfree(mem_to_release);
    return 0;
}

static void kflat_dbg_buf_deinit(void) {
    unsigned long flags;
    void* mem_to_release;

    spin_lock_irqsave(&kflat_dbg_lock, flags);
    mem_to_release = _dbg_buffer.mem;
    _dbg_buffer.mem = NULL;
    _dbg_buffer.offset = 0;
    _dbg_buffer.size = 0;
    spin_unlock_irqrestore(&kflat_dbg_lock, flags);

    vfree(mem_to_release);
}

void kflat_dbg_buf_clear(void) {
    unsigned long flags;
    spin_lock_irqsave(&kflat_dbg_lock, flags);
    _dbg_buffer.offset = 0;
    spin_unlock_irqrestore(&kflat_dbg_lock, flags);
}

static ssize_t kflat_dbg_buf_read(struct file* file, char* __user buffer, size_t size, loff_t* ppos) {
    ssize_t ret = 0;
    loff_t pos = *ppos;
    void* page;
    unsigned long flags;

    if(pos < 0)
        return -EINVAL;
    if(size == 0)
        return 0;
    else if(size > PAGE_SIZE)
        size = PAGE_SIZE;

    page = (void*)__get_free_page(GFP_KERNEL);
    if(page == NULL)
        return -ENOMEM;

    spin_lock_irqsave(&kflat_dbg_lock, flags);
    if(_dbg_buffer.mem == NULL || _dbg_buffer.offset == 0 || pos > _dbg_buffer.offset) {
        size = 0;
        goto exit;
    }
    if(size > _dbg_buffer.offset - pos)
        size = _dbg_buffer.offset - pos;
    memcpy(page, _dbg_buffer.mem + pos, size);

exit:
    spin_unlock_irqrestore(&kflat_dbg_lock, flags);

    ret = copy_to_user(buffer, page, size);
    if(ret)
        return -EFAULT;
    *ppos = pos + size;

    free_page((unsigned long)page);
    return size;
}

void kflat_dbg_printf(const char* fmt, ...) {
    long avail_size, written;
    unsigned long flags;
    va_list args;

    spin_lock_irqsave(&kflat_dbg_lock, flags);

    if(_dbg_buffer.mem == NULL)
        goto exit;

    avail_size = _dbg_buffer.size - _dbg_buffer.offset;
    if(avail_size < 0)
        goto exit;

    va_start(args, fmt);
    written = vscnprintf(_dbg_buffer.mem + _dbg_buffer.offset, avail_size, fmt, args);
    va_end(args);

    _dbg_buffer.offset += written;

exit:
    spin_unlock_irqrestore(&kflat_dbg_lock, flags);
    return;
}
EXPORT_SYMBOL_GPL(kflat_dbg_printf);

/*******************************************************
 * STOP_MACHINE SUPPORT
 *  Some structures that user wishes to dump with kflat
 *  may be heavily used by kernel. In such cases, there's
 *  huge chance that kflat code will be exposed to data
 *  races while accessing such structures without
 *  synchronization.
 *
 *  To overcome this issue, user can request kflat to use
 *  kernel's stop_machine functionality which basically stops
 *  all other CPUs and disables interrupts, therefore giving
 *  kflat exclusive access to the targeted structure.
 ******************************************************/
struct stopm_args {
    struct kflat* kflat;
    struct probe_regs* regs;
    void (*handler)(struct kflat*, struct probe_regs*);
};

static int _stop_machine_func(void* arg) {
    struct stopm_args* stopm = (struct stopm_args*)arg;
#if defined(CONFIG_KASAN)
    kasan_disable_current();
#endif

    pr_info("--- Stop machine started ---");
    stopm->handler(stopm->kflat, stopm->regs);
    pr_info("-- Stop machine finishing ---");

#if defined(CONFIG_KASAN)
    kasan_enable_current();
#endif
    return 0;
}

static int flatten_stop_machine(struct kflat* kflat, struct probe_regs* regs) {
    int err;
    cpumask_t cpumask;
    struct stopm_args arg = {
        .kflat = kflat,
        .regs = regs,
        .handler = kflat->recipe->handler,
    };

    cpumask_clear(&cpumask);
    cpumask_set_cpu(raw_smp_processor_id(), &cpumask);

    err = stop_machine(_stop_machine_func, (void*)&arg, &cpumask);
    if(err)
        pr_err("@Flatten stop_machine failed: %d", err);
    return err;
}

/*******************************************************
 * PROBING DELEGATE
 *  This functions will be invoked after kprobe successfully
 *  reroutes execution flow in kernel. In here, argument regs
 *  contains the copy of all registers values (useful for
 *  extracting function arguments).
 *
 *  This functions returns uint64_t containing the address
 *  to which kprobe should return.
 *******************************************************/
asmlinkage __used uint64_t probing_delegate(struct probe_regs* regs) {
    int err;
    uint64_t return_addr;
    struct kflat* kflat;

    pr_info("flatten started");

    // Extract pointer to KFLAT structure provided by `probing_pre_handler`
    kflat = (struct kflat*)regs->kflat_ptr;
    if(kflat == NULL)
        BUG();

    // Make sure this isn't atomic context. Kprobe might have been attached to
    //  interrupt function
    if(in_atomic()) {
        pr_err("This is still an atomic context. Attaching to a non-preemtible code is not supported");
        kflat->flat.error = EFAULT;
        goto probing_exit;
    }

    flatten_init(&kflat->flat);
    kflat->flat.FLCTRL.debug_flag = kflat->debug_flag;

    if(kflat->recipe->pre_handler)
        kflat->recipe->pre_handler(kflat);

        // Disable KASAN - flexible recipes may read SLUB redzone
#if defined(CONFIG_KASAN)
    kasan_disable_current();
#endif

    // Invoke recipe via stop_machine if user asked for that
    if(kflat->use_stop_machine)
        flatten_stop_machine(kflat, regs);
    else
        kflat->recipe->handler(kflat, regs);

#if defined(CONFIG_KASAN)
    kasan_enable_current();
#endif

    pr_info("Flatten done: error=%d\n", kflat->flat.error);
    if(!kflat->flat.error) {
        err = flatten_write(&kflat->flat);
        if(err)
            pr_err("flatten write failed: %d\n", kflat->flat.error);
    }
    flatten_fini(&kflat->flat);

    // Wake up poll handler
    wake_up_interruptible(&kflat->dump_ready_wq);

probing_exit:
    // Prepare for return
    probing_disarm(kflat);
    return_addr = READ_ONCE(kflat->probing.return_ip);

    if(kflat->skip_function_body) {
        pr_info("flatten finished - returning to PARENT function");
        return_addr = 0x0;
    } else
        pr_info("flatten finished - returning to INTERRUPTED function");

    kflat_put(kflat);
    return return_addr;
}
NOKPROBE_SYMBOL(probing_delegate);

/*******************************************************
 * KFLAT tests runner
 *******************************************************/
struct stopm_kflat_test {
    struct kflat* kflat;
    flat_test_case_handler_t handler;
};

static int kflat_test_stop_machine(void* arg) {
    struct stopm_kflat_test* target = (struct stopm_kflat_test*)arg;
    return target->handler(&target->kflat->flat);
}

int kflat_run_test(struct kflat* kflat, struct kflat_ioctl_tests* test) {
    int err;
    size_t tests_count = sizeof(test_cases) / sizeof(test_cases[0]);
    struct flatten_header* kflat_hdr = (struct flatten_header*)kflat->flat.area;

    if(tests_count == 0) {
        pr_err("KFLAT hasn't been compiled with embedded test cases");
        return -EFAULT;
    }

    for(size_t i = 0; i < tests_count; i++) {
        if(!strcmp(test->test_name, test_cases[i]->name)) {
            kflat->debug_flag = test->debug_flag;
            if(kflat->debug_flag)
                kflat_dbg_buf_init(dbg_buffer_size);

            flatten_init(&kflat->flat);
            kflat->flat.FLCTRL.debug_flag = kflat->debug_flag;
            kflat->flat.FLCTRL.mem_copy_skip = test->skip_memcpy;

#if defined(CONFIG_KASAN)
            kasan_disable_current();
#endif

            if(test->use_stop_machine) {
                cpumask_t cpumask;
                struct stopm_kflat_test arg = {
                    .kflat = kflat,
                    .handler = test_cases[i]->handler,
                };

                if(!(test_cases[i]->flags & KFLAT_TEST_ATOMIC)) {
                    pr_err("Cannot execute non-atomic test '%s' under stom_machine",
                           test_cases[i]->name);
                    flatten_fini(&kflat->flat);
                    return -EINVAL;
                }

                cpumask_clear(&cpumask);
                cpumask_set_cpu(smp_processor_id(), &cpumask);

                flat_infos("Running kflat test under stop_machine: %s", test_cases[i]->name);
                err = stop_machine(kflat_test_stop_machine, (void*)&arg, &cpumask);
                if(err)
                    pr_err("@Flatten stop_machine failed: %d", err);
            } else {
                err = test_cases[i]->handler(&kflat->flat);
            }

#if defined(CONFIG_KASAN)
            kasan_enable_current();
#endif

            flat_infos("@Flatten done: %d\n", kflat->flat.error);
            flatten_fini(&kflat->flat);

            // On success, return the size of flattened memory
            if(!err)
                err = kflat->flat.error;
            if(err)
                return (err <= 0) ? err : -err;
            return kflat_hdr->image_size;
        }
    }

    pr_err("No such test named '%s' (avail %ld tests)", test->test_name, tests_count);
    return -ENOENT;
}

/*******************************************************
 * FILE OPERATIONS
 *******************************************************/
static int kflat_open(struct inode* inode, struct file* filep) {
    struct kflat* kflat;

    /* this module is used only for debug purposes, but restrict access anyway */
    if(!capable(CAP_SYS_RAWIO))
        return -EPERM;

    kflat = kzalloc(sizeof(*kflat), GFP_KERNEL);
    if(!kflat)
        return -ENOMEM;
    atomic_set(&kflat->refcount, 1);

    mutex_init(&kflat->lock);
    init_waitqueue_head(&kflat->dump_ready_wq);
    probing_init(kflat);
    filep->private_data = kflat;
    return nonseekable_open(inode, filep);
}

static int kflat_ioctl_locked(struct kflat* kflat, unsigned int cmd,
                              unsigned long arg) {
    int ret;
    union {
        struct kflat_ioctl_enable enable;
        struct kflat_ioctl_disable disable;
        struct kflat_ioctl_mem_map map;
        struct kflat_ioctl_tests tests;
        char* buf;
    } args;
    struct kflat_recipe* recipe;

    switch(cmd) {
    case KFLAT_PROC_ENABLE:
        if(kflat->flat.area == NULL)
            return -EINVAL;
        if(kflat->mode == KFLAT_MODE_ENABLED)
            return -EBUSY;

        if(copy_from_user(&args.enable, (void*)arg, sizeof(args.enable)))
            return -EFAULT;
        if(args.enable.target_name[0] == '\0')
            return -EINVAL;

        kflat->pid = args.enable.pid;
        kflat->debug_flag = !!args.enable.debug_flag;
        kflat->use_stop_machine = !!args.enable.use_stop_machine;
        kflat->skip_function_body = !!args.enable.skip_function_body;
        args.enable.target_name[sizeof(args.enable.target_name) - 1] = '\0';

#if LINEAR_MEMORY_ALLOCATOR == 0
        if(kflat->use_stop_machine) {
            pr_err("KFLAT is not compiled with LINEAR_MEMORY_ALLOCATOR option, "
                   "which is required to enable stop_machine flag");
            return -EINVAL;
        }
#endif

        if(kflat->debug_flag)
            kflat_dbg_buf_init(dbg_buffer_size);

        recipe = kflat_recipe_get(args.enable.target_name);
        if(recipe == NULL)
            return -ENOENT;

        if(kflat->recipe)
            kflat_recipe_put(kflat->recipe);
        kflat->recipe = recipe;

        if(args.enable.run_recipe_now) {
            // Run probing delegate here, instead of attaching kprobe
            struct probe_regs regs = {0};
            regs.kflat_ptr = (uint64_t)kflat;
            kflat_get(kflat); // kprobe handler would do this normally
            probing_delegate(&regs);
        } else {
            ret = probing_arm(kflat, kflat->recipe->symbol, kflat->pid);
            if(ret) {
                kflat_recipe_put(kflat->recipe);
                kflat->recipe = NULL;
                return -EFAULT;
            }
        }

        kflat->mode = KFLAT_MODE_ENABLED;
        return 0;

    case KFLAT_PROC_DISABLE:
        if(kflat->mode == KFLAT_MODE_DISABLED)
            return -EINVAL;
        kflat->mode = KFLAT_MODE_DISABLED;

        probing_disarm(kflat);

        args.disable.size = ((struct flatten_header*)kflat->flat.area)->image_size;
        args.disable.invoked = args.disable.size > sizeof(size_t);
        args.disable.error = kflat->flat.error;
        if(copy_to_user((void*)arg, &args.disable, sizeof(args.disable)))
            return -EFAULT;
        return 0;

    case KFLAT_TESTS:
        if(kflat->mode != KFLAT_MODE_DISABLED) {
            pr_err("Cannot run embedded tests when KFLAT is armed");
            return -EBUSY;
        } else if(kflat->flat.area == NULL) {
            pr_err("MMap KFLAT shared buffer before running tests");
            return -EINVAL;
        }

        if(copy_from_user(&args.tests, (void*)arg, sizeof(args.tests)))
            return -EFAULT;
        args.tests.test_name[sizeof(args.tests.test_name) - 1] = '\0';

        return kflat_run_test(kflat, &args.tests);

    case KFLAT_MEMORY_MAP:
        if(copy_from_user(&args.map, (void*)arg, sizeof(args.map)))
            return -EFAULT;

        kdump_dump_vma(&kflat->mem_map);
        ret = kdump_tree_flatten(&kflat->mem_map, args.map.buffer, args.map.size);
        kdump_tree_destroy(&kflat->mem_map);
        return ret;

    case KFLAT_GET_LOADED_RECIPES:
        args.buf = (char*)kmalloc(RECIPE_LIST_BUFF_SIZE, GFP_KERNEL);
        if(args.buf == NULL)
            return -EFAULT;

        ret = kflat_recipe_get_all(args.buf, RECIPE_LIST_BUFF_SIZE);
        if(copy_to_user((char*)arg, args.buf, RECIPE_LIST_BUFF_SIZE)) {
            kfree(args.buf);
            return -EFAULT;
        }

        kfree(args.buf);
        return ret;

    default:
        return -ENOTTY;
    }
}

static long kflat_ioctl(struct file* filep, unsigned int cmd, unsigned long arg) {
    int res;
    struct kflat* kflat;

    kflat = filep->private_data;

    mutex_lock(&kflat->lock);
    res = kflat_ioctl_locked(kflat, cmd, arg);
    mutex_unlock(&kflat->lock);

    return res;
}

static int kflat_mmap_flatten(struct kflat* kflat, struct vm_area_struct* vma) {
    int ret = 0;
    void* area;
    size_t alloc_size, off;
    struct page* page;

    alloc_size = vma->vm_end - vma->vm_start;
    if(vma->vm_pgoff)
        return -EINVAL;
    if(vma->vm_flags & (VM_EXEC | VM_WRITE))
        return -EPERM;

    mutex_lock(&kflat->lock);

    if(kflat->flat.area != NULL) {
        pr_err("cannot mmap kflat device twice");
        ret = -EBUSY;
        goto exit;
    }

    area = vmalloc_user(alloc_size);
    if(!area) {
        ret = -ENOMEM;
        goto exit;
    }

    kflat->flat.area = area;
    kflat->flat.size = alloc_size;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 3, 0)
    /* We have a lot of older kernels that backported vm_flags_set making the following
     *  line fail to compile. Let's leave vm_flags unchanged on older kernels.
     */
    // vma->vm_flags |= VM_DONTEXPAND;
#else
    vm_flags_set(vma, VM_DONTEXPAND);
#endif
    for(off = 0; off < alloc_size; off += PAGE_SIZE) {
        page = vmalloc_to_page(kflat->flat.area + off);
        if(vm_insert_page(vma, vma->vm_start + off, page))
            WARN_ONCE(1, "vm_insert_page() failed");
    }

exit:
    mutex_unlock(&kflat->lock);
    return ret;
}

#ifdef KFLAT_VM_TREE_SUPPORT
static int kflat_mmap_kdump(struct kflat* kflat, struct vm_area_struct* vma) {
    int ret = 0;

    kdump_dump_vma(&kflat->mem_map);
    ret = kdump_tree_remap(&kflat->mem_map, vma);
    kdump_tree_destroy(&kflat->mem_map);

    return ret;
}
#endif

static int kflat_mmap(struct file* filep, struct vm_area_struct* vma) {
    off_t off;
    struct kflat* kflat;

    kflat = filep->private_data;

    off = vma->vm_pgoff;
    vma->vm_pgoff = 0;
    switch(off) {
    case KFLAT_MMAP_FLATTEN:
        return kflat_mmap_flatten(kflat, vma);

#ifdef KFLAT_VM_TREE_SUPPORT
    case KFLAT_MMAP_KDUMP:
        return kflat_mmap_kdump(kflat, vma);
#endif

    default:
        return -EINVAL;
    }
}

static __poll_t kflat_poll(struct file* filep, struct poll_table_struct* wait) {
    struct kflat* kflat = filep->private_data;
    unsigned int ret_mask = 0;
    size_t size;

    poll_wait(filep, &kflat->dump_ready_wq, wait);

    // Check whether timeout occurred or recipe was triggered
    mutex_lock(&kflat->lock);
    if(kflat->flat.area == NULL) {
        ret_mask = POLLERR;
        goto exit;
    }

    size = ((struct flatten_header*)kflat->flat.area)->image_size;
    if(kflat->flat.error) {
        ret_mask = POLLERR;
    } else if(size > sizeof(size_t)) {
        ret_mask = POLLIN | POLLRDNORM;
    }

exit:
    mutex_unlock(&kflat->lock);

    return ret_mask;
}

static int kflat_close(struct inode* inode, struct file* filep) {
    struct kflat* kflat = filep->private_data;

    if(kflat->mode != KFLAT_MODE_DISABLED)
        probing_disarm(kflat);
    kflat_put(kflat);
    return 0;
}

static const struct file_operations kflat_fops = {
    .owner = THIS_MODULE,
    .open = kflat_open,
    .unlocked_ioctl = kflat_ioctl,
    .compat_ioctl = kflat_ioctl,
    .mmap = kflat_mmap,
    .release = kflat_close,
    .read = kflat_dbg_buf_read,
    .poll = kflat_poll,
};

/*******************************************************
 * MODULE REGISTRATION
 *******************************************************/
static struct dentry* kflat_dbgfs_node;

static int __init kflat_init(void) {
    int rv;
    struct dentry* node;

    rv = kdump_init();
    if(rv)
        return rv;

    node = debugfs_create_file_unsafe("kflat", 0600, NULL, NULL, &kflat_fops);
    if(node == NULL) {
        pr_err("failed to create kflat in debugfs\n");
        rv = -ENOMEM;
        goto fail_debugfs;
    }

    kflat_lookup_kallsyms_name = (lookup_kallsyms_name_t)probing_get_kallsyms();
    kflat_kallsyms_lookup = (kallsyms_lookup_t)flatten_global_address_by_name("kallsyms_lookup");

    kflat_dbgfs_node = node;
    return 0;

fail_debugfs:
    kdump_exit();
    return rv;
}

static void __exit kflat_exit(void) {
    kflat_dbg_buf_deinit();
    debugfs_remove(kflat_dbgfs_node);
    kdump_exit();
}

MODULE_AUTHOR("Samsung R&D Poland - Mobile Security Group (srpol.mb.sec@samsung.com)");
MODULE_DESCRIPTION("Kernel driver allowing user to dump kernel structures");
MODULE_LICENSE("GPL");

module_init(kflat_init);
module_exit(kflat_exit);
