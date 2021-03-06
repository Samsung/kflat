#include "kflat.h"
#include "probing.h"

#include <linux/atomic.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/debugfs.h>


/*******************************************************
 * NON-EXPORTED FUNCTIONS
 *******************************************************/
int kflat_ioctl_test(struct kflat *kflat, unsigned int cmd, unsigned long arg);

/*******************************************************
 * REFCOUNTS
 *******************************************************/
static void kflat_get(struct kflat *kflat) {
	atomic_inc(&kflat->refcount);
}

static void kflat_put(struct kflat *kflat) {
	if (atomic_dec_and_test(&kflat->refcount)) {
		kflat_recipe_put(kflat->recipe);
		kflat->recipe = NULL;
		vfree(kflat->area);
		kfree(kflat);
	}
}

/*******************************************************
 * CLIENTS REGISTRY
 *******************************************************/
LIST_HEAD(kflat_clients_registry);
DEFINE_SPINLOCK(kflat_clients_registry_lock);

struct kflat_client {
	struct list_head list;
	struct kflat* kflat;
};

static int kflat_register(struct kflat* kflat) {
	int ret = 0;
	struct kflat_client* entry;
	unsigned long flags;

	entry = kmalloc(sizeof *entry, GFP_KERNEL);
	if(entry == NULL)
		return -ENOMEM;
	
	spin_lock_irqsave(&kflat_clients_registry_lock, flags);

	// Check for PID duplicates
	list_for_each_entry(entry, &kflat_clients_registry, list) {
		if(entry->kflat->pid == kflat->pid) {
			pr_err("cannot register the same PID twice");
			ret = -EBUSY;
			goto exit;
		}
	}

	entry->kflat = kflat;
	list_add(&entry->list, &kflat_clients_registry);

exit:
	spin_unlock_irqrestore(&kflat_clients_registry_lock, flags);
	if(ret != 0)
		// If an error occurred, `entry` buffer hasn't been used
		kfree(entry);
	return ret;
}

static int kflat_unregister(struct kflat* kflat) {
	int ret = 0;
	struct kflat_client* entry = NULL;
	unsigned long flags;
	
	spin_lock_irqsave(&kflat_clients_registry_lock, flags);
	list_for_each_entry(entry, &kflat_clients_registry, list) {
		if(entry->kflat == kflat) {
			list_del(&entry->list);
			goto exit;
		}
	}
	ret = -EINVAL;

exit:
	spin_unlock_irqrestore(&kflat_clients_registry_lock, flags);
	if(entry != NULL)
		kfree(entry);
	return ret;
}

struct kflat* _kflat_access_current(void) {
	pid_t current_pid;
	struct kflat_client* entry;
	unsigned long flags;

	current_pid = get_current()->pid;
	spin_lock_irqsave(&kflat_clients_registry_lock, flags);
	list_for_each_entry(entry, &kflat_clients_registry, list) {
		if(entry->kflat->pid == current_pid) {
			goto exit;
		}
	}
	entry = NULL;

exit:
	spin_unlock_irqrestore(&kflat_clients_registry_lock, flags);
	return entry != NULL ? entry->kflat : NULL;
}

struct kflat* kflat_get_current(void) {
	struct kflat* kflat = _kflat_access_current();
	if(kflat != NULL)
		kflat_get(kflat);
	return kflat;
}

void kflat_put_current(struct kflat* kflat) {
	if(kflat != NULL)
		kflat_put(kflat);
}

/*******************************************************
 * PROBING DELEGATE
 *******************************************************/
asmlinkage __used uint64_t probing_delegate(struct probe_regs* regs) {
	int err;
	uint64_t return_addr;
	struct kflat* kflat;
	struct probe* probe_priv;

	pr_info("kflat started");

	// Use _kflat_access_current, because refcount was already incremented
	//  in probing_pre_handler function.
	kflat = _kflat_access_current();
	if(kflat == NULL)
		BUG();
	probe_priv = &kflat->probing;
	probe_priv->triggered = 1;

	flatten_init(kflat);
	kflat->recipe->handler(kflat, regs);

	flat_infos("@Flatten done: %d\n", kflat->errno);
	if (!kflat->errno) {
		err = flatten_write(kflat);
		if(err)
			flat_errs("@Flatten write failed: %d\n", kflat->errno);
	}
	flatten_fini(kflat);

	// Prepare for return
	probing_disarm(probe_priv);
	probe_priv->is_armed = 0;
	return_addr = READ_ONCE(probe_priv->return_ip);

	kflat_put_current(kflat);
	probe_priv = NULL;

	pr_info("kflat finished; returning to %llx...", return_addr);
	return return_addr;
}

/*******************************************************
 * FILE OPERATIONS
 *******************************************************/
static int kflat_open(struct inode *inode, struct file *filep) {
	struct kflat *kflat;

	if(!capable(CAP_SYS_RAWIO))
		return -EPERM;

	kflat = kzalloc(sizeof(*kflat), GFP_KERNEL);
	if (!kflat)
		return -ENOMEM;
	atomic_set(&kflat->refcount, 1);

	mutex_init(&kflat->lock);
	kflat->FLCTRL.fixup_set_root = RB_ROOT_CACHED;
	kflat->FLCTRL.imap_root = RB_ROOT_CACHED;
	filep->private_data = kflat;
	return nonseekable_open(inode, filep);
}

static int kflat_ioctl_locked(struct kflat *kflat, unsigned int cmd,
				 unsigned long arg)
{
	int ret;
	union {
		struct kflat_ioctl_init init;
		struct kflat_ioctl_enable enable;
		struct kflat_ioctl_mem_map map;
	} args;
	struct kflat_recipe* recipe;

	switch (cmd) {
	case KFLAT_INIT:
		if (kflat->mode != KFLAT_MODE_DISABLED)
			return -EBUSY;

		if(copy_from_user(&args.init, (void*)arg, sizeof(args.init)))
			return -EFAULT;
		if(args.init.size == 0)
			return -EINVAL;

		kflat->size = args.init.size;
		kflat->debug_flag = args.init.debug_flag;
		kflat->mode = KFLAT_MODE_ENABLED;
		return 0;

	case KFLAT_PROC_ENABLE:
		if (kflat->area == NULL)
			return -EINVAL;

		if(copy_from_user(&args.enable, (void*) arg, sizeof(args.enable)))
			return -EFAULT;
		if(args.enable.target_name[0] == '\0')
			return -EINVAL;

		kflat->pid = args.enable.pid;
		args.enable.target_name[sizeof(args.enable.target_name) - 1] = '\0';

		recipe = kflat_recipe_get(args.enable.target_name);
		if(recipe == NULL)
			return -ENOENT;
		
		if(kflat->recipe)
			kflat_recipe_put(kflat->recipe);
		kflat->recipe = recipe;

		ret = probing_arm(&kflat->probing, kflat->recipe->symbol, kflat->pid);
		if(ret)
			return ret;

		kflat_register(kflat);	//tODO: ERROR handling
		return 0;

	case KFLAT_PROC_DISABLE:
		if (kflat->mode == KFLAT_MODE_DISABLED)
			return -EINVAL;
		kflat->mode = KFLAT_MODE_DISABLED;
		
		probing_disarm(&kflat->probing);
		kflat_unregister(kflat);
		return 0;

	case KFLAT_TESTS:
		ret =  kflat_ioctl_test(kflat, cmd, arg);
		return ret;

	case KFLAT_MEMORY_MAP:
		if(copy_from_user(&args.map, (void*) arg, sizeof(args.map)))
			return -EFAULT;

		kdump_dump_vma(&kflat->mem_map);
		ret = kdump_tree_flatten(&kflat->mem_map, args.map.buffer, args.map.size);
		kdump_tree_destroy(&kflat->mem_map);
		return ret;

	default:
		return -ENOTTY;
	}
}

static long kflat_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	int res;
	struct kflat *kflat;

	kflat = filep->private_data;

	mutex_lock(&kflat->lock);
	res = kflat_ioctl_locked(kflat, cmd, arg);
	mutex_unlock(&kflat->lock);
	
	return res;
}

static int kflat_mmap_flatten(struct kflat *kflat, struct vm_area_struct *vma) {
	void *area;
	size_t alloc_size, off;
	struct page *page;

	alloc_size = vma->vm_end - vma->vm_start;
	if(vma->vm_pgoff || alloc_size != kflat->size)
		return -EINVAL;

	if(kflat->mode != KFLAT_MODE_ENABLED) {
		pr_err("kflat must be intialized before mmaping memory");
		return -EINVAL;
	} else if(kflat->area != NULL) {
		pr_err("cannot mmap kflat device twice");
		return -EBUSY;
	}

	area = vmalloc_user(alloc_size);
	if (!area)
		return -ENOMEM;

	mutex_lock(&kflat->lock);
	kflat->area = area;
	mutex_unlock(&kflat->lock);
	
	vma->vm_flags |= VM_DONTEXPAND;
	for (off = 0; off < alloc_size; off += PAGE_SIZE) {
		page = vmalloc_to_page(kflat->area + off);
		if (vm_insert_page(vma, vma->vm_start + off, page))
			WARN_ONCE(1, "vm_insert_page() failed");
	}
	return 0;
}

static int kflat_mmap_kdump(struct kflat* kflat, struct vm_area_struct* vma) {
	int ret = 0;

	kdump_dump_vma(&kflat->mem_map);
	ret = kdump_tree_remap(&kflat->mem_map, vma);
	kdump_tree_destroy(&kflat->mem_map);

	return ret;
}

static int kflat_mmap(struct file* filep, struct vm_area_struct* vma) {
	off_t off;
	struct kflat *kflat;

	kflat = filep->private_data;

	off = vma->vm_pgoff;
	vma->vm_pgoff = 0;
	if(off == KFLAT_MMAP_FLATTEN)
		return kflat_mmap_flatten(kflat, vma);
	else if(off == KFLAT_MMAP_KDUMP)
		return kflat_mmap_kdump(kflat, vma);
	else
		return -EINVAL;
}

static int kflat_close(struct inode *inode, struct file *filep) {
	struct kflat* kflat = filep->private_data;

	if(kflat->mode != KFLAT_MODE_DISABLED) {
		probing_disarm(&kflat->probing);
		kflat_unregister(kflat);
	}
	kflat_put(kflat);
	return 0;
}

static const struct file_operations kflat_fops = {
	.owner = THIS_MODULE,
	.open = kflat_open,
	.unlocked_ioctl = kflat_ioctl,
	.mmap = kflat_mmap,
	.release = kflat_close,
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
	if (node == NULL) {
		pr_err("failed to create kflat in debugfs\n");
		return -ENOMEM;
	}

	kflat_dbgfs_node = node;
	return 0;
}

static void __exit kflat_exit(void) {
	debugfs_remove(kflat_dbgfs_node);
	kdump_exit();
}

MODULE_AUTHOR("Bartosz Zator");
MODULE_DESCRIPTION("Kernel driver allowing user to dump kernel structures");
MODULE_LICENSE("GPL");

module_init(kflat_init);
module_exit(kflat_exit);
