#include <linux/module.h> /* Needed by all modules */ 
#include <linux/printk.h> /* Needed for pr_info() */ 
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>

struct sub_struct {
    int a;
    char lol[256];
};

struct main_struct {
    int b;
    struct sub_struct *ptr;
};

int test_open(struct inode *inode, struct file *filep) {
	return nonseekable_open(inode, filep);
}

int test_close(struct inode *inode, struct file *filep) {
	return 0;
}

long test_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    struct main_struct tmp;
    if(copy_from_user(&tmp, (struct main_struct *) arg, sizeof(struct main_struct))) {
        return -EFAULT;
    }

    pr_info("%d\n", tmp.b);
    return 0;
}

static const struct file_operations test_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = test_ioctl,
	.open = test_open,
    .release = test_close,
};

static struct dentry* test_dbgfs_node;

int init_module(void) { 
    pr_info("Hello world.\n"); 

    test_dbgfs_node = debugfs_create_file_unsafe("test_ioctl", 0600, NULL, NULL, &test_fops);

    if (test_dbgfs_node == NULL)
        return -ENOMEM;   

    return 0; 
} 

void cleanup_module(void) { 
    debugfs_remove(test_dbgfs_node);
    pr_info("Goodbye world 1.\n"); 
} 

MODULE_LICENSE("GPL");