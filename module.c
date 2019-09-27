// /security/bmstu/module.c
//---INCLUDES
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/ptrace.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/security.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/ext2_fs.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/kd.h>
#include <linux/stat.h>
#include <asm/uaccess.h>
#include <asm/ioctls.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/quota.h>
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/sysctl.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/uidgid.h>
#include <linux/lsm_hooks.h>
#include <linux/usb.h>

MODULE_AUTHOR("fktrc");
MODULE_DESCRIPTION("BMSTU Linux Security Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");


static inline bool is_root_uid(void) {
	return uid_eq(current_uid(), GLOBAL_ROOT_UID);
}

static int match_device(struct usb_device *dev, void *p)
{
    char *product = dev->product;
    char *manufacturer = dev->manufacturer;
    char *serial = dev->serial;
    
	printk("bmstuLogs usb_device product %s, serial %s\n", product, serial);
	if (strcmp(serial, "9HHORL8W") == 0)
	{
		return 1;
	}
	
	return 0;
}

static int find_usb_device(void)
{
	void *p;
	int match = usb_for_each_dev(p, match_device);
    return match;
}

//---HOOKS

static int bmstu_inode_permission(struct inode *inode, int mask)
{		
	if (is_root_uid())
	{
		return 0;
	}

	if ((inode->i_mode & S_IFMT) == S_IFDIR) {
		return 0;
	}
		
	const struct cred *cred = current_cred();	
	struct dentry *dentry;
	char buf[64];
    const char *path;
	
	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_u.d_alias) {
    	path = dentry_path_raw(dentry, buf, sizeof(buf));
		if(strstr(path, "/home/") != NULL)
		{
			printk("bmstuLogs inode_permission path %s\n", path);
		}
    }
	spin_unlock(&inode->i_lock);	
		
	return 0;
}

static int bmstu_file_permission(struct file *file, int mask)
{
	if (is_root_uid())
	{
		return 0;
	}
	
	if (!file)
	{
		return 0;
	}
	
	char *path;
    char *dentry;
    char *parent_dentry;
    char buff[256];
    
    dentry = file->f_path.dentry->d_iname;
    parent_dentry = file->f_path.dentry->d_parent->d_iname;
    path = dentry_path_raw(file->f_path.dentry, buff, 256);

	if(strstr(path, "/home/") == NULL)
	{
		return 0;
	}
	
	printk("bmstuLogs file_permission hook at %s, mask %i\n", path, mask);
	return 0;
}

static int bmstu_file_open(struct file *file)
{    
	if (is_root_uid())
	{
		return 0;
	}
	
	if (!file)
	{
		return 0;
	}
	
	char *path;
    char *current_dentry;
    char *parent_dentry;
    char buff[256];
    
    current_dentry = file->f_path.dentry->d_iname;
    parent_dentry = file->f_path.dentry->d_parent->d_iname;
    path = dentry_path_raw(file->f_path.dentry, buff, 256);
    
	if(strstr(path, "/home/") == NULL)
	{
		return 0;
	}

	char buf[1024];
	int size_buf = 1024;
	int res;

	res = vfs_getxattr(file->f_path.dentry, "user.bmstu", buf, size_buf);
	
	if (strcmp(buf, "bruh") != 0)
	{
		printk("bmstuLogs file open at %s\n", path);
        return 0;
	}
	
	if (find_usb_device())
	{
		printk("bmstuLogs file open at %s\n", path);
		printk("bmstuLogs USB device found. Access granted!\n");
        return 0;
	}
	
    printk("file open: You shall not pass!\n");
    return -EACCES;
}					   

static int bmstu_inode_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
	if (is_root_uid())
	{
		return 0;
	}

	struct inode *inode = d_backing_inode(dentry);
	printk("bmstuLogs bmstu_inode_setxattr hook %s\n", name);
	return 0;
}

static int bmstu_inode_getxattr(struct dentry *dentry, const char *name)
{
	if (is_root_uid())
	{
		return 0;
	}

	printk("bmstuLogs bmstu_inode_getxattr hook %s\n", name);
	return 0;
}

static int bmstu_inode_listxattr(struct dentry *dentry)
{
	if (is_root_uid())
	{
		return 0;
	}

	const struct cred *cred = current_cred();
	printk("bmstuLogs bmstu_inode_listxattr hook\n");
	return 0;
}

static int bmstu_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (is_root_uid())
	{
		return 0;
	}

	printk("bmstuLogs bmstu_inode_removexattr hook %s\n", name);
	return 0;
}

//---HOOKS REGISTERING
static struct security_hook_list bmstu_hooks[] =
{
	//LSM_HOOK_INIT(inode_permission, bmstu_inode_permission),
	//LSM_HOOK_INIT(file_permission, bmstu_file_permission),
	LSM_HOOK_INIT(file_open, bmstu_file_open),
	
	//LSM_HOOK_INIT(inode_setxattr, bmstu_inode_setxattr),
	//LSM_HOOK_INIT(inode_getxattr, bmstu_inode_getxattr),
	//LSM_HOOK_INIT(inode_listxattr, bmstu_inode_listxattr),
	//LSM_HOOK_INIT(inode_removexattr, bmstu_inode_removexattr),
};

//---INIT
void __init bmstu_add_hooks(void)
{
    	security_add_hooks(bmstu_hooks, ARRAY_SIZE(bmstu_hooks), "bmstu");
}
