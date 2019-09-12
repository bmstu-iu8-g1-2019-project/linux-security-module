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

MODULE_LICENSE("GPL");


static inline bool is_root_uid(void) {
	return uid_eq(current_uid(), GLOBAL_ROOT_UID);
}

//---HOOKS

static int bmstu_inode_permission(struct inode *inode, int mask)
{		
	if (is_root_uid())
	{
		return 0;
	}

	// Don't check this if it is a directory
	if ((inode->i_mode & S_IFMT) == S_IFDIR) {
	}
		
	const struct cred *cred = current_cred();	
	printk("bmstuLogs inode_permission hook, uid %i\n", cred->uid);	
		
	struct dentry *dentry;
	char buf[64];
    const char *path;
	
	spin_lock(&inode->i_lock);
	hlist_for_each_entry(dentry, &inode->i_dentry, d_u.d_alias) {
    	path = dentry_path_raw(dentry, buf, sizeof(buf));
    	printk("bmstuLogs inode_permission path %s\n", path);
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
    char *dentry;
    char *parent_dentry;
    char buff[256];
    
    dentry = file->f_path.dentry->d_iname;
    parent_dentry = file->f_path.dentry->d_parent->d_iname;
    path = dentry_path_raw(file->f_path.dentry, buff, 256);
    	
	if (strcmp(path, "/home/qemu/dir") == 0)
	{
	    printk(KERN_ALERT "You shall not pass!\n");
        return -EACCES;
	}

	//printk("bmstuLogs file_open hook at %s\n", path);
	
	return 0;
}				     

//---HOOKS REGISTERING
static struct security_hook_list bmstu_hooks[] =
{
	//LSM_HOOK_INIT(inode_permission, bmstu_inode_permission),
	//LSM_HOOK_INIT(file_permission, bmstu_file_permission),
	LSM_HOOK_INIT(file_open, bmstu_file_open),
};

//---INIT
void __init bmstu_add_hooks(void)
{
    	security_add_hooks(bmstu_hooks, ARRAY_SIZE(bmstu_hooks), "bmstu");
}
