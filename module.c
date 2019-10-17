/*
 *  BMSTU Linux security module
 *
 *  This file contains the LSM hook function implementations.
 *
 *  Author:  Alex Sparrow, <fktrcfylh1234567@yandex.ru>
 *
 *  Copyright 2019 BMSTU IU8.
 */

#include <linux/lsm_hooks.h>
#include <linux/usb.h>
#include <linux/xattr.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>

MODULE_AUTHOR("fktrc");
MODULE_DESCRIPTION("BMSTU Linux Security Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");

bool has_access(void)
{
	struct group_info *group_info;
	int i;

	group_info = get_current_groups();

	for (i = 0; i < group_info->ngroups; i++)
	{
		kgid_t kgid = group_info->gid[i];
		printk("bmstuLogs kgroupid %d\n", kgid);

		gid_t gid = kgid.val;
		printk("bmstuLogs groupid %d\n", gid);

		if (gid == 1001)
		{
			printk("bmstuLogs gid == 1001\n");
			return true;
		}
	}

	return false;
}

inline bool is_root_uid(void)
{
    const struct cred *cred;
    cred = current_cred();
    return uid_eq(current_uid(), GLOBAL_ROOT_UID);
}

int match_device(struct usb_device *dev, void *p)
{
    char *product;
    char *manufacturer;
    char *serial;

    product = dev->product;
    manufacturer = dev->manufacturer;
    serial = dev->serial;

    printk("bmstuLogs usb_device product %s, serial %s\n", product, serial);
    if (strcmp(serial, "9HHORL8W") == 0) {
        return 1;
    }

    return 0;
}

int find_usb_device(void)
{
    void *p = NULL;
    bool match = usb_for_each_dev(p, match_device);
    return match;
}

char *get_file_xattr(struct file *file)
{
    char *buff = kcalloc(32, sizeof(char), GFP_KERNEL);
    int size_buff = 32 * sizeof(char);
    int res;

    if (buff == NULL) {
        return NULL;
    }

    res = vfs_getxattr(file->f_path.dentry, "security.bmstu", buff, size_buff);
    return buff;
}

bool inode_is_dir(struct inode *inode)
{
    return (inode->i_mode & S_IFMT) == S_IFDIR;
}

int file_may_access(struct file *file, int mask)
{
    char *path;
    char *attr;
    char *current_dentry;
    char *parent_dentry;
    char buff[256];

    if (is_root_uid()) {
        return 0;
    }

    if (!file) {
        return 0;
    }

    current_dentry = file->f_path.dentry->d_iname;
    parent_dentry = file->f_path.dentry->d_parent->d_iname;
    path = dentry_path_raw(file->f_path.dentry, buff, 256);

    if (strstr(path, "/home/") == NULL) {
        return 0;
    }

    attr = get_file_xattr(file);
    printk("bmstuLogs file permission %s, mask %d\n", path, mask);

    if (strcmp(attr, "bruh") != 0) {
        printk("bmstuLogs non-protected file access %s\n", path);
        kfree(attr);
        return 0;
    }

    kfree(attr);

	if (has_access()) {
        printk("bmstuLogs Access for file granted! %s\n", path);
        return 0;
	}

    if (find_usb_device()) {
        printk("bmstuLogs USB device found. Access granted! %s\n", path);
        return 0;
    }

    printk("bmstuLogs file: You shall not pass!\n");
    return -EACCES;
}

int inode_may_access(struct inode *inode, int mask)
{
    struct dentry *dentry;
    char *path = NULL;
    char buff_path[64];
    int result;

    char *buff_xattr;
    int size_buff_xattr;

    if (is_root_uid()) {
        return 0;
    }

    if (!inode) {
        return 0;
    }

    spin_lock(&inode->i_lock);
    hlist_for_each_entry(dentry, &inode->i_dentry, d_u.d_alias)
    {
        path = dentry_path_raw(dentry, buff_path, sizeof(buff_path));
    }
    spin_unlock(&inode->i_lock);

    if (path == NULL) {
        return 0;
    }

    if (strstr(path, "/home/") == NULL) {
        return 0;
    }

    buff_xattr = kcalloc(32, sizeof(char), GFP_KERNEL);
    size_buff_xattr = 32 * sizeof(char);

    if (buff_xattr == NULL) {
        return -EACCES;
    }

    result = __vfs_getxattr(dentry, inode, "security.bmstu", buff_xattr, size_buff_xattr);
    printk("bmstuLogs inode access %s, mask %d, attr %d:%s\n",
        path, mask, result, buff_xattr);

    kfree(buff_xattr);

    if (result < 0) {
        return 0;
    }

	if (has_access()) {
        printk("bmstuLogs Access for inode granted! %s\n", path);
        return 0;
	}

    if (find_usb_device()) {
        printk("bmstuLogs USB device found. Access granted! %s\n", path);
        return 0;
    }

    printk("bmstuLogs inode: You shall not pass!\n");
    return -EACCES;
}

//---HOOKS

static int bmstu_file_permission(struct file *file, int mask)
{
    return file_may_access(file, mask);
}

static int bmstu_inode_permission(struct inode *inode, int mask)
{
    return inode_may_access(inode, mask);
}

static int bmstu_inode_setxattr(struct dentry *dentry, const char *name,
                                const void *value, size_t size, int flags)
{
    return 0;
}

static int bmstu_inode_getxattr(struct dentry *dentry, const char *name)
{
    return 0;
}

static int bmstu_inode_listxattr(struct dentry *dentry)
{
    return 0;
}

static int bmstu_inode_removexattr(struct dentry *dentry, const char *name)
{
    return 0;
}

//---HOOKS REGISTERING
static struct security_hook_list bmstu_hooks[] =
        {
                LSM_HOOK_INIT(file_permission, bmstu_file_permission),
                LSM_HOOK_INIT(inode_permission, bmstu_inode_permission),

                LSM_HOOK_INIT(inode_setxattr, bmstu_inode_setxattr),
                LSM_HOOK_INIT(inode_getxattr, bmstu_inode_getxattr),
                LSM_HOOK_INIT(inode_listxattr, bmstu_inode_listxattr),
                LSM_HOOK_INIT(inode_removexattr, bmstu_inode_removexattr),
        };

//---INIT
void __init bmstu_add_hooks(void)
{
    security_add_hooks(bmstu_hooks, ARRAY_SIZE(bmstu_hooks), "bmstu");
}
