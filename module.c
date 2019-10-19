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

#include <asm/uaccess.h>
#include <linux/kernel.h>

MODULE_AUTHOR("fktrc");
MODULE_DESCRIPTION("BMSTU Linux Security Module");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0.1");

static bool has_gid(unsigned int target_gid)
{
	struct group_info *group_info;
	int i;

	group_info = get_current_groups();

	for (i = 0; i < group_info->ngroups; i++)
	{
		kgid_t kgid = group_info->gid[i];
		gid_t gid = kgid.val;
		printk("bmstuLogs groupid %d\n", gid);

		if (gid == target_gid)
		{
			return true;
		}
	}

	return false;
}

static bool is_root_uid(void)
{
    const struct cred *cred;
    cred = current_cred();
    return uid_eq(current_uid(), GLOBAL_ROOT_UID);
}

static int match_device(struct usb_device *dev, void *p)
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

static int find_usb_device(void)
{
    void *p = NULL;
    bool match = usb_for_each_dev(p, match_device);
    return match;
}

static void read_config_file(void)
{
    struct file *f;
    char *buff;
    int size_buff;

    f = filp_open("/etc/bmstu", O_RDONLY, 0);

    if(f == NULL) {
        printk("bmstuLogs filp_open error\n");
        return;
    }

    buff = kcalloc(32, sizeof(char), GFP_KERNEL);
    size_buff = 32 * sizeof(char);

    if (buff == NULL) {
        return;
    }

    kernel_read(f, buff, size_buff, 0);
    printk("%s", buff);

    filp_close(f, NULL);
    kfree(buff);
}

static int inode_may_access(struct inode *inode, int mask)
{
    struct dentry *dentry;
    char *path = NULL;
    char buff_path[64];
    int err;
    unsigned int gid = 0;

    char *attr;
    int size_buff;

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

    attr = kcalloc(32, sizeof(char), GFP_KERNEL);
    size_buff = 32 * sizeof(char);

    if (attr == NULL) {
        return -EACCES;
    }

    err = __vfs_getxattr(dentry, inode, "security.bmstu", attr, size_buff);

    if (err < 0) {
        kfree(attr);
        return 0;
    }

    err = kstrtouint(attr, 0, &gid);
    kfree(attr);

    printk("bmstuLogs inode access %s, mask %d, expect GID %d\n", path, mask, gid);

    // Incorrect value in xattr
    if (err < 0) {
        return 0;
    }

	if (!has_gid(gid)) {
	    printk("bmstuLogs inode: You shall not pass!\n");
        return -EACCES;
	}

	read_config_file();

    printk("bmstuLogs Access for inode granted! %s\n", path);
    return 0;
}

static int xattr_may_change(struct dentry *dentry, const char *name)
{
    char *path = NULL;
    char buff_path[64];

    if (strcmp(name, "security.bmstu") != 0) {
        return 0;
    }

    path = dentry_path_raw(dentry, buff_path, sizeof(buff_path));

    if (path == NULL) {
        return 0;
    }

    printk("bmstuLogs bmstu xattr modify at %s\n", path);

    return 0;
}

//---HOOKS

static int bmstu_inode_permission(struct inode *inode, int mask)
{
    return inode_may_access(inode, mask);
}

static int bmstu_inode_setxattr(struct dentry *dentry, const char *name,
                                const void *value, size_t size, int flags)
{
    return xattr_may_change(dentry, name);
}

static int bmstu_inode_removexattr(struct dentry *dentry, const char *name)
{
    return xattr_may_change(dentry, name);
}

//---HOOKS REGISTERING
static struct security_hook_list bmstu_hooks[] =
        {
                LSM_HOOK_INIT(inode_permission, bmstu_inode_permission),
                LSM_HOOK_INIT(inode_setxattr, bmstu_inode_setxattr),
                LSM_HOOK_INIT(inode_removexattr, bmstu_inode_removexattr),
        };

//---INIT
void __init bmstu_add_hooks(void)
{
    security_add_hooks(bmstu_hooks, ARRAY_SIZE(bmstu_hooks), "bmstu");
}
