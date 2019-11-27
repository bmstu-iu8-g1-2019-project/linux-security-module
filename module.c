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
MODULE_VERSION("1.0.0");

struct bmstu_user {
	kuid_t uid;
	char *token_serial;
};

struct bmstu_user *bmstu_users;
size_t users_count;

bool bmstu_lsm_is_running;

// Checks has curent user access for some label
static bool has_gid(unsigned int target_gid)
{
	struct group_info *group_info;
	int i;

	group_info = get_current_groups();

	for (i = 0; i < group_info->ngroups; i++) {
		gid_t gid = group_info->gid[i].val;

		if (gid == target_gid) {
			return true;
		}
	}

	return false;
}

// Checks is curent user root
static bool is_root_uid(void)
{
	return uid_eq(current_uid(), GLOBAL_ROOT_UID);
}

// This func will be called for each plugged device
// void *p is required device serial
static int match_device(struct usb_device *dev, void *p)
{
	if (strcmp(dev->serial, (char *)p) == 0) {
		return 1;
	}

	return 0;
}

// Checks is device plugged
static int find_usb_device(void)
{
	void *p = NULL;
	int i = 0;

	for (; i < users_count; i++) {
		if (uid_eq(current_uid(), bmstu_users[i].uid)) {
			p = bmstu_users[i].token_serial;
			break;
		}
	}

	return usb_for_each_dev(p, match_device);
}

// Reading config file on startup
static void read_config_file(void)
{
	struct file *f;
	char *buff;
	char *str;
	loff_t pos = 0;
	int i = 0;
	int j = 0;
	int len;
	bool is_in_uid = true;
	int err;
	uid_t uid;

	f = filp_open("/etc/bmstu", O_RDONLY, 0);
	if (f == NULL) {
		printk("BMSTU_LSM config file open error\n");
		return;
	}

	buff = kmalloc(32, GFP_KERNEL);
	if (buff == NULL) {
		printk("BMSTU_LSM cannot allocate memory\n");
		return;
	}

	str = kmalloc(32, GFP_KERNEL);
	if (str == NULL) {
		printk("BMSTU_LSM cannot allocate memory\n");
		kfree(buff);
		return;
	}

	do {
		len = kernel_read(f, buff, 32, &pos);

		for (i = 0; i < len; i++) {
			if (buff[i] == ' ') {
				str[j] = '\0';
				is_in_uid = false;
				j = 0;

				err = kstrtouint(str, 0, &uid);
				if (err < 0) {
					kfree(str);
					kfree(buff);
					return;
				}

				bmstu_users = krealloc(
					bmstu_users,
					(users_count + 1) *
						sizeof(struct bmstu_user),
					GFP_ATOMIC);

				if (bmstu_users == NULL) {
					printk("BMSTU_LSM cannot allocate memory\n");
					kfree(str);
					kfree(buff);
					return;
				}

				users_count++;
				bmstu_users[users_count - 1].uid.val = uid;
				continue;
			}

			if (buff[i] == '\n') {
				str[j] = '\0';
				is_in_uid = true;

				bmstu_users[users_count - 1].token_serial =
					kcalloc(j + 1, sizeof(char),
						GFP_KERNEL);

				if (bmstu_users[users_count - 1].token_serial ==
				    NULL) {
					printk("BMSTU_LSM cannot allocate memory\n");
					kfree(str);
					kfree(buff);
					return;
				}

				strcpy(bmstu_users[users_count - 1].token_serial,
				       str);

				j = 0;
				continue;
			}

			str[j] = buff[i];
			j++;
		}

	} while (len > 0);

	filp_close(f, NULL);
	kfree(str);
	kfree(buff);
}

// Checks has curent process access for some label
static bool check_process(gid_t target_gid)
{
	struct inode *inode;
	struct dentry *dentry;
	struct path path;
	char path_name[256];
	pid_t pid = current->pid;
	int err;
	int size;
	int i = 0;

	char *attr;
	int *data;
	char is_root[2];

	// Searching for process binary file
	sprintf(path_name, "/proc/%d/exe", pid);
	kern_path(path_name, LOOKUP_FOLLOW, &path);
	inode = path.dentry->d_inode;

	spin_lock(&inode->i_lock);
	hlist_for_each_entry (dentry, &inode->i_dentry, d_u.d_alias) {
	}
	spin_unlock(&inode->i_lock);

	// Reading process binary permissions
	size = __vfs_getxattr(dentry, inode, "security.bmstu_exe", NULL, 0);

	// No permissions
	if (size < 0) {
		return false;
	}

	// Checks has binary full rights
	if (size == 1) {
		err = __vfs_getxattr(dentry, inode, "security.bmstu_exe",
				     is_root, 1);

		is_root[1] = '\0';

		if (strcmp(is_root, "0") == 0) {
			printk("BMSTU_LSM whitelist program\n");
			return true;
		}

		return false;
	}

	attr = kmalloc(size, GFP_KERNEL);
	if (attr == NULL) {
		printk("BMSTU_LSM cannot allocate memory\n");
		return false;
	}

	err = __vfs_getxattr(dentry, inode, "security.bmstu_exe", attr, size);

	data = (int *)attr;

	for (; i < (size - 1) / sizeof(int); i++) {
		if (data[i] == target_gid) {
			kfree(attr);
			return true;
		}
	}

	kfree(attr);
	return false;
}

// This system hook called every time when some proccess accessing any file
static int inode_may_access(struct inode *inode, int mask)
{
	struct dentry *dentry;
	char *path = NULL;
	char buff_path[64];
	int err;
	unsigned int gid = 0;
	char *attr;

	if (!inode) {
		return 0;
	}

	if (is_root_uid()) {
		return 0;
	}

	// Getting path of inode
	spin_lock(&inode->i_lock);
	hlist_for_each_entry (dentry, &inode->i_dentry, d_u.d_alias) {
		path = dentry_path_raw(dentry, buff_path, sizeof(buff_path));
	}
	spin_unlock(&inode->i_lock);

	if (path == NULL) {
		return 0;
	}

	attr = kcalloc(8, sizeof(char), GFP_KERNEL);

	if (attr == NULL) {
		return -EACCES;
	}

	// Reading file security label
	err = __vfs_getxattr(dentry, inode, "security.bmstu", attr,
			     sizeof(attr));

	if (err < 0) {
		kfree(attr);
		return 0;
	}

	err = kstrtouint(attr, 0, &gid);
	kfree(attr);

	// Incorrect value in xattr
	if (err < 0) {
		return 0;
	}

	if (mask & MAY_READ) {
		printk("BMSTU_LSM inode access read %s, mask %d, expect GID %d\n",
		       path, mask, gid);
	}

	if (mask & MAY_WRITE) {
		printk("BMSTU_LSM inode access write %s, mask %d, expect GID %d\n",
		       path, mask, gid);
	}

	if (!has_gid(gid)) {
		printk("BMSTU_LSM You shall not pass!\n");
		return -EACCES;
	}

	if (!check_process(gid)) {
		printk("BMSTU_LSM Programm shall not pass!\n");
		return -EACCES;
	}

	if (!find_usb_device()) {
		printk("BMSTU_LSM no USB-token. You shall not pass!\n");
		return -EACCES;
	}

	printk("BMSTU_LSM Access for inode granted! %s\n", path);
	return 0;
}

// This system hook called every time when file xattr changing
static int xattr_may_change(struct dentry *dentry, const char *name)
{
	if (strcmp(name, "security.bmstu") != 0) {
		return 0;
	}

	// Only root can change security label
	if (!is_root_uid()) {
		return -EACCES;
	}

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

// Hook to run initial startup
static int bmstu_file_open(struct file *file)
{
	char *path;
	char buff[256];

	if (bmstu_lsm_is_running) {
		return 0;
	}

	if (!file) {
		return 0;
	}

	path = dentry_path_raw(file->f_path.dentry, buff, 256);

	if (strcmp(path, "/etc/passwd") == 0) {
		printk("BMSTU_LSM reading config\n");
		read_config_file();
		bmstu_lsm_is_running = true;
	}

	return 0;
}

//---HOOKS REGISTERING
static struct security_hook_list bmstu_hooks[] = {
	LSM_HOOK_INIT(inode_permission, bmstu_inode_permission),
	LSM_HOOK_INIT(inode_setxattr, bmstu_inode_setxattr),
	LSM_HOOK_INIT(inode_removexattr, bmstu_inode_removexattr),
	LSM_HOOK_INIT(file_open, bmstu_file_open),
};

//---INIT
void __init bmstu_add_hooks(void)
{
	printk("BMSTU_LSM init hooks\n");
	bmstu_lsm_is_running = false;
	security_add_hooks(bmstu_hooks, ARRAY_SIZE(bmstu_hooks), "bmstu");
}
