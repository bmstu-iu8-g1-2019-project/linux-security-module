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

struct bmstu_user {
	kuid_t uid;
	char *token_serial;
};

struct bmstu_user *bmstu_users;
size_t users_count;

bool bmstu_lsm_is_running;

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

static bool is_root_uid(void)
{
	return uid_eq(current_uid(), GLOBAL_ROOT_UID);
}

static int match_device(struct usb_device *dev, void *p)
{
	if (strcmp(dev->serial, (char *)p) == 0) {
		return 1;
	}

	return 0;
}

static int find_usb_device(void)
{
	void *p = NULL;
	int i = 0;

	for (; i < users_count; i++) {
		if (uid_eq(current_uid(), bmstu_users[i].uid)) {
			p = bmstu_users[i].token_serial;
			printk("BMSTU_LSM your serial %s\n", (char *)p);
			break;
		}
	}

	return usb_for_each_dev(p, match_device);
}

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
		printk("BMSTU_LSM cannot alloce memory\n");
		return;
	}

	str = kmalloc(32, GFP_KERNEL);
	if (str == NULL) {
		printk("BMSTU_LSM cannot alloce memory\n");
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
					return;
				}

				bmstu_users = krealloc(
					bmstu_users,
					(users_count + 1) *
						sizeof(struct bmstu_user),
					GFP_ATOMIC);

				if (bmstu_users == NULL) {
					printk("BMSTU_LSM cannot alloce memory\n");
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
					printk("BMSTU_LSM cannot alloce memory\n");
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
	kfree(buff);
	kfree(str);
}

static bool check_process(gid_t target_gid)
{
	struct inode *inode;
	struct dentry *dentry;
	struct path path;
	char path_name[256];
	pid_t pid = current->pid;
	int err;
	char attr[1024];

	sprintf(path_name, "/proc/%d/exe", pid);
	printk("%s", path_name);

	kern_path(path_name, LOOKUP_FOLLOW, &path);
	inode = path.dentry->d_inode;

	spin_lock(&inode->i_lock);
	hlist_for_each_entry (dentry, &inode->i_dentry, d_u.d_alias) {
	}
	spin_unlock(&inode->i_lock);

	err = __vfs_getxattr(dentry, inode, "security.bmstu_exe", attr,
			     sizeof(attr));

	if (err < 0) {
		return false;
	}
	
	if (strcmp(attr, "0") == 0) {
		printk("root program");
		return true;
	}

	printk("attr %s", attr);
	
	return false;
}

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

	return 0;

	if (!find_usb_device()) {
		printk("BMSTU_LSM no USB-token. You shall not pass!\n");
		return -EACCES;
	}

	printk("BMSTU_LSM Access for inode granted! %s\n", path);
	return 0;
}

static int xattr_may_change(struct dentry *dentry, const char *name)
{
	if (strcmp(name, "security.bmstu") != 0) {
		return 0;
	}

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
