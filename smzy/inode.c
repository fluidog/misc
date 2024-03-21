/**
 * @file inode.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief The sysfs interface of SMZY.
 * @version 0.1
 * @date 2022-03-28
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <linux/kernel.h>

#include <linux/kobject.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/security.h>

// #define SMZY_DEBUG
#include "smzy.h"


static ssize_t read_sensitive_resource(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	size_t length = 0;
	char *kbuf;

	kbuf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);

	length = export_sensitive_resource(kbuf, PAGE_SIZE);
	if(unlikely(length >= PAGE_SIZE)){
		length++; // +1 Used to add a terminator "\0"
		kfree(kbuf);
		kbuf = kmalloc(length, GFP_KERNEL);
		if(!kbuf)
			return -ENOMEM;
		length = export_sensitive_resource(kbuf, length);
		dbg("realloc size:%ld\n",length);
	}

	length = simple_read_from_buffer(buf, size, ppos, kbuf, length);

	kfree(kbuf);
	return length;
}
static ssize_t write_sensitive_resource(struct file *file, const char __user *buf,
			      size_t size, loff_t *ppos)
{
	int error;
	char *kbuf;
	char *t_type, *t_class, *permission;

	error = -ENOMEM;
	kbuf = kmalloc(size,GFP_KERNEL);
	if(!kbuf)
		return error;
	
	if(copy_from_user(kbuf, buf, size))
		goto err;

	error = -EBFONT;
	if(kbuf[size-1]!='\n')
		goto err;
	kbuf[size-1] = '\0';

	t_type = strsep(&kbuf,":");
	if(unlikely(!t_type || !*t_type))
		goto err;

	t_class = strsep(&kbuf,":");
	if(unlikely(!t_class || !*t_class))
		goto err;

	permission = strsep(&kbuf,":");
	if(unlikely(!permission || !*permission))
		goto err;

	dbg("%s:%s:%s\n", t_type, t_class, permission);

	error = import_sensitive_resource(t_type,t_class,permission);
	if(unlikely(error))
		goto err;

	error = size;
err:
	// bug : kbuf changed.
	kfree(kbuf);
	return error;
}


static ssize_t read_private_data(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	size_t length = 0;
	char *kbuf;

	kbuf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);

	length = export_private_data(kbuf, PAGE_SIZE);
	if(unlikely(length >= PAGE_SIZE)){
		length++; // +1 Used to add a terminator "\0"
		kfree(kbuf);
		kbuf = kmalloc(length, GFP_KERNEL);
		if(!kbuf)
			return -ENOMEM;
		length = export_private_data(kbuf, length);
		dbg("realloc size:%ld\n",length);
	}

	length = simple_read_from_buffer(buf, size, ppos, kbuf, length);

	kfree(kbuf);
	return length;
}
static ssize_t write_private_data(struct file *file, const char __user *buf,
			      size_t size, loff_t *ppos)
{
	int error;
	char *kbuf;
	char *t_type, *t_class, *user, *permissions;

	error = -ENOMEM;
	kbuf = kmalloc(size,GFP_KERNEL);
	if(!kbuf)
		return error;
	
	if(copy_from_user(kbuf, buf, size))
		goto err;

	error = -EBFONT;
	if(kbuf[size-1]!='\n')
		goto err;
	kbuf[size-1] = '\0';

	user = strsep(&kbuf,":");
	if(unlikely(!user || !*user))
		goto err;

	t_type = strsep(&kbuf,":");
	if(unlikely(!t_type || !*t_type))
		goto err;

	t_class = strsep(&kbuf,":");
	if(unlikely(!t_class || !*t_class))
		goto err;	

	permissions = strsep(&kbuf,":");
	if(unlikely(!permissions || !*permissions))
		goto err;

	dbg("%s:%s:%s:%s\n", user, t_type, t_class, permissions);
	
	error = import_private_data(t_type, t_class, user, permissions);
	if(unlikely(error))
		goto err;

	error = size;
err:
	kfree(kbuf);
	return error;
}


static ssize_t read_three_admin(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	size_t length = 0;
	char *kbuf;

	kbuf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);

	length = export_three_admin(kbuf, PAGE_SIZE);
	if(unlikely(length >= PAGE_SIZE)){
		length++; // +1 Used to add a terminator "\0"
		kfree(kbuf);
		kbuf = kmalloc(length, GFP_KERNEL);
		if(!kbuf)
			return -ENOMEM;
		length = export_three_admin(kbuf, length);
		dbg("realloc size:%ld\n",length);
	}

	length = simple_read_from_buffer(buf, size, ppos, kbuf, length);

	kfree(kbuf);
	return length;
}
static ssize_t write_three_admin(struct file *file, const char __user *buf,
			      size_t size, loff_t *ppos)
{
	int error;
	char *kbuf;
	char *t_type, *user;

	error = -ENOMEM;
	kbuf = kmalloc(size,GFP_KERNEL);
	if(!kbuf)
		return error;
	
	if(copy_from_user(kbuf, buf, size))
		goto err;

	error = -EBFONT;
	if(kbuf[size-1]!='\n')
		goto err;
	kbuf[size-1] = '\0';

	user = strsep(&kbuf,":");
	if(unlikely(!user || !*user))
		goto err;

	t_type = strsep(&kbuf,":");
	if(unlikely(!t_type || !*t_type))
		goto err;

	dbg("%s:%s\n", t_type, user);
	
	error = import_three_admin(t_type, user);
	if(unlikely(error))
		goto err;

	error = size;
err:
	kfree(kbuf);
	return error;
}


static ssize_t read_security_software(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	size_t length = 0;
	char *kbuf;

	kbuf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);

	length = export_security_software(kbuf, PAGE_SIZE);
	if(unlikely(length >= PAGE_SIZE)){
		length++; // +1 Used to add a terminator "\0"
		kfree(kbuf);
		kbuf = kmalloc(length, GFP_KERNEL);
		if(!kbuf)
			return -ENOMEM;
		length = export_security_software(kbuf, length);
		dbg("realloc size:%ld\n",length);
	}

	length = simple_read_from_buffer(buf, size, ppos, kbuf, length);

	kfree(kbuf);
	return length;
}
static ssize_t write_security_software(struct file *file, const char __user *buf,
			      size_t size, loff_t *ppos)
{
	int error;
	char *kbuf;
	char *s_type;

	error = -ENOMEM;
	kbuf = kmalloc(size,GFP_KERNEL);
	if(!kbuf)
		return error;
	
	if(copy_from_user(kbuf, buf, size))
		goto err;

	error = -EBFONT;
	if(kbuf[size-1]!='\n')
		goto err;
	kbuf[size-1] = '\0';

	s_type = kbuf;

	dbg("%s\n", s_type);
	
	error = import_security_software(s_type);
	if(unlikely(error))
		goto err;

	error = size;
err:
	kfree(kbuf);
	return error;
}


static ssize_t read_smzy_stat(struct file *file, char __user *buf, size_t size, loff_t *ppos)
{
	size_t length = 0;
	char *kbuf;

	kbuf = (char *)kmalloc(PAGE_SIZE, GFP_KERNEL);

	length = export_smzy_stat(kbuf, PAGE_SIZE);
	if(unlikely(length >= PAGE_SIZE)){
		length++; // +1 Used to add a terminator "\0"
		kfree(kbuf);
		kbuf = kmalloc(length, GFP_KERNEL);
		if(!kbuf)
			return -ENOMEM;
		length = export_smzy_stat(kbuf, length);
		dbg("realloc size:%ld\n",length);
	}

	length = simple_read_from_buffer(buf, size, ppos, kbuf, length);

	kfree(kbuf);
	return length;
}



static const struct file_operations sensitive_resource_ops = {
	.read		= read_sensitive_resource,
	.write		= write_sensitive_resource,
};
static const struct file_operations three_admin_ops = {
	.read		= read_three_admin,
	.write		= write_three_admin,
};
static const struct file_operations security_software_ops = {
	.read		= read_security_software,
	.write		= write_security_software,
};
static const struct file_operations private_data_ops = {
	.read		= read_private_data,
	.write		= write_private_data,
};
static const struct file_operations smzy_stat_ops = {
	.read		= read_smzy_stat,
};


static const struct tree_descr smzy_files[] = {
		[3] = {
			"smzy-stat", &smzy_stat_ops, S_IRUGO|S_IWUSR},
		[4] = {
			"baseline", &sensitive_resource_ops, S_IRUGO|S_IWUSR},
		[5] = {
			"anquanruanjian", &security_software_ops, S_IRUGO|S_IWUSR},
		[6] = {
			"siyoushuju", &private_data_ops, S_IRUGO|S_IWUSR},
		[7] = {
			"sanyuan", &three_admin_ops, S_IRUGO|S_IWUSR},
		/* last one */
			{NULL}
};



static struct dentry *smzy_root,*files_dentry[10];
static void securityfs_mkfile(void)
{
	int i;
	const char *name = "smzy";
	smzy_root = securityfs_create_dir(name, NULL);

	
	for(i=3; smzy_files[i].name; i++){
		files_dentry[i] = securityfs_create_file(smzy_files[i].name,smzy_files[i].mode,smzy_root,NULL,smzy_files[i].ops);
	}
}

static void securityfs_rmfile(void)
{
	int i;
	
	for(i=3; smzy_files[i].name; i++){
		securityfs_remove(files_dentry[i]);
	}

	securityfs_remove(smzy_root);

}


int init_fs(void)
{
	
	securityfs_mkfile();
	
	return 0;
}

void exit_fs(void)
{
	
	securityfs_rmfile();

}
