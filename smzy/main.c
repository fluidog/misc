/**
 * @file main.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief SMZY entry for initialize this module.
 * @version 0.1
 * @date 2022-03-28
 * 
 * @copyright Copyright (c) 2022
 * 
 */
#include <linux/module.h>

// #define DEBUG
#include "smzy.h"


int __init init_smzy(void)
{
	int error = 0;

	printk("Init smzy security module!\n");

	error = init_fs();
	if(error)
		return error;

	error = init_smzy_core();
	if(error){
		exit_fs();
		return error;
	}

	return error;
}


void __exit exit_smzy(void)
{
	exit_smzy_core();
	exit_fs();

	printk("Exit smzy security module!\n");
}


module_init(init_smzy);
module_exit(exit_smzy);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("liuqi");
MODULE_VERSION("v0.1");
MODULE_DESCRIPTION("SMZY SECURITY");
