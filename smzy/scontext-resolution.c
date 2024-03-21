/**
 * @file context_resolution.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief 
 * @version 0.1
 * @date 2022-03-29
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// #define SMZY_DEBUG
#include "smzy.h"

#include "avc.h"
#include "avc_ss.h"
#include "classmap.h"

static char *smzyuser_to_selrole[][2] = {
	{"root", "secadm_r"},
	{"audit", "auditadm_r"},
	{"sec", "secadm_r"},
	{"normal", NULL},
	{"system", "system_r"},
	{"object","object_r" },
	{"other",NULL},
	{NULL},
};


static int (*selinux_sid_to_context)(u32 sid, char **scontext, u32 *scontext_len); // selinux function

int resolve_sid(u32 sid, char **userp, char **rolep, char **typep)
{
	int error;
	char *user, *role, *type;
	char *scontext;
	u32 scontext_len;

	error = selinux_sid_to_context(sid, &scontext, &scontext_len);
	if(error)
		return error;

	error = -EINVAL;
	user = strsep(&scontext, ":");
	if(!user)
		goto err_user;
	if(userp){
		*userp = kstrdup(user, GFP_ATOMIC);
		if(!*userp){
			error = -ENOMEM;
			goto err_user;
		}
	}

	role = strsep(&scontext, ":");
	if(!role)
		goto err_role;
	if(rolep){
		*rolep = kstrdup(role, GFP_ATOMIC); ;
		if(!*rolep){
			error = -ENOMEM;
			goto err_role;
		}
	}

	type = strsep(&scontext, ":");
	if(!type)
		goto err_type;
	if(typep){
		*typep = kstrdup(type, GFP_ATOMIC);
		if(!*typep){
			error = -ENOMEM;
			goto err_type;
		}
	}

	kfree(scontext);
	return 0;

err_type:
	kfree(*rolep);
err_role:
	kfree(*userp);
err_user:
	kfree(scontext);

	return error;
}




int encode_smzyuser_or_selrole(char *name, bool isrole, u8 *idp)
{
	u8 user;
	for(user=0; user < ARRAY_SIZE(smzyuser_to_selrole) - 1; user++){
		if(smzyuser_to_selrole[user][isrole] && 
			!strcmp(name, smzyuser_to_selrole[user][isrole])){
			*idp = user;
			return 0;
		}
	}
	*idp = user -1; // Treat as "other" user
	return 0;
}

int decode_smzyuser_or_selrole(u8 id, bool isrole, char **namep)
{
	if(!namep || id >= ARRAY_SIZE(smzyuser_to_selrole) - 1)
		return -EINVAL;
	*namep = kstrdup(smzyuser_to_selrole[id][isrole], GFP_ATOMIC);
	if(!*namep)
		return -ENOMEM;
	return 0;
}


int encode_class_permissions(char *clsname, u16 *classp, char *permsname, u32 *permsp)
{
	int i;
	const char **perms, *tmp;

	for(i=0; secclass_map[i].name ;i++){
		if(!strcmp(clsname, secclass_map[i].name)){
			*classp = i + 1;
			break;
		}
	}

	/* Class name not found */
	if(!secclass_map[i].name)
		return -EBFONT;

	/* Only convert class if permissions name is NULL. */
	if(!permsname || !permsp)
		return 0;

	perms = secclass_map[i].perms;

	// todo : there have a big BUG.....
	*permsp = 0;

	while (1)
	{
		tmp = strsep(&permsname,",");
		if(!tmp || !*tmp)
			break;
		for(i=0; perms[i]; i++){
			if(strstr(tmp,perms[i])){
				*permsp |= 1<<i;
				break;
			}
		}
		if(!perms[i])
			pr_warn("[smzy encode_class_permissions] invalid permission:%s\n", tmp);	
	}
	
	return 0;
}

int decode_class(u16 class, char **clsnamep)
{
	if(!clsnamep)
		return -EINVAL;
	*clsnamep = kstrdup(secclass_map[class-1].name, GFP_ATOMIC);
	if(!*clsnamep)
		return -ENOMEM;

	return 0;
}
int decode_permissions(u16 class, u32 permissions, char **permsnamep)
{
	int i;
	const char **perms;
	ssize_t length = 0;
	if(!permsnamep)
		return -EINVAL;

	perms = secclass_map[class-1].perms;

	*permsnamep = kzalloc(PAGE_SIZE, GFP_KERNEL); // PAGE_SIZE is enough
	if(!*permsnamep)
		return -ENOMEM;
	
	for(i=0; permissions && perms[i]; i++){
		if(permissions & 1){
			length += sprintf(*permsnamep + length, "%s,", perms[i]);
		}
		permissions >>= 1;
	}

	(*permsnamep)[length-1] = '\0'; // Omit the last separator ","
	return 0;
}


int init_scontext_resolution(void)
{
	// selinux_sid_to_context = (int (*)(u32 sid, char **scontext, u32 *scontext_len)) \
	// 				kallsyms_lookup_name("security_sid_to_context");
	// if(!selinux_sid_to_context)
	// 	return -ESPIPE;
	// printk("addr: %llx\n",(u64)selinux_sid_to_context);

	return 0;
}
