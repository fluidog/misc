/**
 * @file access-control.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief SMZY access control entry consisting of "sensitive", "software", "private" and "admin".
 * @version 0.1
 * @date 2022-03-28
 * 
 * @copyright Copyright (c) 2022
 * 
 */
// #define SMZY_DEBUG
#include "smzy.h"


enum smzy_final_avd{
	SMZY_ALLOW = 0,
	SMZY_DENY,
	SMZY_NEXT, // continue verdict
};


#define BUFFER_SIZE(total_buf_size,data_length) \
			total_buf_size > data_length ? total_buf_size - data_length : 0


// sensitive resource
int import_sensitive_resource(char *t_type, char *t_clsname, char *permsname)
{
	int error;
	u16 t_class;
	u32 permissions;

	error = encode_class_permissions(t_clsname, &t_class, permsname, &permissions);
	if(error)
		return error;

	return sensitive_add_node(t_type, t_class, permissions);
}

// security software
int import_security_software(char *s_type)
{
	return software_add_node(s_type);
}


// three admin
int import_three_admin(char *t_type, char *usname)
{
	u8 user;
	encode_smzyuser_or_selrole(usname, 0, &user);
	return admin_add_node(t_type, user);
}

// private data
int import_private_data(char *t_type, char *t_clsname, char *usname, char *permsname)
{
	int error;
	u8 user;
	u16 t_class;
	u32 permissions;

	encode_smzyuser_or_selrole(usname, 0, &user);
	error = encode_class_permissions(t_clsname, &t_class, permsname, &permissions);
	if(error)
		return error;

	return private_add_node(t_type, t_class, user, permissions);
}


struct buffer{
	char *addr;
	size_t size;
	size_t length;
};

static int apply_dump_sensitive(void *args, char *t_type, u16 t_class, u32 permissions)
{
	int error;
	struct buffer *buf = args;
	char *t_clasname, *permsname;

	error = decode_class(t_class, &t_clasname);
	if(error)
		return error;
	error = decode_permissions(t_class, permissions, &permsname);
	if(error)
		goto err;

	buf->length += snprintf(buf->addr + buf->length,
				BUFFER_SIZE(buf->size, buf->length),
				"%s:(0x%x)%s:(0x%x){%s}\n",
				t_type, t_class, t_clasname, permissions, permsname);

	kfree(permsname);
err:
	kfree(t_clasname);
	return error;
}
ssize_t export_sensitive_resource(char *buf, size_t size)
{
	int error;
	struct buffer tmp;
	tmp.addr = buf;
	tmp.size = size;
	tmp.length = 0;
	error = sensitive_map(&tmp, apply_dump_sensitive);
	if(error)
		return error;
	return tmp.length;
}

static int apply_dump_software(void *args, char *s_type)
{
	struct buffer *buf = args;
	buf->length += snprintf(buf->addr + buf->length, 
				BUFFER_SIZE(buf->size, buf->length), "%s\n", s_type);
	return 0;
}
ssize_t export_security_software(char *buf, size_t size)
{
	int error;
	struct buffer tmp;
	tmp.addr = buf;
	tmp.size = size;
	tmp.length = 0;
	error = software_map(&tmp,apply_dump_software);
	if(error)
		return error;
	return tmp.length;
}

static int apply_dump_admin(void *args, char *t_type, u16 user_map)
{
	int error;
	u8 user;
	char *usname;
	struct buffer *buf = args;

	buf->length += snprintf(buf->addr + buf->length, 
				BUFFER_SIZE(buf->size, buf->length), 
				"%s:(0x%x){", t_type, user_map);
	for(user=0; user_map; user++){
		if(user_map & 1){
			error = decode_smzyuser_or_selrole(user,0,&usname);
			if(error)
				return error;
			buf->length += snprintf(buf->addr + buf->length, 
				BUFFER_SIZE(buf->size, buf->length), 
				"%s,", usname);
			kfree(usname);
		}
		user_map >>= 1;
	}
	if(buf->size > buf->length)
		buf->addr[buf->length -1 ] = '}';
	buf->length += snprintf(buf->addr + buf->length, 
				BUFFER_SIZE(buf->size, buf->length), 
				"\n");
	return 0;
}
ssize_t export_three_admin(char *buf, size_t size)
{
	int error;
	struct buffer tmp;
	tmp.addr = buf;
	tmp.size = size;
	tmp.length = 0;
	error = admin_map(&tmp,apply_dump_admin);
	if(error)
		return error;
	return tmp.length;
}

static int apply_dump_private(void *args, char *t_type, u16 t_class, u8 user, u32 permissions)
{
	int error;
	char *t_clsname, *usname, *permsname;
	struct buffer *buf = args;

	error = decode_class(t_class, &t_clsname);
	if(error)
		return error;

	error = decode_permissions(t_class, permissions, &permsname);
	if(error)
		goto err_perms;

	error = decode_smzyuser_or_selrole(user, 0, &usname);
	if(error)
		goto err_user;

	buf->length += snprintf(buf->addr + buf->length,
				BUFFER_SIZE(buf->size, buf->length), 
				"%s:(0x%x)%s:(%d)%s:(0x%x){%s}\n", 
				t_type, t_class, t_clsname, user, usname, permissions, permsname);

	kfree(usname);
err_user:
	kfree(permsname);
err_perms:
	kfree(t_clsname);
	return error;
}
ssize_t export_private_data(char *buf, size_t size)
{
	int error;
	struct buffer tmp;
	tmp.addr = buf;
	tmp.size = size;
	tmp.length = 0;
	error = private_map(&tmp,apply_dump_private);
	if(error)
		return error;
	return tmp.length;
}


ssize_t export_smzy_stat(char *buf, size_t size)
{
	ssize_t length = 0;
	length += admin_stat(buf + length, BUFFER_SIZE(size, length));
	length += sensitive_stat(buf + length, BUFFER_SIZE(size, length));
	length += private_stat(buf + length, BUFFER_SIZE(size, length));
	length += software_stat(buf + length, BUFFER_SIZE(size, length));
	// length += avc_stat(buf + length, BUFFER_SIZE(size, length));
	return length;
}

/**
 * @brief Core function, smzy access control hook.
 * 
 * @param s_sid 
 * @param t_sid 
 * @param t_class 
 * @param request 
 * @return enum smzy_final_avd 
 */
enum smzy_final_avd smzy_compute_av(u32 s_sid, u32 t_sid, u16 t_class, u32 request)
{
	int error;
	char *s_user, *s_role, *s_type, *t_type;
	u8 user;
	struct smzy_av_decision *avd, tmp;

	avd = smzy_avc_lookup(s_sid, t_sid, t_class);
	if(!avd){
		error = resolve_sid(s_sid, &s_user, &s_role, &s_type);
		if(error){
			pr_warn("[smzy compute_av] resolve_sid error:%d sid:%d\n", error, s_sid);
			return SMZY_NEXT;
		}
		error = resolve_sid(t_sid, NULL, NULL, &t_type);
		if(error){
			kfree(s_user);
			kfree(s_role);
			kfree(s_type);	
			pr_warn("[smzy compute_av] resolve_sid error:%d sid:%d\n", error, t_sid);
			return SMZY_NEXT;
		}
		
		encode_smzyuser_or_selrole(s_role, 1, &user);

		tmp.sensitive = sensitive_compute_av(t_type, t_class);
		tmp.software = software_compute_av(s_type);
		tmp.private = private_compute_av(t_type, t_class, user);
		tmp.admin = admin_compute_av(t_type, user);

		error = smzy_avc_insert(s_sid, t_sid, t_class, &tmp);
		avd = &tmp;
	}


	if(request & (~avd->private)){
		return SMZY_DENY;
	}

	if(!avd->admin){
		return SMZY_DENY;
	}

	// Is not sensitive resource request.
	if(!(avd->sensitive & request)){
		return SMZY_ALLOW;
	}

	if(!avd->software){
		return SMZY_DENY;
	}

	return SMZY_NEXT;
}


int init_smzy_core(void)
{
	int error;
#define SENSITIVE_DB_SLOTS 128
#define SOFTWARRE_DB_SLOTS 128
#define PRIVATE_DB_SLOTS 128
#define ADMIN_DB_SLOTS 128
#define AVC_SLOTS 512

	error = init_scontext_resolution();
	if(error)
		return error;

	error = sensitive_init_db(SENSITIVE_DB_SLOTS);
	if(error)
		return error;

	error = private_init_db(PRIVATE_DB_SLOTS);
	if(error)
		goto err_private;

	error = admin_init_db(ADMIN_DB_SLOTS);
	if(error)
		goto err_admin;

	error = software_init_db(SOFTWARRE_DB_SLOTS);
	if(error)
		goto err_software;

	error = smzy_avc_init(AVC_SLOTS);
	if(error)
		goto err_avc;

	return 0;

err_avc:
	software_exit_db();
err_software:
	admin_exit_db();
err_admin:
	private_exit_db();
err_private:
	sensitive_exit_db();
	return error;
}

void exit_smzy_core(void)
{
	smzy_avc_exit();
	software_exit_db();
	admin_exit_db();
	private_exit_db();
	sensitive_exit_db();
} 