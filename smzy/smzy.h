
#ifndef _SMZY_H
#define _SMZY_H


#include <linux/kernel.h>
#include <linux/slab.h>

#include <linux/list.h>
#include <linux/string.h>


#define SMZY_DEBUG

#ifdef SMZY_DEBUG
#define dbg(format, ...) \
	pr_info("[smzy %s:%d] " format, \
        __FUNCTION__, __LINE__, ##__VA_ARGS__);
#else
#define dbg(format, ...)
#endif


struct smzy_av_decision{
	u32 private;
	u32 sensitive;
	bool admin;
	bool software;
};


static inline u32 smzy_hash(const char *key, size_t size)
{
	u32 hashval = 0;
	
	// To do: Can be optimized to integer steps if size is always too long.
	for(; size; size--){
		// hashval = ((hashval << 4) | (hashval >> (8 * sizeof(u32) - 4))) ^ (*key++);
		hashval += *key++;
	}
	return hashval;
}

int init_fs(void);
void exit_fs(void);

int init_scontext_resolution(void);
int resolve_sid(u32 sid, char **userp, char **rolep, char ** typep);
int encode_smzyuser_or_selrole(char *name, bool isrole, u8 *idp);
int decode_smzyuser_or_selrole(u8 id, bool isrole, char **namep);
int encode_class_permissions(char *clsname, u16 *classp, char *permsname, u32 *permsp);
int decode_class(u16 class, char **clsnamep);
int decode_permissions(u16 class, u32 permissions, char **permsnamep);

int init_smzy_core(void);
void exit_smzy_core(void);
int import_private_data(char *t_type, char *t_clsname, char *usname, char *permsname);
ssize_t export_private_data(char *buf, size_t size);
int import_three_admin(char *t_type, char *usname);
ssize_t export_three_admin(char *buf, size_t size);
int import_security_software(char *s_type);
ssize_t export_security_software(char *buf, size_t size);
int import_sensitive_resource(char *t_type, char *t_clsname, char *permsname);
ssize_t export_sensitive_resource(char *buf, size_t size);
ssize_t export_smzy_stat(char *buf, size_t size);


int smzy_avc_init(u32 slots);
void smzy_avc_exit(void);
void smzy_avc_flush(void);
int smzy_avc_insert(u32 s_sid, u32 t_sid, u16 t_class, struct smzy_av_decision *avd);
struct smzy_av_decision *smzy_avc_lookup(u32 s_sid, u32 t_sid, u16 t_class);


int software_init_db(u32 slots);
void software_exit_db(void);
int software_add_node(char *s_type);
void software_del_node(char *s_type);
void software_clean_db(void);
bool software_compute_av(char *s_type);
int software_map(void *args,int (*apply)(void *args, char *s_type));
ssize_t software_stat(char *buf, size_t size);

int admin_init_db(u32 slots);
void admin_exit_db(void);
int admin_add_node(char *t_type, u8 user);
void admin_del_node(char *t_type);
void admin_clean_db(void);
bool admin_compute_av(char *t_type, u8 user);
int admin_map(void *args,int (*apply)(void *args, char *t_type, u16 user_map));
ssize_t admin_stat(char *buf, size_t size);

int private_init_db(u32 slots);
void private_exit_db(void);
int private_add_node(char *t_type, u16 t_class, u8 user, u32 permissions);
void private_del_node(char *t_type, u16 t_class, u8 user);
void private_clean_db(void);
u32 private_compute_av(char *t_type, u16 t_class, u8 user);
int private_map(void *args,int (*apply)(void *args, char *t_type, u16 t_class, u8 user, u32 permissions));
ssize_t private_stat(char *buf, size_t size);

int sensitive_init_db(u32 slots);
void sensitive_exit_db(void);
int sensitive_add_node(char *t_type, u16 t_class, u32 permissions);
void sensitive_del_node(char *t_type, u16 t_class);
void sensitive_clean_db(void);
u32 sensitive_compute_av(char *t_type, u16 t_class);
int sensitive_map(void *args,int (*apply)(void *args, char *t_type, u16 t_class, u32 permissions));
ssize_t sensitive_stat(char *buf, size_t size);

#endif