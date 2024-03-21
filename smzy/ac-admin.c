/**
 * @file ac-admin.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief Three admin access control logic.
 * @version 0.1
 * @date 2022-03-28
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// #define SMZY_DEBUG
#include "smzy.h"


struct admin_db{
	struct hlist_head *head;
	u32 elements;		/* number of elements in hash table */
	u32 slots;			/* number of slots in hash table */
};
static struct admin_db *admin_db;

struct admin_node{
	struct hlist_node list;
	char *t_type;
	u16 user_map;
	char data[0];
};


static inline u32 admin_hash(char *t_type)
{
	return smzy_hash(t_type, strlen(t_type)) & (admin_db->slots - 1);
}
static struct admin_node *admin_search_node(char *t_type)
{
	u32 index;
	struct admin_node *node;

	index = admin_hash(t_type);

	hlist_for_each_entry(node ,&admin_db->head[index], list){
		if(!strcmp(node->t_type, t_type)){
			return node;
		}
	}
	return NULL;
}

int admin_add_node(char *t_type, u8 user)
{
	int index;
	struct admin_node *node;
	size_t length;


	/* Merge items with the same key(t_type) */
	node = admin_search_node(t_type);
	if(node){
		node->user_map |= 1 << user;
		dbg("Merge %s:%x\n", node->t_type, node->user_map);
		return 0;
	}

	length = strlen(t_type) + 1;	// Include string terminators "\0"
	node = (struct admin_node *)kmalloc(length + sizeof(*node), GFP_KERNEL);
	if(!node)
		return -ENOMEM;
	
	memcpy(node->data, t_type, length);
	node->t_type = node->data;
	node->user_map = 1 << user;
	
	dbg("%s:%x\n", node->t_type, node->user_map);

	index = admin_hash(node->t_type);
	hlist_add_head(&node->list, &admin_db->head[index]);

	admin_db->elements++;
	return 0;
}


void admin_del_node(char *t_type)
{
	struct admin_node *node;
	node = admin_search_node(t_type);
	if(node){
		hlist_del(&node->list);
		kfree(node);
		admin_db->elements--;
	}
}

bool admin_compute_av(char *t_type, u8 user)
{
	struct admin_node *node;

	node = admin_search_node(t_type);
	if(!node)
		return 1;

	if(node->user_map && (1<<user))
		return 1;

	return 0;
}

void admin_clean_db(void)
{
	int i;
	struct admin_node *node;
	struct hlist_node *n;

	for(i=0; i < admin_db->slots; i++ ){
		hlist_for_each_entry_safe(node,n,&admin_db->head[i],list){
			hlist_del(&node->list);
			kfree(node);
			admin_db->elements--;
		}
	}
}

int admin_map(void *args,int (*apply)(void *args, char *t_type, u16 user_map))
{
	int i, error;
	struct admin_node *node;

	for(i=0; i < admin_db->slots; i++ ){
		hlist_for_each_entry(node, &admin_db->head[i],list){
			error = apply(args, node->t_type, node->user_map);
			if(error)
				return error;
		}
    }
	return 0;
}

ssize_t admin_stat(char *buf, size_t size)
{
	int i;
	u32 used_slots = 0;
	for(i=0; i < admin_db->slots; i++ ){
		if(!hlist_empty(&admin_db->head[i]))
			used_slots++;
	}

	return snprintf(buf, size, "admin\t%d:%d:%d\n",
			admin_db->elements, used_slots, admin_db->slots);
}

int admin_init_db(u32 slots)
{
	int i;
	admin_db = kmalloc(sizeof(*admin_db), GFP_KERNEL);
	if(!admin_db)
		return -ENOMEM;

	admin_db->slots = slots;
	admin_db->elements = 0;
	
	admin_db->head = kmalloc(admin_db->slots * sizeof(*(admin_db->head)), GFP_KERNEL);
	if(!admin_db->head){
		kfree(admin_db);
		return -ENOMEM;
	}

	for(i=0; i < admin_db->slots; i++)
		INIT_HLIST_HEAD(&admin_db->head[i]);

	return 0;
}

void admin_exit_db(void)
{
	admin_clean_db();

	kfree(admin_db->head);
	kfree(admin_db);
}