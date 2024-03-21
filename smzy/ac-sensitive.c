/**
 * @file ac-sensitive.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief Sensitive resource access control logic.
 * @version 0.1
 * @date 2022-03-28
 * 
 * @copyright Copyright (c) 2022
 * 
 */
// #define SMZY_DEBUG
#include "smzy.h"

struct sensitive_db{
	struct hlist_head *head;
	u32 elements;		/* number of elements in hash table */
	u32 slots;			/* number of slots in hash table */
};
static struct sensitive_db *sensitive_db; // Security software hash list

struct sensitive_node{
	struct hlist_node list;
	char *t_type;
	u16 t_class;
	u32 permissions;
	char data[0];
};

static inline u32 sensitive_hash(char *t_type, u16 t_class)
{
	u32 hvalue = 0;
	hvalue = smzy_hash(t_type, strlen(t_type));
	hvalue ^= smzy_hash((const char *)&t_class, sizeof(t_class));

	return hvalue & (sensitive_db->slots - 1);
}

/* This is a trick. We can add items with the same key(t_typ,t_class) and different data(user) into the hlist. */
static struct sensitive_node *sensitive_search_node(char *t_type, u16 t_class)
{
	u32 index;
	struct sensitive_node *node;

	index = sensitive_hash(t_type, t_class);

	hlist_for_each_entry(node ,&sensitive_db->head[index], list){
		if(!strcmp(node->t_type, t_type) && 
			(node->t_class==t_class) ){
			return node;
		}
	}
	return NULL;
}

int sensitive_add_node(char *t_type, u16 t_class, u32 permissions)
{
	int index;
	struct sensitive_node *node;
	size_t length;

	/* Duplicate keys(t_type,t_class) are just ignored. */
	if(sensitive_search_node(t_type, t_class)){
		pr_warn("[smzy %s:%d] Duplicate %s:%x\n", __FUNCTION__, __LINE__, t_type, t_class);
		return 0;
	}

	length = strlen(t_type) + 1;	// Include string terminators "\0"
	node = (struct sensitive_node *)kmalloc(length + sizeof(*node), GFP_KERNEL);
	if(!node)
		return -ENOMEM;

	memcpy(node->data, t_type, length);
	node->t_type = node->data;
	node->t_class = t_class;
	node->permissions = permissions;

	dbg("%s:0x%x:0x%x\n",node->t_type, node->t_class, node->permissions);

	index = sensitive_hash(node->t_type, node->t_class);
	hlist_add_head(&node->list, &sensitive_db->head[index]);

	sensitive_db->elements++;
	return 0;
}

void sensitive_del_node(char *t_type, u16 t_class)
{
	struct sensitive_node *node;
	
	node = sensitive_search_node(t_type, t_class);
	if(node){
		hlist_del(&node->list);
		kfree(node);
		sensitive_db->elements--;
	}
}

u32 sensitive_compute_av(char *t_type, u16 t_class)
{
	struct sensitive_node *node;
	node = sensitive_search_node(t_type, t_class);
	if(!node)
		return 0;

	return node->permissions;
}

void sensitive_clean_db(void)
{
	int i;
	struct sensitive_node *node;
	struct hlist_node *n;

	for(i=0; i < sensitive_db->slots; i++ ){
		hlist_for_each_entry_safe(node,n,&sensitive_db->head[i],list){
			hlist_del(&node->list);
			kfree(node);
			sensitive_db->elements--;
		}
	}
}

int sensitive_map(void *args,int (*apply)(void *args, char *t_type, u16 t_class, u32 permissions))
{
	int i, error;
	struct sensitive_node *node;

	for(i=0; i < sensitive_db->slots; i++ ){
		hlist_for_each_entry(node, &sensitive_db->head[i],list){
			error = apply(args, node->t_type, node->t_class, node->permissions);
			if(error)
				return error;
		}
    }
	return 0;
}

ssize_t sensitive_stat(char *buf, size_t size)
{
	int i;
	u32 used_slots = 0;
	for(i=0; i < sensitive_db->slots; i++ ){
		if(!hlist_empty(&sensitive_db->head[i]))
			used_slots++;
	}

	return snprintf(buf, size, "sensitive\t%d:%d:%d\n",
			sensitive_db->elements, used_slots, sensitive_db->slots);
}

int sensitive_init_db(u32 slots)
{
	int i;
	sensitive_db = kmalloc(sizeof(*sensitive_db), GFP_KERNEL);
	if(!sensitive_db)
		return -ENOMEM;

	sensitive_db->slots = slots;
	sensitive_db->elements = 0;
	
	sensitive_db->head = kmalloc(sensitive_db->slots * sizeof(*(sensitive_db->head)), GFP_KERNEL);
	if(!sensitive_db->head){
		kfree(sensitive_db);
		return -ENOMEM;
	}

	for(i=0; i < sensitive_db->slots; i++)
		INIT_HLIST_HEAD(&sensitive_db->head[i]);

	return 0;
}

void sensitive_exit_db(void)
{
	sensitive_clean_db();

	kfree(sensitive_db->head);
	kfree(sensitive_db);
}