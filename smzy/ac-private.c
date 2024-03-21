/**
 * @file ac-private.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief Private data access control logic.
 * @version 0.1
 * @date 2022-03-28
 * 
 * @copyright Copyright (c) 2022
 * 
 */
// #define SMZY_DEBUG
#include "smzy.h"

static struct private_db{
	struct hlist_head *head;
	u32 elements;		/* number of elements in hash table */
	u32 slots;			/* number of slots in hash table */
}*private_db;

struct private_node{
	struct hlist_node list;	
	char *t_type;
	u16 t_class;
	u8 user;
	u32 permissions;
	char data[0];
};


static inline u32 private_hash(char *t_type, u16 t_class)
{
	u32 hvalue;
	hvalue = smzy_hash(t_type, strlen(t_type));
	hvalue ^= smzy_hash((const char *)&t_class, sizeof(t_class));

	return hvalue & (private_db->slots - 1);
}

/* This is a trick. We can add items with the same key(t_typ,t_class) and different data(user) into the hlist. */
static struct private_node *private_search_node(char *t_type, u16 t_class, u8 user)
{
	u32 index;
	struct private_node *node;

	index = private_hash(t_type, t_class);

	hlist_for_each_entry(node ,&private_db->head[index], list){
		if(!strcmp(node->t_type, t_type) && 
			(node->t_class==t_class) && 
			(node->user==user)){
			return node;
		}
	}
	return NULL;
}

int private_add_node(char *t_type, u16 t_class, u8 user, u32 permissions)
{
	int index;
	struct private_node *node;
	size_t length;

	/* Duplicate items are just ignored. */ 
	if(private_search_node(t_type, permissions, user)){
		pr_warn("[smzy %s:%d]  Duplicate %d:%s:0x%x:0x%x\n", __FUNCTION__, __LINE__, user, t_type, t_class, permissions);
		return 0;
	}

	length = strlen(t_type) + 1;	// Include string terminators "\0"
	node = (struct private_node *)kmalloc(length + sizeof(*node), GFP_KERNEL);
	if(!node)
		return -ENOMEM;
	
	memcpy(node->data, t_type, length);
	node->t_type = node->data;
	node->user = user;
	node->t_class = t_class;
	node->permissions = permissions;
	
	dbg("%d:%s:0x%x:0x%x\n",node->user, node->t_type, node->t_class, node->permissions);

	index = private_hash(node->t_type, node->t_class);
	hlist_add_head(&node->list, &private_db->head[index]);

	private_db->elements++;

	return 0;
}


void private_del_node(char *t_type, u16 t_class, u8 user)
{
	struct private_node *node;
	node = private_search_node(t_type, t_class, user);
	if(node){
		hlist_del(&node->list);
		kfree(node);
		private_db->elements--;
	}
}

u32 private_compute_av(char *t_type, u16 t_class, u8 user)
{
	int index;
	struct private_node *node;
	u32 denied = 0, allow;

	index = private_hash(t_type, t_class);

	hlist_for_each_entry(node ,&private_db->head[index], list){
		if(!strcmp(node->t_type, t_type) && (node->t_class==t_class)){
			if(node->user==user){
				allow = node->permissions;
			}else{
				denied |= node->permissions;
			}
		}
	}
	return ~denied | allow;
}

void private_clean_db(void)
{
	int i;
	struct private_node *node;
	struct hlist_node *n;

	for(i=0; i < private_db->slots; i++ ){
		hlist_for_each_entry_safe(node,n,&private_db->head[i],list){
			hlist_del(&node->list);
			kfree(node);
			private_db->elements--;
		}
	}
}

int private_map(void *args,int (*apply)(void *args, char *t_type, u16 t_class, u8 user, u32 permissions))
{
	int i, error;
	struct private_node *node;

	for(i=0; i < private_db->slots; i++ ){
		hlist_for_each_entry(node, &private_db->head[i],list){
			error = apply(args, node->t_type, node->t_class, node->user, node->permissions);
			if(error)
				return error;
		}
    }
	return 0;
}

ssize_t private_stat(char *buf, size_t size)
{
	int i;
	u32 used_slots = 0;
	for(i=0; i < private_db->slots; i++ ){
		if(!hlist_empty(&private_db->head[i]))
			used_slots++;
	}

	return snprintf(buf, size, "private\t%d:%d:%d\n",
			private_db->elements, used_slots, private_db->slots);
}

int private_init_db(u32 slots)
{
	int i;
	private_db = kmalloc(sizeof(*private_db), GFP_KERNEL);
	if(!private_db)
		return -ENOMEM;

	private_db->slots = slots;
	private_db->elements = 0;
	
	private_db->head = kmalloc(private_db->slots * sizeof(*(private_db->head)), GFP_KERNEL);
	if(!private_db->head){
		kfree(private_db);
		return -ENOMEM;
	}

	for(i=0; i < private_db->slots; i++)
		INIT_HLIST_HEAD(&private_db->head[i]);

	return 0;
}
void private_exit_db(void)
{
	private_clean_db();

	kfree(private_db->head);
	kfree(private_db);
}