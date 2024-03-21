/**
 * @file ac-software.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief Security software access control logic.
 * @version 0.1
 * @date 2022-03-28
 * 
 * @copyright Copyright (c) 2022
 * 
 */

// #define SMZY_DEBUG
#include "smzy.h"

struct software_db{
	struct hlist_head *head;
	u32 elements;		/* number of elements in hash table */
	u32 slots;			/* number of slots in hash table */
};
static struct software_db *software_db; // Security software hash list

struct software_node{
	struct hlist_node list;
	char *s_type;
	char data[0];
};

static inline u32 software_hash(char *s_type)
{
	return smzy_hash(s_type, strlen(s_type)) & (software_db->slots - 1);
}
static struct software_node *software_search_node(char *s_type)
{
	u32 index;
	struct software_node *node;

	index = software_hash(s_type);

	hlist_for_each_entry(node ,&software_db->head[index], list){
		if(!strcmp(node->s_type, s_type)){
			return node;
		}
	}
	return NULL;
}

int software_add_node(char *s_type)
{
	int index;
	struct software_node *node; 
	size_t length;

	/* Duplicate keys(s_type) are just ignored. */
	if(software_search_node(s_type)){
		pr_warn("[smzy %s:%d]  Duplicate %s\n", __FUNCTION__, __LINE__, s_type);
		return 0;
	}

	length = strlen(s_type) + 1;	// Include string terminators "\0"
	node = (struct software_node *)kmalloc(length + sizeof(*node), GFP_KERNEL);
	if(!node)
		return -ENOMEM;
	
	memcpy(node->data, s_type, length);
	node->s_type = node->data;

	dbg("%s\n",node->s_type);

	index = software_hash(node->s_type);
	hlist_add_head(&node->list, &software_db->head[index]);

	software_db->elements++;

	return 0;
}


void software_del_node(char *s_type)
{
	struct software_node *node;

	node = software_search_node(s_type);
	if(node){
		hlist_del(&node->list);
		kfree(node);
		software_db->elements--;
	}
}

bool software_compute_av(char *s_type)
{
	struct software_node *node;
	node = software_search_node(s_type);
	if(!node)
		return 0;

	return 1;
}

void software_clean_db(void)
{
	int i;
	struct software_node *node;
	struct hlist_node *n;

	for(i=0; i < software_db->slots; i++ ){
		hlist_for_each_entry_safe(node,n,&software_db->head[i],list){
			hlist_del(&node->list);
			kfree(node);
			software_db->elements--;
		}
	}
}

int software_map(void *args,int (*apply)(void *args, char *s_type))
{
	int i, error;
	struct software_node *node;

	for(i=0; i < software_db->slots; i++ ){
		hlist_for_each_entry(node, &software_db->head[i],list){
			error = apply(args, node->s_type);
			if(error)
				return error;
		}
    }
	return 0;
}

ssize_t software_stat(char *buf, size_t size)
{
	int i;
	u32 used_slots = 0;
	for(i=0; i < software_db->slots; i++ ){
		if(!hlist_empty(&software_db->head[i]))
			used_slots++;
	}

	return snprintf(buf, size, "software\t%d:%d:%d\n",
			software_db->elements, used_slots, software_db->slots);
}

int software_init_db(u32 slots)
{
	int i;
	software_db = kmalloc(sizeof(*software_db), GFP_KERNEL);
	if(!software_db)
		return -ENOMEM;

	software_db->slots = slots;
	software_db->elements = 0;
	
	software_db->head = kmalloc(software_db->slots * sizeof(*(software_db->head)), GFP_KERNEL);
	if(!software_db->head){
		kfree(software_db);
		return -ENOMEM;
	}

	for(i=0; i < software_db->slots; i++)
		INIT_HLIST_HEAD(&software_db->head[i]);

	return 0;
}

void software_exit_db(void)
{
	software_clean_db();

	kfree(software_db->head);
	kfree(software_db);
}