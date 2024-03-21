/**
 * @file avc.c
 * @author liuqi (liuqi1@kylinos.cn)
 * @brief Access vector cache of SMZY.
 * @version 0.1
 * @date 2022-03-28
 * 
 * @copyright Copyright (c) 2022
 * 
 */
// #define SMZY_DEBUG
#include "smzy.h"

struct smzy_av_cache{
	struct hlist_head *head;	
	struct kmem_cache *node_pools;
	struct stat{
		u32 lookups;
		u32 misses;
		u32 allocations;
		u32 actives;		// current active smzy_avc nodes.
		u32 reclaims;		//reclaim times
		u32 slots;			/* number of slots in hash table */
	}stat;
};
static struct smzy_av_cache *smzy_av_cache;


struct smzy_avc_node{
	struct hlist_node list;
	u64 used;	// The number of used, which is used only for statistical analysis.

	u32 s_sid;
	u32 t_sid;
	u16 t_class;
	struct smzy_av_decision decision;
};


static inline u32 smzy_avc_hash(u32 s_sid, u32 t_sid, u16 t_class)
{
	u32 hashval;
	hashval = smzy_hash((const char *)&s_sid, sizeof(s_sid));
	hashval ^= smzy_hash((const char *)&t_sid, sizeof(t_sid));
	hashval ^= smzy_hash((const char *)&t_class, sizeof(t_class));

	return hashval  & (smzy_av_cache->stat.slots -1);
}

static struct smzy_avc_node *smzy_avc_search_node(u32 s_sid, u32 t_sid, u16 t_class)
{
	struct smzy_avc_node *node;
	int index;

	index = smzy_avc_hash(s_sid, t_sid, t_class);

	hlist_for_each_entry(node, &smzy_av_cache->head[index], list) {
		if (s_sid == node->s_sid &&
		    t_class == node->t_class &&
		    t_sid == node->t_sid) {
				node->used++;
				return node;
		}
	}
	return NULL;
}

struct smzy_av_decision *smzy_avc_lookup(u32 s_sid, u32 t_sid, u16 t_class)
{
	struct smzy_avc_node *node;

	smzy_av_cache->stat.lookups++;
	node = smzy_avc_search_node(s_sid, t_sid, t_class);

	if (node)
		return &node->decision;

	smzy_av_cache->stat.misses++;
	return NULL;
}

static void smzy_avc_reclaim_node(void)
{
	struct smzy_avc_node *node, *last_node = NULL;
	struct hlist_node *n;
	int i;
	smzy_av_cache->stat.reclaims++;

	// Reclaim half of them which are least used. 
	for(i=0; i< smzy_av_cache->stat.slots; i++){
			hlist_for_each_entry_safe(node, n, &smzy_av_cache->head[i], list) {
				if(!last_node){
					last_node = node;
					continue;
				}

				if(node->used > last_node->used)
					node = last_node;
				
				last_node = NULL;
				hlist_del(&node->list);
				kfree(node);
				smzy_av_cache->stat.actives--;
		}
	}
}

static struct smzy_avc_node *smzy_avc_alloc_node(void)
{
	struct smzy_avc_node *node;

	node = kmem_cache_zalloc(smzy_av_cache->node_pools, GFP_ATOMIC|__GFP_NOMEMALLOC);
	if(!node)
		return NULL;

	smzy_av_cache->stat.allocations++;
	smzy_av_cache->stat.actives++;

	if(smzy_av_cache->stat.actives > smzy_av_cache->stat.slots) // reclaims some nodes while too many.
		smzy_avc_reclaim_node();

	return node;
}

int smzy_avc_insert(u32 s_sid, u32 t_sid, u16 t_class, struct smzy_av_decision *avd)
{
	struct smzy_avc_node *node;

	node = smzy_avc_search_node(s_sid, t_sid, t_class);
	if(node){
		memcpy(&node->decision, avd, sizeof(struct smzy_av_decision));
		return 0;
	}

	node = smzy_avc_alloc_node();
	if(!node)
		return -ENOMEM; 

	node->s_sid = s_sid;
	node->t_sid = t_sid;
	node->t_class = t_class;
	node->used = 1;
	memcpy(&node->decision, avd, sizeof(struct smzy_av_decision));

	return 0;
}

void smzy_avc_flush(void)
{
	int i;
	struct smzy_avc_node *node;
	struct hlist_node *n;

	for(i=0; i < smzy_av_cache->stat.slots; i++ ){
		hlist_for_each_entry_safe(node,n,&smzy_av_cache->head[i],list){
			hlist_del(&node->list);
			kfree(node);
		}
	}
	smzy_av_cache->stat.actives = 0;
}

ssize_t avc_stat(char *buf, size_t size)
{
	int i;
	u32 used_slots = 0;
	for(i=0; i < smzy_av_cache->stat.slots; i++ ){
		if(!hlist_empty(&smzy_av_cache->head[i]))
			used_slots++;
	}

	return snprintf(buf, size, "avc %d:%d:%d\n",
			smzy_av_cache->stat.actives, used_slots, smzy_av_cache->stat.slots);
}

int smzy_avc_init(u32 slots)
{
	int i,error;
	error = -ENOMEM;
	smzy_av_cache = kmalloc(sizeof(*smzy_av_cache), GFP_KERNEL);
	if(!smzy_av_cache)
		return error;

	smzy_av_cache->head = kmalloc(slots * sizeof(*(smzy_av_cache->head)), GFP_KERNEL);
	if(!smzy_av_cache->head)
		goto err_avchead;

	for(i=0; i < slots; i++)
		INIT_HLIST_HEAD(&smzy_av_cache->head[i]);

	smzy_av_cache->node_pools = kmem_cache_create("smzy_smzy_avc_node", sizeof(struct smzy_avc_node),
					0, 0, NULL);
	if(!smzy_av_cache->node_pools)
		goto err_nodepools;

	memset(&smzy_av_cache->stat, 0, sizeof(smzy_av_cache->stat));
	smzy_av_cache->stat.slots = slots;

	return 0;

err_nodepools:
	kfree(smzy_av_cache->head);
err_avchead:
	kfree(smzy_av_cache);
	return error;
}

void smzy_avc_exit(void)
{
	smzy_avc_flush();

	kmem_cache_destroy(smzy_av_cache->node_pools);
	kfree(smzy_av_cache->head);
	kfree(smzy_av_cache);
}