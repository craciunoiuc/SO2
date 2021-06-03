/* SPDX-License-Identifier: GPL-2.0+ */

/*
 * tracer_helper.h - Header used internally by tracer.c
 *
 * Author: Cezar Craciunoiu <cezar.craciunoiu@gmail.com>
 */
#ifndef TRACER_HELPER_H__
#define TRACER_HELPER_H__

/* Number of buckets in process hashtable (1<<8) */
#define MAX_PROC_PW2	8

/* Number of buckets in memory hashtable (1<<8) */
#define MAX_MEM_PW2	8

/* Number of entries for each process */
#define PROBED_DATA_NR	9

/* Data in the process buffer */
#define PROC_DATA_KMALLOC	0
#define PROC_DATA_KFREE		1
#define PROC_DATA_KMALLOC_MEM	2
#define PROC_DATA_KFREE_MEM	3
#define PROC_DATA_SCHED		4
#define PROC_DATA_UP		5
#define PROC_DATA_DOWN		6
#define PROC_DATA_LOCK		7
#define PROC_DATA_UNLOCK	8

/* Probed functions names */
static char __s_kmalloc[NAME_MAX]	= "__kmalloc";
static char __s_kfree[NAME_MAX]		= "kfree";
static char __s_up[NAME_MAX]		= "up";
static char __s_down[NAME_MAX]		= "down_interruptible";
static char __s_lock[NAME_MAX]		= "mutex_lock_nested";
static char __s_unlock[NAME_MAX]	= "mutex_unlock";
static char __s_sched[NAME_MAX]		= "schedule";

/* Used to save the pid of the ioctl invoker (to skip probing it) */
static pid_t this_module_pid;

/*
 * struct kmalloc_regs - structure used to pass handler data
 * @size: the size allocated by malloc
 */
struct kmalloc_regs {
	uint32_t size;
};

/*
 * struct mem_entry - addr-size associations to register allocations
 * @addr: the addr allocated by malloc
 * @size: the size allocated by malloc
 * @node: the node in the hashtable
 */
struct mem_entry {
	uint32_t addr;
	uint32_t size;
	struct hlist_node node;
};

/*
 * struct mem_entry - addr-size associations to register allocations
 * @addr: the addr allocated by malloc
 * @size: the size allocated by malloc
 * @node: the node in the hashtable
 */
struct hash_entry {
	pid_t proc_pid;
	uint32_t data[PROBED_DATA_NR];
	DECLARE_HASHTABLE(mem_table, MAX_MEM_PW2);
	struct hlist_node node;
};

/*
 * hash_entry_alloc() - allocates space for one process
 * @pid:		The pid of the process to be allocated
 * Return:		The new entry to be added in the hashtable
 */
static struct hash_entry *hash_entry_alloc(pid_t pid)
{
	struct hash_entry *h_entry;

	h_entry = kcalloc(1, sizeof(*h_entry), GFP_KERNEL);
	if (!h_entry)
		return NULL;

	h_entry->proc_pid = pid;

	hash_init(h_entry->mem_table);

	return h_entry;
}

/*
 * mem_entry_alloc() - allocates space for one memory entry
 * @addr:		The address of the memory to be saved
 * @size:		The size of the memory to be saved
 * Return:		The new entry to be added in the memory hashtable
 */
static struct mem_entry *mem_entry_alloc(uint32_t addr, uint32_t size)
{
	struct mem_entry *m_entry;

	m_entry = kmalloc(sizeof(*m_entry), GFP_ATOMIC);
	if (!m_entry)
		return NULL;

	m_entry->size = size;
	m_entry->addr = addr;

	return m_entry;
}

/*
 * mem_entry_free() - frees space of one memory entry
 * @m_entry:		The entry to be freed
 */
static void mem_entry_free(struct mem_entry *m_entry)
{
	kfree(m_entry);
}
/*
 * mem_entry_free() - frees space of one process entry
 * @h_entry:		The entry to be freed
 *
 * Also frees saved memory entries for the process
 */
static void hash_entry_free(struct hash_entry *h_entry)
{
	struct mem_entry *m_entry;
	struct hlist_node *tmp;
	uint32_t bkt;

	hash_for_each_safe(h_entry->mem_table, bkt, tmp, m_entry, node) {
		hash_del(&m_entry->node);
		mem_entry_free(m_entry);
	}

	kfree(h_entry);
}


/* Hashtable used to save process information */
DECLARE_HASHTABLE(proc_table, MAX_PROC_PW2);

/* RW Lock for hashtable synchronization */
DEFINE_RWLOCK(proc_table_lock);

#endif /* TRACER_HELPER_H__ */
