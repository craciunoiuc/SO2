/* SPDX-License-Identifier: GPL-2.0+ */

/*
 * tracer_probes.h - Header used internally by tracer.c for probing actions
 *
 * Author: Cezar Craciunoiu <cezar.craciunoiu@gmail.com>
 */
#ifndef TRACER_PROBES_H__
#define TRACER_PROBES_H__

/*
 * trace_increase_hash_value() - increments the value at type with qty
 * @type:			The value to be increased
 * @qty:			The quantity to be increased with
 *
 * Find the current pid in the hashtable and increase the value. Thread-safe
 * operation.
 */
static inline void trace_increase_hash_value(uint32_t type, uint32_t qty)
{
	struct hash_entry *h_entry;
	pid_t key = current->pid;

	write_lock(&proc_table_lock);
	hash_for_each_possible(proc_table, h_entry, node, key) {
		if (h_entry->proc_pid == key) {
			h_entry->data[type] += qty;
			break;
		}
	}
	write_unlock(&proc_table_lock);
}

/*
 * trace_add_hash_mem_entry() - saves the addr-size memory association
 * @addr:			The address to be saved
 * @size:			The size of the allocated memory
 *
 * Find the current pid in the hashtable and save the addr-size memory entry
 * in its own hashtable. The internal hashtable is synchronized with the same
 * write lock. The entry is allocated.
 */
static inline void trace_add_hash_mem_entry(uint32_t addr, uint32_t size)
{
	struct mem_entry *m_entry;
	struct hash_entry *h_entry;
	pid_t key = current->pid;

	m_entry = mem_entry_alloc(addr, size);

	write_lock(&proc_table_lock);
	hash_for_each_possible(proc_table, h_entry, node, key) {
		if (h_entry->proc_pid == key) {
			hash_add(h_entry->mem_table, &m_entry->node, addr);
			break;
		}
	}
	write_unlock(&proc_table_lock);
}

/*
 * trace_remove_hash_mem_entry() - removes the addr-size memory association
 * @addr:			The address to be removed
 *
 * Find the current pid in the hashtable and remove the addr-size memory entry
 * in its own hashtable. The internal hashtable is synchronized with the same
 * write lock. The entry is freed.
 */
static inline uint32_t trace_remove_hash_mem_entry(uint32_t addr)
{
	struct mem_entry *m_entry;
	struct hlist_node *tmp;
	struct hash_entry *h_entry;
	pid_t key = current->pid;
	uint32_t size_to_ret = 0;

	write_lock(&proc_table_lock);
	hash_for_each_possible(proc_table, h_entry, node, key) {
		if (h_entry->proc_pid == key) {
			hash_for_each_possible_safe(h_entry->mem_table,
						m_entry, tmp, node, addr) {
				if (m_entry->addr == addr) {
					size_to_ret = m_entry->size;
					hash_del(&m_entry->node);
					mem_entry_free(m_entry);
					break;
				}
			}
			break;
		}
	}
	write_unlock(&proc_table_lock);

	return size_to_ret;
}

/*
 * up_probe_handler() - the up handler
 * @ri:			The kprobe instance
 * @regs:		The registers
 *
 * Increments the up value for the current process.
 * Skips incremeting if the process is the ioctl invoker.
 */
static int up_probe_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	if (current->pid == this_module_pid)
		return 1;

	trace_increase_hash_value(PROC_DATA_UP, 1);

	return 0;
}
NOKPROBE_SYMBOL(up_probe_handler);

/* Registers the handler to the probe */
static struct kretprobe up_probe = {
	.entry_handler = up_probe_handler,
	.maxactive = 256,
};

/*
 * down_probe_handler() - the down handler
 * @ri:			The kprobe instance
 * @regs:		The registers
 *
 * Increments the down value for the current process.
 * Skips incremeting if the process is the ioctl invoker.
 */
static int down_probe_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	if (current->pid == this_module_pid)
		return 1;

	trace_increase_hash_value(PROC_DATA_DOWN, 1);

	return 0;
}
NOKPROBE_SYMBOL(down_probe_handler);

/* Registers the handler to the probe */
static struct kretprobe down_probe = {
	.entry_handler = down_probe_handler,
	.maxactive = 256,
};

/*
 * mutex_lock_probe_handler() - the mutex_lock handler
 * @ri:			The kprobe instance
 * @regs:		The registers
 *
 * Increments the mutex_lock value for the current process.
 * Skips incremeting if the process is the ioctl invoker.
 */
static int mutex_lock_probe_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	if (current->pid == this_module_pid)
		return 1;

	trace_increase_hash_value(PROC_DATA_LOCK, 1);

	return 0;
}
NOKPROBE_SYMBOL(mutex_lock_probe_handler);

/* Registers the handler to the probe */
static struct kretprobe mutex_lock_probe = {
	.entry_handler = mutex_lock_probe_handler,
	.maxactive = 256,
};

/*
 * mutex_unlock_probe_handler() - the mutex_unlock handler
 * @ri:			The kprobe instance
 * @regs:		The registers
 *
 * Increments the mutex_unlock value for the current process.
 * Skips incrementing if the process is the ioctl invoker.
 */
static int mutex_unlock_probe_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	if (current->pid == this_module_pid)
		return 1;

	trace_increase_hash_value(PROC_DATA_UNLOCK, 1);

	return 0;
}
NOKPROBE_SYMBOL(mutex_unlock_probe_handler);

/* Registers the handler to the probe */
static struct kretprobe mutex_unlock_probe = {
	.entry_handler = mutex_unlock_probe_handler,
	.maxactive = 256,
};

/*
 * sched_probe_handler() - the sched handler
 * @ri:			The kprobe instance
 * @regs:		The registers
 *
 * Increments the sched value for the current process.
 * Skips incrementing if the process is the ioctl invoker.
 */
static int sched_probe_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	if (current->pid == this_module_pid)
		return 1;

	trace_increase_hash_value(PROC_DATA_SCHED, 1);

	return 0;
}
NOKPROBE_SYMBOL(sched_probe_handler);

/* Registers the handler to the probe */
static struct kretprobe sched_probe = {
	.entry_handler = sched_probe_handler,
	.maxactive = 256,
};

/*
 * kmalloc_probe_ret_handler() - the kmalloc return handler
 * @ri:				The kprobe instance
 * @regs:			The registers
 *
 * Increments the sched value for the current process. Also increases the total
 * allocated memory by kmalloc and saves the memory entry in the process table.
 * Skips incrementing if the process is the ioctl invoker.
 */
static int kmalloc_probe_ret_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	struct kmalloc_regs *handler_data;

	if (current->pid == this_module_pid)
		return 1;

	handler_data = (struct kmalloc_regs *)ri->data;

	trace_increase_hash_value(PROC_DATA_KMALLOC, 1);

	trace_increase_hash_value(PROC_DATA_KMALLOC_MEM, handler_data->size);

	trace_add_hash_mem_entry(regs_return_value(regs), handler_data->size);

	return 0;
}
NOKPROBE_SYMBOL(kmalloc_probe_ret_handler);

/*
 * kmalloc_probe_entry_handler() - the kmalloc entry handler
 * @ri:				The kprobe instance
 * @regs:			The registers
 *
 * Saves the size that will be allocated by malloc to be given to the ret
 * handler.
 */
static int kmalloc_probe_entry_handler(struct kretprobe_instance *ri,
					struct pt_regs *regs)
{
	struct kmalloc_regs *handler_data;

	if (current->pid == this_module_pid)
		return 1;

	handler_data = (struct kmalloc_regs *)ri->data;
	handler_data->size = regs->ax;

	return 0;
}
NOKPROBE_SYMBOL(kmalloc_probe_entry_handler);

/* Registers the handlers and the data storage to the probe */
static struct kretprobe kmalloc_probe = {
	.entry_handler = kmalloc_probe_entry_handler,
	.handler = kmalloc_probe_ret_handler,
	.data_size = sizeof(struct kmalloc_regs),
	.maxactive = 256,
};

/*
 * kfree_probe_handler() - the kfree handler
 * @ri:				The kprobe instance
 * @regs:			The registers
 *
 * Searches for the saved size and increases the freed quantity.
 */
static int kfree_probe_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
	if (current->pid == this_module_pid)
		return 1;

	trace_increase_hash_value(PROC_DATA_KFREE, 1);

	trace_increase_hash_value(PROC_DATA_KFREE_MEM,
				trace_remove_hash_mem_entry(regs->ax));
	return 0;
}
NOKPROBE_SYMBOL(kfree_probe_handler);

/* Registers the handler to the probe */
static struct kretprobe kfree_probe = {
	.entry_handler = kfree_probe_handler,
	.maxactive = 256,
};

#endif /* TRACER_PROBES_H__ */
