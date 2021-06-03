/* SPDX-License-Identifier: GPL-2.0+ */

/*
 * proc_entry.h - Header used internally by tracer.c for procfs actions
 *
 * Author: Cezar Craciunoiu <cezar.craciunoiu@gmail.com>
 */
#ifndef PROC_ENTRY_H__
#define PROC_ENTRY_H__

/* The entry in procfs */
static struct proc_dir_entry *proc_tracer;

/* The header to be printed in procfs */
static char *table_header =
	"PID kmalloc kfree kmalloc_mem kfree_mem sched up down lock unlock";

/*
 * tracer_proc_show() - prints data to the procfs file
 * @m:			The file where the print happens
 * @v:			unused
 * Return:		The result of the print
 *
 * The function prints the information from the hashtable of all processes.
 * The information si protected with a readlock.
 */
static int tracer_proc_show(struct seq_file *m, void *v)
{
	struct hash_entry *h_entry;
	uint32_t bucket;

	seq_printf(m, "%s\n", table_header);

	read_lock(&proc_table_lock);
	hash_for_each(proc_table, bucket, h_entry, node) {
		seq_printf(m, "%d %d %d %d %d %d %d %d %d %d\n",
			h_entry->proc_pid,
			h_entry->data[PROC_DATA_KMALLOC],
			h_entry->data[PROC_DATA_KFREE],
			h_entry->data[PROC_DATA_KMALLOC_MEM],
			h_entry->data[PROC_DATA_KFREE_MEM],
			h_entry->data[PROC_DATA_SCHED],
			h_entry->data[PROC_DATA_UP],
			h_entry->data[PROC_DATA_DOWN],
			h_entry->data[PROC_DATA_LOCK],
			h_entry->data[PROC_DATA_UNLOCK]
		);
	}
	read_unlock(&proc_table_lock);

	return 0;
}

/*
 * mem_entry_alloc() - opens the procfs entry
 * @inode:		The inode
 * @file:		The file to be opened
 * Return:		The result of the open
 */
static int tracer_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, tracer_proc_show, NULL);
}

/* Registers the operations for procfs */
static const struct proc_ops r_pops = {
	.proc_open	= tracer_read_open,
	.proc_read	= seq_read,
	.proc_release	= single_release,
};

#endif /* PROC_ENTRY_H__ */
