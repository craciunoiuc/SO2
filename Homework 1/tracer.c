// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Linux KProbe Tracer
 *
 * Author: Cezar Craciunoiu <cezar.craciunoiu@gmail.com>
 */
#include <linux/cdev.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/hashtable.h>
#include <linux/miscdevice.h>
#include <linux/sched/signal.h>
#include <linux/kprobes.h>
#include <linux/semaphore.h>

#include "./tracer.h"
#include "./tracer_helper.h"
#include "./tracer_probes.h"
#include "./proc_entry.h"

static int tracer_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int tracer_release(struct inode *inode, struct file *file)
{
	return 0;
}

/*
 * tracer_ioctl() - ioctl interpretation function
 * @file:			The value to be increased
 * @cmd:			The ioctl command
 * @arg:			The ioctl argument
 *
 * If the operation is TRACER_ADD_PROCESS it adds a new process entry in the
 * hashtable. The operation is thread-safe.
 *
 * If the operation is TRACER_REMOVE_PROCESS it removes the process entry from
 * the hashtable. The operation is thread-safe.
 */
static long tracer_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct hash_entry *h_entry;
	struct hlist_node *tmp;
	int ret = 0;
	pid_t key = arg;

	this_module_pid = current->pid;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		h_entry = hash_entry_alloc(key);

		if (!h_entry) {
			ret = -ENOMEM;
			break;
		}

		write_lock(&proc_table_lock);
		hash_add(proc_table, &h_entry->node, key);
		write_unlock(&proc_table_lock);

		break;

	case TRACER_REMOVE_PROCESS:
		write_lock(&proc_table_lock);
		hash_for_each_possible_safe(proc_table, h_entry, tmp, node, key) {
			if (h_entry->proc_pid == key) {
				hash_del(&h_entry->node);
				hash_entry_free(h_entry);
				break;
			}
		}
		write_unlock(&proc_table_lock);


		break;
	default:
		ret = -EINVAL;
	}

	return ret;
}

/* Ioctl file operations functions registration */
static const struct file_operations tracer_fops = {
	.owner = THIS_MODULE,
	.open = tracer_open,
	.release = tracer_release,
	.unlocked_ioctl = tracer_ioctl,
};

/* Devices properties registration */
static struct miscdevice dev = {
	.minor = TRACER_DEV_MINOR,
	.name  = TRACER_DEV_NAME,
	.fops  = &tracer_fops,
};


/*
 * tracer_init() - kprobe tracer init
 *
 * Initializes all used values. It frees everything if failure is detected.
 */
static int tracer_init(void)
{
	int ret = 0;

	proc_tracer = proc_create(PROCFS_FILE, 0000, proc_tracer, &r_pops);

	if (!proc_tracer) {
		ret = -ENOMEM;
		goto tracer_init_proc_fail;
	}

	hash_init(proc_table);

	ret = misc_register(&dev);
	if (ret)
		goto tracer_init_proc_fail;

	up_probe.kp.symbol_name = __s_up;
	ret = register_kretprobe(&up_probe);
	if (ret)
		goto tracer_init_up_fail;

	down_probe.kp.symbol_name = __s_down;
	ret = register_kretprobe(&down_probe);
	if (ret)
		goto tracer_init_down_fail;

	kmalloc_probe.kp.symbol_name = __s_kmalloc;
	ret = register_kretprobe(&kmalloc_probe);
	if (ret)
		goto tracer_init_kmalloc_fail;

	kfree_probe.kp.symbol_name = __s_kfree;
	ret = register_kretprobe(&kfree_probe);
	if (ret)
		goto tracer_init_kfree_fail;

	sched_probe.kp.symbol_name = __s_sched;
	ret = register_kretprobe(&sched_probe);
	if (ret)
		goto tracer_init_sched_fail;

	mutex_lock_probe.kp.symbol_name = __s_lock;
	ret = register_kretprobe(&mutex_lock_probe);
	if (ret)
		goto tracer_init_lock_fail;

	mutex_unlock_probe.kp.symbol_name = __s_unlock;
	ret = register_kretprobe(&mutex_unlock_probe);
	if (ret)
		goto tracer_init_unlock_fail;

goto tracer_init_success;

tracer_init_unlock_fail:
	unregister_kretprobe(&mutex_unlock_probe);

tracer_init_lock_fail:
	unregister_kretprobe(&mutex_lock_probe);

tracer_init_sched_fail:
	unregister_kretprobe(&sched_probe);

tracer_init_kfree_fail:
	unregister_kretprobe(&kfree_probe);

tracer_init_kmalloc_fail:
	unregister_kretprobe(&kmalloc_probe);

tracer_init_down_fail:
	unregister_kretprobe(&down_probe);

tracer_init_up_fail:
	unregister_kretprobe(&up_probe);

tracer_init_proc_fail:
	proc_remove(proc_tracer);

tracer_init_success:
	return ret;
}

/*
 * tracer_exit() - kprobe tracer exit
 *
 * Frees all used data. Cleans hashtables, unregisters probes, and removes
 * procfs entry and the device.
 */
static void tracer_exit(void)
{
	struct hash_entry *h_entry;
	struct hlist_node *tmp;
	uint32_t bkt;

	write_lock(&proc_table_lock);
	hash_for_each_safe(proc_table, bkt, tmp, h_entry, node) {
		hash_del(&h_entry->node);
		hash_entry_free(h_entry);
	}
	write_unlock(&proc_table_lock);

	proc_remove(proc_tracer);
	misc_deregister(&dev);

	unregister_kretprobe(&up_probe);
	unregister_kretprobe(&down_probe);
	unregister_kretprobe(&kmalloc_probe);
	unregister_kretprobe(&kfree_probe);
	unregister_kretprobe(&sched_probe);
	unregister_kretprobe(&mutex_lock_probe);
	unregister_kretprobe(&mutex_unlock_probe);
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Linux KProbe Tracer");
MODULE_AUTHOR("Cezar Craciunoiu <cezar.craciunoiu@gmail.com>");
MODULE_LICENSE("GPL v2");
