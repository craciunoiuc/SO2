// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * Author: Cezar Craciunoiu <cezar.craciunoiu@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define PROCFS_MAX_SIZE		512
#define COMMAND_LENGTH		4

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

/*
 * struct string_entry - each entry stores a string in the list
 * @string: the saved string
 * @list: the linked list entry
 */
struct string_entry {
	char *string;
	struct list_head list;
};

static struct list_head head;


static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *p;
	struct string_entry *str_entry;

	list_for_each(p, &head) {
		str_entry = list_entry(p, struct string_entry, list);
		seq_printf(m, "%s", str_entry->string);
	}
	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

/*
 * string_entry_alloc() - allocates space for a string entry
 * @string:		The string that is going to be saved
 * Return:		The new entry or NULL if failed
 */
static inline struct string_entry *string_entry_alloc(char *string)
{
	struct string_entry *str_entry;

	str_entry = kmalloc(sizeof(*str_entry), GFP_KERNEL);
	if (!str_entry)
		return NULL;
	str_entry->string = kmalloc(strlen(string) + 1, GFP_KERNEL);
	if (!str_entry->string)
		return NULL;
	strcpy(str_entry->string, string);
	return str_entry;
}

/*
 * string_entry_free() - frees the allocated space for a string entry
 * @str_entry:		The string that is going to be freed
 */
static inline void string_entry_free(struct string_entry *str_entry)
{
	kfree(str_entry->string);
	kfree(str_entry);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	char *string_to_process;
	struct list_head *p, *q;
	struct string_entry *str_entry;
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	string_to_process = local_buffer + (COMMAND_LENGTH + 1);

	if (!strncmp(local_buffer, "addf", COMMAND_LENGTH)) {
		str_entry = string_entry_alloc(string_to_process);
		if (!str_entry)
			return -ENOMEM;

		list_add(&str_entry->list, &head);
		return local_buffer_size;
	}

	if (!strncmp(local_buffer, "adde", COMMAND_LENGTH)) {
		str_entry = string_entry_alloc(string_to_process);
		if (!str_entry)
			return -ENOMEM;

		list_add_tail(&str_entry->list, &head);
		return local_buffer_size;
	}

	if (!strncmp(local_buffer, "delf", COMMAND_LENGTH)) {
		list_for_each_safe(p, q, &head) {
			str_entry = list_entry(p, struct string_entry, list);
			if (!strcmp(str_entry->string, string_to_process)) {
				list_del(p);
				string_entry_free(str_entry);
				return local_buffer_size;
			}
		}
	}

	if (!strncmp(local_buffer, "dela", COMMAND_LENGTH)) {
		list_for_each_safe(p, q, &head) {
			str_entry = list_entry(p, struct string_entry, list);
			if (!strcmp(str_entry->string, string_to_process)) {
				list_del(p);
				string_entry_free(str_entry);
			}
		}
	}

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open		= list_read_open,
	.proc_read		= seq_read,
	.proc_release	= single_release,
};

static const struct proc_ops w_pops = {
	.proc_open		= list_write_open,
	.proc_write		= list_write,
	.proc_release	= single_release,
};

static int list_init(void)
{
	INIT_LIST_HEAD(&head);

	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Cezar Craciunoiu <cezar.craciunoiu@gmail.com>");
MODULE_LICENSE("GPL v2");
