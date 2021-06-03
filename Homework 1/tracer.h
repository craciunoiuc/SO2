/* SPDX-License-Identifier: GPL-2.0+ */

/*
 * tracer_helper.h - Header shared with user space
 *
 * Author: Cezar Craciunoiu <cezar.craciunoiu@gmail.com>
 */
#ifndef TRACER_H__
#define TRACER_H__ 1

#include <asm/ioctl.h>
#ifndef __KERNEL__
#include <sys/types.h>
#endif /* __KERNEL__ */

/* Device information */
#define TRACER_DEV_MINOR 42
#define TRACER_DEV_MAJOR 10
#define TRACER_DEV_NAME "tracer"

/* Procfs entry name */
#define PROCFS_FILE	    "tracer"

/* Ioctl operations */
#define TRACER_ADD_PROCESS	_IOW(_IOC_WRITE, 42, pid_t)
#define TRACER_REMOVE_PROCESS	_IOW(_IOC_WRITE, 43, pid_t)

#endif /* TRACER_H_ */
