// SPDX-License-Identifier: GPL-2.0+

/*
 * af_stp.c - SO2 network transport protocol
 *
 * Author: Cezar Craciunoiu
 * Author: Calin Juganaru
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/in.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <net/sock.h>

#include "stp.h"
#include "af_stp.h"

/* Structure to hold all statistics for procfs */
static struct proc_stp_stats stats;
/* Lock to guarantee printed data is correct */
static DEFINE_RWLOCK(stp_stats_lock);
/* Procfs entry */
static struct proc_dir_entry *proc_stp_file;

/* Hashtable to keep evidence of bound ports */
static DEFINE_HASHTABLE(stp_binds_htable, 16);

/* STP protocol init */
static struct proto stp_protocol = {
	.owner    = THIS_MODULE,
	.obj_size = sizeof(struct stp_socket),
	.name     = STP_PROTO_NAME
};

/* STP protocol operations init */
static const struct proto_ops stp_ops = {
	.family     = PF_STP,
	.owner      = THIS_MODULE,
	.release    = stp_release,
	.bind       = stp_bind,
	.connect    = stp_connect,
	.socketpair = sock_no_socketpair,
	.accept     = sock_no_accept,
	.getname    = sock_no_getname,
	.poll       = datagram_poll,
	.ioctl      = sock_no_ioctl,
	.listen     = sock_no_listen,
	.shutdown   = sock_no_shutdown,
	.sendmsg    = stp_sendmsg,
	.recvmsg    = stp_recvmsg,
	.mmap       = sock_no_mmap,
	.sendpage   = sock_no_sendpage
};

/* STP socket creation registration */
static const struct net_proto_family stp_net_proto_family = {
	.owner  = THIS_MODULE,
	.family = PF_STP,
	.create = stp_socket_create
};

/* Procfs operations for statistics */
static const struct proc_ops stp_pops = {
	.proc_open      = stp_open,
	.proc_read      = seq_read,
	.proc_release   = single_release
};

/*
 * stp_connect() - Associates a socket with a remote port and MAC address
 * @sock:	The socket on which the connect happens
 * @addr:	The address of the socket
 * @length:	The length of the address
 * @flags:	The connection flags
 * Return:	0 or negative on error
 */
static int stp_connect(struct socket *sock, struct sockaddr *addr,
			int length, int flags)
{
	struct stp_socket *stp_sock;
	struct sockaddr_stp *stp_addr;

	if (!sock || !addr)
		return -EINVAL;

	stp_sock = (struct stp_socket *) sock->sk;
	stp_addr = (struct sockaddr_stp *) addr;

	if (sizeof(*stp_addr) > length || !stp_sock)
		return -EINVAL;

	stp_sock->dst_port = stp_addr->sas_port;
	memcpy(stp_sock->mac, stp_addr->sas_addr, MAC_ADDRESS_LENGTH);

	return 0;
}

/*
 * stp_sendmsg() - Prepares a packet for sending and adds it to the queue
 * @sock:	The socket to send the message on
 * @header:	The header of the message
 * @length:	The length of the message
 * Return:	0 or negative on fail
 */
static int stp_sendmsg(struct socket *sock, struct msghdr *header,
			size_t length)
{
	struct sk_buff *socket_buffer;
	struct net_device *device;
	struct stp_socket *stp_socket;
	struct sockaddr_stp *stp_addr;
	struct stp_hdr stp_header;
	size_t total_length;
	int retval;

	if (!sock || !header)
		return -EINVAL;

	stp_socket     = (struct stp_socket *) sock->sk;
	stp_header.src = stp_socket->bound_port;
	stp_header.len = length + sizeof(stp_header);
	stp_addr       = (struct sockaddr_stp *) header->msg_name;
	stp_header.dst = stp_addr ? stp_addr->sas_port : stp_socket->dst_port;
	stp_socket->dst_port = stp_addr ? stp_addr->sas_port : 0;

	device = dev_get_by_index(sock_net(sock->sk), stp_socket->bound_if);

	if (!device)
		return -EINVAL;

	total_length = device->needed_tailroom + length +
			sizeof(struct stp_hdr) + sizeof(struct sockaddr_stp);
	socket_buffer = sock_alloc_send_skb(sock->sk, total_length, 0, &retval);
	if (!socket_buffer) {
		retval = -ENOMEM;
		goto stp_sendmsg_alloc_send_fail;
	}

	retval = stp_build_skb(socket_buffer, device, sock, &header->msg_iter,
				stp_header, length);
	if (retval < 0)
		goto stp_sendmsg_build_skb_fail;

	retval = dev_queue_xmit(socket_buffer);
	retval = net_xmit_errno(retval);
	if (!retval)
		goto stp_sendmsg_dev_queue_xmit_fail;

	write_lock(&stp_stats_lock);
	++stats.tx_pkts;
	write_unlock(&stp_stats_lock);

	return length;

stp_sendmsg_dev_queue_xmit_fail:
stp_sendmsg_alloc_send_fail:
stp_sendmsg_build_skb_fail:
	dev_put(device);

	return retval;
}

/*
 * stp_recvmsg() - Called to receive a new STP packet.
 * @sock:	The socket on which the recv happens
 * @header:	The message header
 * @length:	The length of the header
 * @flags:	The connection flags
 * Return:	the number of bytes received or negative on error
 */
static int stp_recvmsg(struct socket *sock, struct msghdr *header,
			size_t length, int flags)
{
	write_lock(&stp_stats_lock);
	++stats.rx_pkts;
	write_unlock(&stp_stats_lock);

	if (!sock || !sock->sk) {
		write_lock(&stp_stats_lock);
		++stats.no_sock;
		write_unlock(&stp_stats_lock);
		return -EINVAL;
	}

	if (!header) {
		write_lock(&stp_stats_lock);
		++stats.hdr_err;
		write_unlock(&stp_stats_lock);
		return -EINVAL;
	}

	return length;
}

/*
 * stp_release() - Removes the socket from the bound list and also cleans it.
 * @sock:	The socket to release
 * Return:	0 or negative on error
 */
static int stp_release(struct socket *sock)
{
	struct stp_socket *stp_sk = (struct stp_socket *) sock->sk;
	int bkt;
	struct hlist_node *tmp;
	struct stp_socket *iter;

	if (!sock || !sock->sk)
		return -EINVAL;

	if (stp_sk->bound_port) {
		spin_lock(&stp_sk->lock);

		hash_for_each_safe(stp_binds_htable, bkt, tmp, iter, node) {
			if (stp_sk->bound_port == iter->bound_port)
				hash_del(&stp_sk->node);
		}
		stp_sk->bound_port = 0;
		spin_unlock(&stp_sk->lock);
	}

	skb_queue_purge(&sock->sk->sk_receive_queue);
	skb_queue_purge(&sock->sk->sk_write_queue);

	sock_put(sock->sk);
	sock->sk = NULL;

	return 0;
}

/*
 * stp_socket_create() - Binds a socket to a port
 * @sock:	The socket to bind
 * @addr:	Address to bind to
 * @addr_len:	Address length
 * Return:	0 or negative on error
 */
static int stp_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
	struct sockaddr_stp *stp_addr = (struct sockaddr_stp *) addr;
	struct stp_socket *stp_sk, *iter;

	if (!addr || !sock || addr_len < sizeof(struct sockaddr_stp))
		return -EINVAL;

	if (stp_addr->sas_family != AF_STP)
		return -EAFNOSUPPORT;

	if (!ntohs(stp_addr->sas_port))
		return -EINVAL;

	stp_sk = (struct stp_socket *) sock->sk;

	lock_sock(sock->sk);
	spin_lock(&stp_sk->lock);

	hash_for_each_possible(stp_binds_htable, iter, node,
				stp_addr->sas_port) {
		if (iter->bound_port == stp_addr->sas_port) {
			spin_unlock(&stp_sk->lock);
			release_sock(sock->sk);
			return -EBUSY;
		}
	}

	stp_sk->bound_port = stp_addr->sas_port;
	stp_sk->bound_if = stp_addr->sas_ifindex;
	hash_add(stp_binds_htable, &stp_sk->node, stp_addr->sas_port);

	spin_unlock(&stp_sk->lock);
	release_sock(sock->sk);

	return 0;
}

/*
 * stp_socket_create() - Creates a new STP socket and initializes it
 * @net:	Given to sk_alloc
 * @sock:	The socket to create
 * @protocol:	Protocol of the created socket
 * @kern:	Given to sk_alloc
 * Return:	0 or negative on error
 */
static int stp_socket_create(struct net *net, struct socket *sock, int protocol,
			   int kern)
{
	struct sock *sk;

	if (protocol != 0 || !sock)
		return -EINVAL;

	if (sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;
	sk = sk_alloc(net, AF_STP, GFP_KERNEL, &stp_protocol, kern);
	if (!sk)
		return -ENOMEM;

	sock->ops = &stp_ops;
	sk->sk_family = AF_STP;
	sk->sk_protocol = protocol;
	spin_lock_init(&((struct stp_socket *) sk)->lock);

	sock_init_data(sock, sk);

	return 0;
}

/*
 * stp_proc_show() - Prints the statistics to procfs
 * @m:		The file to print to
 * @v:		Unused
 * Return:	0 or negative on error
 */
static int stp_proc_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s\n", "RxPkts HdrErr CsumErr NoSock NoBuffs TxPkts");
	read_lock(&stp_stats_lock);
	seq_printf(m, "%d %d %d %d %d %d\n", stats.rx_pkts, stats.hdr_err,
		stats.csum_err, stats.no_sock, stats.no_buffs, stats.tx_pkts);
	read_unlock(&stp_stats_lock);
	return 0;
}

/*
 * stp_open() - Opens a procfs entry
 * @inode:	Unused
 * @file:	The file to open
 * Return:	0 or negative on error
 */
static int stp_open(struct inode *inode, struct  file *file)
{
	return single_open(file, stp_proc_show, NULL);
}

/*
 * stp_init() - Registers the procfs entry, the protocol and the socket type
 * Return:	0 or negative on error
 */
static int stp_init(void)
{
	int retval;

	proc_stp_file = proc_create(STP_PROC_NET_FILENAME, 0444,
					init_net.proc_net, &stp_pops);
	if (!proc_stp_file)
		goto stp_init_proc_fail;

	retval = proto_register(&stp_protocol, 0);
	if (retval)
		goto stp_init_proto_register_fail;

	retval = sock_register(&stp_net_proto_family);
	if (retval)
		goto stp_init_sock_register_fail;

	hash_init(stp_binds_htable);

	return 0;

stp_init_sock_register_fail:
	proto_unregister(&stp_protocol);

stp_init_proto_register_fail:
	proc_remove(proc_stp_file);

stp_init_proc_fail:
	return -ENOMEM;
}

/*
 * stp_exit() - Unregisters everything and cleans bound ports
 */
static void stp_exit(void)
{
	struct stp_socket *h_entry;
	struct hlist_node *tmp;
	uint32_t bkt;

	proc_remove(proc_stp_file);
	sock_unregister(AF_STP);
	proto_unregister(&stp_protocol);

	hash_for_each_safe(stp_binds_htable, bkt, tmp, h_entry, node)
		if (h_entry && h_entry->bound_port)
			hash_del(&h_entry->node);
}

module_init(stp_init);
module_exit(stp_exit);

MODULE_DESCRIPTION("SO2 Transport Protocol");
MODULE_AUTHOR("Cezar Craciunoiu");
MODULE_AUTHOR("Calin Juganaru");
MODULE_LICENSE("GPL");
