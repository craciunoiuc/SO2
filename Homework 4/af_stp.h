/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Used internally in af_stp.c
 */

#ifndef AF_STP_H_
#define AF_STP_H_

#define MAC_ADDRESS_LENGTH	6

/*
 * struct proc_stp_stats - statistics about the STP protocol
 * @rx_pkts: the number of received packets
 * @hdr_err: the number of header errors
 * @csum_err: the number of checksum errors
 * @no_sock: the number of packets without a destination socket
 * @no_buffs: the number of packets that could not be recieved (queue full)
 * @tx_pkts: the number of sent packets
 */
struct proc_stp_stats {
	int rx_pkts;
	int hdr_err;
	int csum_err;
	int no_sock;
	int no_buffs;
	int tx_pkts;
};

/*
 * struct stp_socket - stp socket information
 * @socket: the used socket structure
 * @bound_if: the used interface
 * @bound_port: the port number used
 * @dst_port: the port number sending to
 * @mac: the mac address sending to
 * @lock: lock to make socket access exclusive
 * @node: hash table node
 */
struct stp_socket {
	struct sock socket;
	int bound_if;
	int bound_port;
	int dst_port;
	unsigned char mac[MAC_ADDRESS_LENGTH];
	spinlock_t lock;
	struct hlist_node node;
};

static int stp_connect(struct socket *sock, struct sockaddr *addr, int length,
			int flags);
static int stp_sendmsg(struct socket *sock, struct msghdr *header,
			size_t length);
static int stp_recvmsg(struct socket *sock, struct msghdr *header,
			size_t length, int flags);
static int stp_release(struct socket *sock);
static int stp_bind(struct socket *sock, struct sockaddr *addr, int addr_len);
static int stp_socket_create(struct net *net, struct socket *sock,
				int protocol, int kern);
static int stp_proc_show(struct seq_file *m, void *v);
static int stp_open(struct inode *inode, struct  file *file);

/*
 * stp_build_skb() - Builds the content in the socket buffer before sending
 * @skb:	The socket buffer to fill
 * @device:	The network device in use
 * @sock:	The socket sending data
 * @it:		The iter to copy the datagram from
 * @stp_header:	The STP header to add to the packet
 * @length:	The length of the packet
 * Return:	0 or negative on fail
 */
static inline int stp_build_skb(struct sk_buff *skb, struct net_device *device,
				struct socket *sock, struct iov_iter *it,
				struct stp_hdr stp_header, size_t length)
{
	__u8 *stp_header_aux;
	int retval;

	skb_reserve(skb, sizeof(stp_header) + sizeof(struct sockaddr_stp));

	skb_put(skb, length);
	retval = skb_copy_datagram_from_iter(skb, 0, it, length);

	stp_header_aux = skb_push(skb, sizeof(stp_header));
	memcpy(stp_header_aux, &stp_header, sizeof(stp_header));

	retval = dev_hard_header(skb, device, htons(ETH_P_STP),
				((struct stp_socket *) sock)->mac, NULL,
				length + sizeof(stp_header));
	if (retval < 0)
		return retval;

	skb->dev = device;
	skb->sk = sock->sk;
	skb->priority = sock->sk->sk_priority;
	skb->protocol = PF_STP;

	return 0;
}

#endif /* AF_STP_H_ */
