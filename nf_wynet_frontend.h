#ifndef _NF_WYNET_FRONTEND_H
#define _NF_WYNET_FRONTEND_H

/* --------------------------------------------------------------------------
 * INCLUDES
 * -------------------------------------------------------------------------- */
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/netfilter.h>

#include <linux/net/netfilter/hook/wynet-frontend.h>
#include <linux/net/netfilter/hook/types.h>


/* --------------------------------------------------------------------------
 * TYPES
 * -------------------------------------------------------------------------- */
/**
 * @brief: Pattern matching type
 */
enum wynet_frontend_pattern_match {
	WYNET_FRONTEND_PATTERN_MATCH_NONE = 0,
	WYNET_FRONTEND_PATTERN_MATCH_UNICAST,
	WYNET_FRONTEND_PATTERN_MATCH_MULTICAST_RTP,
	WYNET_FRONTEND_PATTERN_MATCH_MULTICAST_UDP,
};

struct wynet_frontend_filter {
    struct wynet_frontend_pattern pattern;
    int is_enable;
};

#define ENABLE_PROFILING
/**
 * @brief: Filtering list
 */
struct nf_wynet_frontend_list {
	int                   lock;
	struct sk_buff_head * skb_list;          /* Packet list */
	int                   skb_list_size_max; /* Max size of packet list */
	u16                   seq_nr;            /* Last seq_nr injected into the PTI */
	u32                   timestamp;         /* Timestamp of the last packet injected in the PTI */ 
	u32                   ssrc;              /* Synchronisation source */

#ifdef ENABLE_PROFILING
    u8                    first;
#endif

	struct sk_buff_head * udp_skb_list;        /* UDP Packet list */

	struct wynet_frontend_filter filter[WYNET_FRONTEND_PATTERN_MAX];

	u32                   is_enable;

	int                   ts_pkts_per_net_pkt;

	struct wynet_frontend_stat stat;

#ifdef ENABLE_PUREPIXEL
	struct purepixel_info pp_info;
	struct list_head      missing_pkt_list;
	u32                   missing_pkt_list_size;
	spinlock_t            missing_pkt_list_lock;
#endif

	/* purepixel queue size auto ajustement */
	unsigned long         	last_jiffies;
	unsigned int          	received_packets;
	unsigned int          	fifo_size;
	unsigned int          	inject_at_once_size; 
	struct workqueue_struct *inject_wq;
};

#ifdef ENABLE_PUREPIXEL
/**
 * @brief: Missing packets list structure
 */
struct nf_rtp_missing_pkt {
	/* Kernel linked list */
    struct list_head list;

    /* Missing packets */
    struct rtp_missing_pkt missing_pkt;
};
#endif /* ENABLE_PUREPIXEL */

/**
 * @brief: Main configuration structure  
 * @member: netfilter_ops      Netfilter operations
 * @member: list               Lists containing the filtered data
 * @member: skb_list           Buffer list used between the pattern matching 
 *                             and the packet enqueueing
 * @member: work_queue         Work queue used to (en/de)queue packets
 * @member: timer_dequeue      Timer used to trig the dequeue if no packet has 
 *                             arrived for timer_polling time
 * @member: timer_polling      Polling time
 */
struct nf_wynet_frontend_config {
	struct nf_hook_ops      netfilter_ops;

	struct nf_wynet_frontend_list list[WYNET_FRONTEND_LIST_MAX];

	struct work_struct      work_inject_rtp;
	struct work_struct      work_inject_udp;
};


#endif /* ! _NF_WYNET_FRONTEND */
