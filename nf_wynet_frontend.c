/* --------------------------------------------------------------------------
 * INCLUDES
 * -------------------------------------------------------------------------- */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/scatterlist.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <linux/in.h>
#include <linux/time.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/jiffies.h>

#include <linux/net/netfilter/hook/trace.h>
#include <linux/net/netfilter/hook/wynet-frontend.h>
#include <linux/net/netfilter/hook/wynet-frontend-command.h>
#include <linux/net/netfilter/hook/rtp.h>

#include "nf_wynet_frontend.h"


/* --------------------------------------------------------------------------
 * EXTERNAL METHODS: PTI methods
 * -------------------------------------------------------------------------- */
extern struct stdemux *stfe_get_handle(int adapter, unsigned int channelid);
extern int stfe_write_kernel(struct stdemux *stdemux, const char * Buffer, size_t Count, loff_t* ppos);
extern int stfe_write_user(struct stdemux *stdemux, const char * Buffer, size_t Count, loff_t* ppos);
extern int stfe_write_scatterlist (struct stdemux *demux, struct scatterlist *sg, int size);


/* --------------------------------------------------------------------------
 * CONSTANTS
 * -------------------------------------------------------------------------- */
#define WYNET_VERSION            "2.0"

#define WYNET_LINUX_DVB_ADAPTER  2

#define PLAYER_PKT_LEN           188

#define WYNET_NET_TS_PKT_IN_RTP  7

#define WYNET_NET_PKT_LEN        (WYNET_NET_TS_PKT_IN_RTP * PLAYER_PKT_LEN)

#define WYNET_FLUSH_LIMIT        20

#define FIFO_DURATION 			250 /* ms */
#define FIFO_INJECT_RATIO 		5   /* fifo_size / FIFO_INJECT_RATIO will be injected at a time */
#define MINIMUM_PACKET_INJECT_COUNT 	6   /* will inject at minimum MINIMUM_PACKET_INJECT_COUNT packet a time */
#define MINIMUM_FIFO_SIZE 		FIFO_INJECT_RATIO * MINIMUM_PACKET_INJECT_COUNT
#define INITIAL_FIFO_SIZE 		300 /* initial number of packet in the fifo till FIFO_DURATION ms has elapsed */
#define FIFO_MAX_SIZE 			1000

#define MAX_SWTS_PAGES 			260 

/* --------------------------------------------------------------------------
 * GLOBAL VARIABLES
 * -------------------------------------------------------------------------- */
struct nf_wynet_frontend_config wynet_frontend_config;


/* --------------------------------------------------------------------------
 * INTERNAL METHOD PROTOTYPES
 * -------------------------------------------------------------------------- */
static int wynet_frontend_is_enabled(int queue_idx);

#ifdef ENABLE_PUREPIXEL
/**
 * @brief: Check discontinuity in the queue queue_idx up to specified amount of packets
 * @param: queue_idx    [in] Index of the queue
 */
void wynet_frontend_check_discontinuity(int queue_idx);
#endif

static void dequeue_rtp_packet( struct nf_wynet_frontend_list *nwf_list, int queue_idx,
				struct scatterlist *sg, struct sk_buff_head *sg_skb_list);

typedef void (dequeue_packet_function)(	struct nf_wynet_frontend_list *nwf_list, int queue_idx,
					struct scatterlist *sg, struct sk_buff_head *sg_skb_list);

static void inject_rtp_handler(struct work_struct* work);

static void inject_udp_handler(struct work_struct* work);

static enum wynet_frontend_pattern_match wynet_frontend_match(struct nf_wynet_frontend_config* config, struct sk_buff* skb, int queue_idx);

static unsigned int wynet_frontend(unsigned int             hooknum,
								   struct sk_buff**         skb,
								   const struct net_device* in,
								   const struct net_device* out,
								   int (*okfn)(struct sk_buff*));

static int wynet_frontend_get_l5_hdr_offset(struct sk_buff * skb);

static void __wynet_frontend_ssrc_changed_handler(int queue_idx, u32 ssrc, u32 timestamp, u16 seq);

static void rtp_queue_skb(struct nf_wynet_frontend_config * config, int queue_idx, struct sk_buff * skb_current);


/**
 *	skb_queue_is_first - check if skb is the first entry in the queue
 *	@list: queue head
 *	@skb: buffer
 *
 *	Returns true if @skb is the first buffer on the list.
 */
static inline bool skb_queue_is_first(const struct sk_buff_head *list,
									  const struct sk_buff *skb)
{
	return (skb->prev == (struct sk_buff *) list);
}

/**
 *	skb_queue_is_last - check if skb is the last entry in the queue
 *	@list: queue head
 *	@skb: buffer
 *
 *	Returns true if @skb is the last buffer on the list.
 */
static inline bool skb_queue_is_last(const struct sk_buff_head *list,
									 const struct sk_buff *skb)
{
	return (skb->next == (struct sk_buff *) list);
}

void init_wynet_frontend_list(struct nf_wynet_frontend_list *list)
{
	memset(list, 0x00, sizeof(struct nf_wynet_frontend_list));

	list->skb_list          = (struct sk_buff_head*)kmalloc(sizeof(struct sk_buff_head), GFP_KERNEL);
	skb_queue_head_init(list->skb_list);
	list->udp_skb_list 	= (struct sk_buff_head*)kmalloc(sizeof(struct sk_buff_head), GFP_KERNEL);
	skb_queue_head_init(list->udp_skb_list);

	list->inject_wq = create_workqueue("inject_wq");

	list->skb_list_size_max = 0;
	list->is_enable         = 0;
	list->timestamp         = 0;
	list->ssrc              = 0;
	list->ts_pkts_per_net_pkt = WYNET_NET_TS_PKT_IN_RTP;
	memset(&list->stat, 0x00, sizeof(struct wynet_frontend_stat));
	list->lock              = 0;

	list->last_jiffies      = jiffies;
	list->received_packets  = 0;
	list->fifo_size  	= INITIAL_FIFO_SIZE;
	list->inject_at_once_size = INITIAL_FIFO_SIZE / FIFO_INJECT_RATIO;

#ifdef ENABLE_PROFILING
	list->first = 2;
#endif

#ifdef ENABLE_PUREPIXEL
	memset(&list->pp_info, 0x00, sizeof(struct purepixel_info));

	INIT_LIST_HEAD(&list->missing_pkt_list);
	list->missing_pkt_list_size = 0;
#endif

}

/* --------------------------------------------------------------------------
 * MODULE HOOK
 * -------------------------------------------------------------------------- */
static int __init nf_wynet_frontend_init(void) {
	int idx;

	trace_info("Load wynet frontend: v%s\n", WYNET_VERSION);

	trace_verbose("Init work queue\n");
	INIT_WORK(&(wynet_frontend_config.work_inject_udp), inject_udp_handler);
	INIT_WORK(&(wynet_frontend_config.work_inject_rtp), inject_rtp_handler);

	for (idx = 0 ; idx < WYNET_FRONTEND_LIST_MAX ; idx++)
		init_wynet_frontend_list(&wynet_frontend_config.list[idx]);

	trace_verbose("Init wynet frontend\n");
	wynet_frontend_config.netfilter_ops.hook     = wynet_frontend;
	wynet_frontend_config.netfilter_ops.pf       = PF_INET;
	wynet_frontend_config.netfilter_ops.hooknum  = NF_IP_LOCAL_IN;
	wynet_frontend_config.netfilter_ops.priority = NF_IP_PRI_FIRST;

	return 0;
}

static void __exit nf_wynet_frontend_exit(void) {
	int idx;
	trace_info("Unload wynet frontend\n");

	for (idx = 0 ; idx < WYNET_FRONTEND_LIST_MAX ; idx++) {
		flush_workqueue(wynet_frontend_config.list[idx].inject_wq);
		destroy_workqueue(wynet_frontend_config.list[idx].inject_wq);
#ifdef ENABLE_PUREPIXEL
		struct list_head* pos = NULL;
		struct list_head* q = NULL;

		list_for_each_safe(pos, q, &(wynet_frontend_config.list[idx].missing_pkt_list)) {
			list_del(pos);
		}
#endif /* ENABLE_PUREPIXEL */

	}

	wynet_frontend_flush_queue(idx);
}

module_init(nf_wynet_frontend_init);
module_exit(nf_wynet_frontend_exit);


/* --------------------------------------------------------------------------
 * INTERNAL METHODS
 * -------------------------------------------------------------------------- */
static int wynet_frontend_is_enabled(int queue_idx)
{
	if ((queue_idx < 0)
	    || (queue_idx >= WYNET_FRONTEND_LIST_MAX))
		return 0;

	return wynet_frontend_config.list[queue_idx].is_enable;
}

static int rtp_enqueue(struct nf_wynet_frontend_config *config,
			    struct nf_wynet_frontend_list *nwf_list,
			    int queue_idx,
			    struct sk_buff *skb_current);

static inline void add_to_rtp_skb_list(struct nf_wynet_frontend_config *config,
			       struct nf_wynet_frontend_list *nwf_list,
			       struct sk_buff * skbuff, int idx)
{
	skbuff = skb_get(skbuff);
	/* Make sure no one will request this sk_buff anymore */
	skb_orphan(skbuff);

#ifdef ENABLE_PROFILING
	if (nwf_list->first == 2) {
		trace_info("PROFILING: Q[%d]: PUTQ: %ums\n", idx, jiffies_to_msecs(jiffies));
		nwf_list->first--;
	}
#endif

	rtp_enqueue(config, nwf_list, idx, skbuff);

	if (skb_queue_len(nwf_list->skb_list) < nwf_list->fifo_size)
		return;

	queue_work(nwf_list->inject_wq, &wynet_frontend_config.work_inject_rtp);
}

static void compute_fifo_size(struct nf_wynet_frontend_list *nwf_list)
{
	nwf_list->received_packets += 1;

	if ((jiffies_to_msecs(jiffies)  - jiffies_to_msecs(nwf_list->last_jiffies)) < FIFO_DURATION)
		return;

	/* fifo len is the number of recevied packet during FIFO_DURATION */
	nwf_list->fifo_size = nwf_list->received_packets;

	/* if fifo_size is too low keep it to something sane */
	if (nwf_list->fifo_size < MINIMUM_FIFO_SIZE)
		nwf_list->fifo_size =  MINIMUM_FIFO_SIZE;

	/* compute number of packet that must be injected at once */
	nwf_list->inject_at_once_size 	= nwf_list->fifo_size / FIFO_INJECT_RATIO;
	nwf_list->last_jiffies 		= jiffies;

	if (nwf_list->inject_at_once_size >= MAX_SWTS_PAGES)
		nwf_list->inject_at_once_size = MAX_SWTS_PAGES - 1;

/*
	trace_info("%s(): received_packets=%i fifo_size=%i inject_at_once_size=%i\n", __func__,
			nwf_list->received_packets,
			nwf_list->fifo_size,
			nwf_list->inject_at_once_size);
*/

	nwf_list->received_packets 	= 0;
}

static void check_fifo_size_and_inject( struct nf_wynet_frontend_config *config,
					int queue_idx,
					struct sk_buff_head *skb_list,
					dequeue_packet_function *dequeue_packet_fun)
{
	unsigned long 			flags;
	int 				packet_idx;
	struct nf_wynet_frontend_list 	*nwf_list;

	struct scatterlist 		*sg;
	struct sk_buff_head   		sg_skb_list;

	nwf_list = &config->list[queue_idx];

	if (!nwf_list->is_enable)
		return;

	spin_lock_irqsave(&skb_list->lock, flags);

	if (skb_queue_len(skb_list) < nwf_list->fifo_size) {
		spin_unlock_irqrestore(&skb_list->lock, flags);
		return;
	}

	skb_queue_head_init(&sg_skb_list);
	sg = (struct scatterlist *) kmalloc(sizeof(struct scatterlist) * MAX_SWTS_PAGES, GFP_ATOMIC);

	while (skb_queue_len(skb_list) > nwf_list->fifo_size)
		for (packet_idx = 0; packet_idx < nwf_list->inject_at_once_size; packet_idx++)
			dequeue_packet_fun(nwf_list, queue_idx, sg, &sg_skb_list);

	spin_unlock_irqrestore(&skb_list->lock, flags);

	if (skb_queue_len(&sg_skb_list)) {
		stfe_write_scatterlist( stfe_get_handle(WYNET_LINUX_DVB_ADAPTER, queue_idx),
					&sg[0], skb_queue_len(&sg_skb_list));
		skb_queue_purge(&sg_skb_list);
	}

	kfree(sg);
}

static void add_to_scatterlist(struct sk_buff *skb, char *start,
			size_t len, struct scatterlist *sg,
			struct sk_buff_head *sg_skb_list)
{
	int index = skb_queue_len(sg_skb_list);
	sg_set_buf(&sg[index], start, len);
	skb_queue_head(sg_skb_list, skb);
}

static void dequeue_udp_packet(struct nf_wynet_frontend_list *nwf_list, int queue_idx,
			       struct scatterlist *sg, struct sk_buff_head *sg_skb_list)
{
	int     l5off;
	struct  sk_buff *skb;

	skb = __skb_dequeue(nwf_list->udp_skb_list);
	if (!skb)
		return;

	l5off = wynet_frontend_get_l5_hdr_offset(skb);

	/* scatterlist full => skip */
	if (skb_queue_len(sg_skb_list) >= MAX_SWTS_PAGES)
		return;

	add_to_scatterlist(skb, skb->data + l5off, skb->len - l5off, sg, sg_skb_list);

	nwf_list->stat.pkt_injected++;
}

static void inject_udp_handler(struct work_struct * work) {
	struct nf_wynet_frontend_config* config;
	int queue_idx;
	
	config = container_of(work, struct nf_wynet_frontend_config, work_inject_udp);

	for (queue_idx = 0 ; queue_idx < WYNET_FRONTEND_LIST_MAX ; queue_idx++)
		check_fifo_size_and_inject(config, queue_idx,
					   config->list[queue_idx].udp_skb_list,
					   dequeue_udp_packet);
}

static void add_to_udp_skb_list(struct nf_wynet_frontend_list *nwf_list, struct sk_buff *skb)
{
	struct  sk_buff_head *skb_list;

	skb_list = nwf_list->udp_skb_list;

	skb = skb_get(skb);
	skb_orphan(skb);
	skb_queue_tail(skb_list, skb);

	nwf_list->stat.pkt_recv++;
	compute_fifo_size(nwf_list);

	if (skb_queue_len(skb_list) < nwf_list->fifo_size)
		return;

	queue_work(nwf_list->inject_wq, &wynet_frontend_config.work_inject_udp);
}

unsigned int wynet_frontend(unsigned int             hooknum,
                            struct sk_buff**         skb,
                            const struct net_device* in,
                            const struct net_device* out,
                            int (*okfn)(struct sk_buff*))
{
	struct nf_wynet_frontend_list *nwf_list;
	struct sk_buff * skbuff = *skb;
	int idx;

	if (!(skbuff))
		return NF_ACCEPT;

	if (!(skb_network_header(skbuff)) && !(ip_hdr(skbuff)))
		return NF_ACCEPT;

	for (idx = 0 ; idx < WYNET_FRONTEND_LIST_MAX ; idx++) {
		if (!wynet_frontend_is_enabled(idx))
			continue;
			
		nwf_list = &wynet_frontend_config.list[idx];

		switch (wynet_frontend_match(&wynet_frontend_config, skbuff, idx)) {
		case WYNET_FRONTEND_PATTERN_MATCH_UNICAST:
		case WYNET_FRONTEND_PATTERN_MATCH_MULTICAST_RTP:
		{
			add_to_rtp_skb_list(&wynet_frontend_config, nwf_list, skbuff, idx);
			return NF_DROP;
		}
		case WYNET_FRONTEND_PATTERN_MATCH_MULTICAST_UDP:
		{
			add_to_udp_skb_list(nwf_list, skbuff);
			return NF_DROP;
		}
		case WYNET_FRONTEND_PATTERN_MATCH_NONE:
		default:
		break;
		}
	}

	return NF_ACCEPT;
}

static int is_skb_ts_in_udp(struct sk_buff *skb)
{
	int offset = wynet_frontend_get_l5_hdr_offset(skb);

	/* check size */
	if (skb->len <= (offset + 376))
		return 0;

	/* is ts embeded in udp */
	if (skb->data[offset] == 0x47 &&
		skb->data[offset+188] == 0x47 &&
			skb->data[offset+376] == 0x47)
		return 1;

	return 0;
}

static int is_skb_ts_in_rtp(struct sk_buff *skb)
{
	int offset = wynet_frontend_get_l5_hdr_offset(skb);
	char *payload;

	if (skb->len < 1328 || is_skb_ts_in_udp(skb))
		return 0;

	/* filter out serpe packet */
	payload = RTP_GET_PAYLOAD(skb->data + offset);
	if (payload[0] != 0x47 &&
		payload[188] != 0x47 &&
			payload[376] != 0x47)
		return 0;

	return IS_RTP_PROTOCOL(RTP_HDR_GET_VERSION(skb->data + offset));
}

static inline int is_pattern_multicast(struct wynet_frontend_pattern *pattern)
{
	return pattern->type == IS_MULTICAST;
}

static inline int is_pattern_unicast(struct wynet_frontend_pattern *pattern)
{
	return pattern->type == IS_UNICAST;
}

static inline int packet_match_multicast_pattern(struct sk_buff *skb, struct wynet_frontend_pattern *pattern, int against_rtp)
{
	int 	nhoff;
	struct 	iphdr _iph, * iph;
	struct 	udphdr _udp, *udp;
	struct wynet_frontend_pattern_multicast * m = NULL;
	int 	does_protocol_match = 0;

	m = &(pattern->p.multicast);

	nhoff = skb_network_offset(skb);
	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (iph == NULL)
		return 0;

	if (iph->protocol != m->protocol)
		return 0;
		
	udp = skb_header_pointer(skb, nhoff + (iph->ihl << 2), sizeof(struct udphdr), &_udp);
	if (udp == NULL)
		return 0;
	
	if (against_rtp)
		does_protocol_match = is_skb_ts_in_rtp(skb);
	else
		does_protocol_match = is_skb_ts_in_udp(skb);


	if (iph->daddr == m->daddr && 
		udp->dest == m->dport &&
			does_protocol_match)
				return 1;

	return 0;
}

static inline int packet_match_unicast_pattern(struct sk_buff *skb, struct wynet_frontend_pattern *pattern)
{
	int 	must_test;
	int 	nhoff;
	struct 	iphdr _iph, * iph;
	struct 	udphdr _udp, *udp;
	struct wynet_frontend_pattern_unicast * u = NULL;

	u = &(pattern->p.unicast);

	nhoff = skb_network_offset(skb);
	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (iph == NULL)
		return 0;

	must_test = 0;
	if (u->saddr == iph->saddr &&
	    	u->daddr == iph->daddr &&
			iph->protocol == u->protocol)
				must_test = 1;

	/* do not test further */
	if (!must_test)
		return 0;

	udp = skb_header_pointer(skb, nhoff + (iph->ihl << 2), sizeof(struct udphdr), &_udp);
	
	if ((u->sport == 0 || udp->source == u->sport) &&
		udp->dest == u->dport &&
			is_skb_ts_in_rtp(skb))
				return 1;

	return 0;
}

static inline int is_skb_multicast(struct sk_buff * skb)
{
	struct iphdr _iph, * iph;
	int nhoff;

	nhoff = skb_network_offset(skb);
	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
	if (iph == NULL)
		return 0;

	if (IN_MULTICAST(ntohl(iph->daddr)))
		return 1;

	return 0;
}

static
enum wynet_frontend_pattern_match wynet_frontend_match(struct nf_wynet_frontend_config * config,
                                                       struct sk_buff * skb,
                                                       int queue_idx)
{
	struct nf_wynet_frontend_list *nwf_list;
	int skb_is_multicast = 0;
	int pattern_idx;

	/* If the hook is not enabled, do nothing */
	if (!wynet_frontend_is_enabled(queue_idx))
		return WYNET_FRONTEND_PATTERN_MATCH_NONE;

	nwf_list = &config->list[queue_idx];

	skb_is_multicast = is_skb_multicast(skb);
	
	/*
	 * Check the pattern corresponding to the type of destination address.
	 */
	for (pattern_idx = 0 ; pattern_idx < WYNET_FRONTEND_PATTERN_MAX; pattern_idx++) {
		struct wynet_frontend_filter 		*filter;
		struct wynet_frontend_pattern 	*pattern;

		filter = &nwf_list->filter[pattern_idx];
		pattern = &filter->pattern;

		if (!filter->is_enable)
			continue;

		/* RTP multicast */
		if (skb_is_multicast &&
		    	is_pattern_multicast(pattern) &&
				packet_match_multicast_pattern(skb, pattern, 1))
					return WYNET_FRONTEND_PATTERN_MATCH_MULTICAST_RTP;
		/* UDP multicast */
		else if (skb_is_multicast &&
				is_pattern_multicast(pattern) &&
					packet_match_multicast_pattern(skb, pattern, 0))
						return WYNET_FRONTEND_PATTERN_MATCH_MULTICAST_UDP;

		else if (!skb_is_multicast &&
				is_pattern_unicast(pattern) &&
					packet_match_unicast_pattern(skb, pattern))
						return WYNET_FRONTEND_PATTERN_MATCH_UNICAST;
	}

	return WYNET_FRONTEND_PATTERN_MATCH_NONE;
}

static struct sk_buff * get_tail_skb_or_queue(struct sk_buff_head *skb_list,
					      struct sk_buff *skb_current)
{
	struct sk_buff *skb;

	skb = skb_peek_tail(skb_list);

	/* got skb from tail */
	if (skb)
		return skb;
		
	/* got no skb => add current skb to tail */
	__skb_queue_head(skb_list, skb_current);
	return NULL;
}

static struct sk_buff * walk_backward_to_first_skb_with_same_ssrc(struct sk_buff_head *skb_list,
							 struct sk_buff *skb_current,
							 struct sk_buff *skb)
{
	int l5off;
	int l5off_current;
	u32 ssrc_current;

	l5off     	= wynet_frontend_get_l5_hdr_offset(skb);
	l5off_current  	= wynet_frontend_get_l5_hdr_offset(skb_current);
	ssrc_current 	= RTP_HDR_GET_SSRC(skb_current->data + l5off_current);

	/* while ssrc not equal */
	while (ssrc_current != RTP_HDR_GET_SSRC(skb->data + l5off)) {
		/* no skb with same ssrc => return the head */
		if (skb_queue_is_first(skb_list, skb))
			return skb;

		skb   = skb->prev;
		l5off = wynet_frontend_get_l5_hdr_offset(skb);
	}

	return skb;
}

static void warn_ssrc_change(u32 ssrc_current, u32 warn_last_injected_ssrc)
{
	trace_info("%s(): PKT: IN: SSRC: 0x%08x becomes 0x%08x\n", 
		    __func__,
		    warn_last_injected_ssrc,
		    ssrc_current);
}

static void rtp_queue_skb(struct nf_wynet_frontend_config * config, int queue_idx, struct sk_buff * skb_current)
{
	struct nf_wynet_frontend_list 	*nwf_list;
	struct sk_buff_head 		*skb_list;

	struct sk_buff* skb         = NULL;
	u32 timestamp, timestamp_current;
	u16 seq, seq_current;
	u32 ssrc_current;
	int l5off_current;
	int l5off;

	/* used to warn when ssrc changes */
	int do_warn_ssrc = 0;
	u32 warn_current_ssrc = 0;
	u32 warn_last_injected_ssrc = 0;

	nwf_list = &config->list[queue_idx];
	skb_list = nwf_list->skb_list;

	l5off_current = wynet_frontend_get_l5_hdr_offset(skb_current);
	timestamp_current = RTP_HDR_GET_TIMESTAMP(skb_current->data + l5off_current);
	ssrc_current = RTP_HDR_GET_SSRC(skb_current->data + l5off_current);
	seq_current = RTP_HDR_GET_SEQNUMBER(skb_current->data + l5off_current);

 	skb = get_tail_skb_or_queue(skb_list, skb_current);
 	if (!skb) {
		return;
	}

	l5off     = wynet_frontend_get_l5_hdr_offset(skb);
 
 	/* current packet has the same ssrc than the last packet injected in the pti
 	 * walk backward the queue until a packet with the same ssrc is found in order
 	 * to insert the current packet in the right position */
 	if (ssrc_current == nwf_list->ssrc)
 		skb = walk_backward_to_first_skb_with_same_ssrc(skb_list, skb_current, skb);
 	else {
 		/* ssrc changed => prepare to debug printk when the spinlock
 		 * will be released */
 		do_warn_ssrc = 1;
 		warn_current_ssrc = ssrc_current;
 		warn_last_injected_ssrc = nwf_list->ssrc;
 	}

	/* walk backward in a same ssrc packet sequence and find the previous packet 
	 * by its timestamp */
	do {
		l5off     = wynet_frontend_get_l5_hdr_offset(skb);
		timestamp = RTP_HDR_GET_TIMESTAMP(skb->data + l5off);
		seq = RTP_HDR_GET_SEQNUMBER(skb->data + l5off);

		/* if we are on the border of two ssrc sequence stop walking here */
		if (ssrc_current != RTP_HDR_GET_SSRC(skb->data + l5off))
			break;

		/* Duplicate packet, drop it */
		if (seq == seq_current) {
			kfree_skb(skb_current);
			return;
		}

		if (RTP_TIMESTAMP_IS_NEWER_THAN(timestamp, timestamp_current) &&
		   (timestamp != timestamp_current || (seq_current == (seq + 1) % 65536)))
		    	break;
		
		/* iterate backward until head is reached */
		if (!skb_queue_is_first(skb_list, skb))
			skb = skb->prev;
		else {
			kfree_skb(skb_current);
			return;
		}
	} while (skb);

	if (skb)
		__skb_append(skb, skb_current, skb_list);
	else
		__skb_queue_head(skb_list, skb_current);

	/* late ssrc changed warning outside of the spinlock */
	if (do_warn_ssrc)
		warn_ssrc_change(warn_current_ssrc, warn_last_injected_ssrc);

	return;
}

int is_nwf_list_locked(struct nf_wynet_frontend_list *nwf_list)
{
	/* not locked/flushing */
	if (!nwf_list->lock)
		return 0;
	
	/* locked/flushing */
	trace_warning("%s(): Stream FIFO is flushing... Discarding pkt!\n", __func__);
	return 1;
}

/* 
 * When a zap occurs, current queue pattern changes while 
 * packets from old channel, old pattern, may still 
 * exist in temporary FIFO. These packets' pattern doesn't
 * match that of the current TV channel but they still 
 * hold a valid queue index. inject_rtp_handler function 
 * checks queue index only which allows these remaining packets to 
 * be enqueued and jinx the player.
 */
static int is_skb_from_old_channel(struct nf_wynet_frontend_config *config,
			    struct sk_buff *skb_current,
			    int queue_idx)
{
	enum wynet_frontend_pattern_match result;

	result = wynet_frontend_match(config, skb_current, queue_idx);

	/* pattern match => good channel */
	if (result != WYNET_FRONTEND_PATTERN_MATCH_NONE)
		return 0;
	
	/* wrong channel */
	trace_debug("%s(): Packet from old channel. Discard it!\n", __func__);
	return 1;
}

void flush_receive_fifo_if_full(struct nf_wynet_frontend_list *nwf_list,
			 int queue_idx)
{
	/* Fifo is not full */
	if (skb_queue_len(nwf_list->skb_list) < FIFO_MAX_SIZE)
		return;

	/* Fifo is full */
	trace_warning("%s(): Not enough size in the queue..."
		      " Flushing stream FIFO\n", __func__);
	wynet_frontend_flush_queue(queue_idx);
}

static struct sk_buff* do_checks_before_enqueue(struct nf_wynet_frontend_config *config,
					 struct nf_wynet_frontend_list *nwf_list,
					 int queue_idx,
					 struct sk_buff *skb_current)
{
	flush_receive_fifo_if_full(nwf_list, queue_idx);

	if (is_skb_from_old_channel(config, skb_current, queue_idx))
		goto error_exit;

	if (is_nwf_list_locked(nwf_list))
		goto error_exit;

	return skb_current;

error_exit:
	kfree_skb(skb_current);
	return NULL;
}

static void do_rtp_enqueue(struct nf_wynet_frontend_config *config,
		      struct nf_wynet_frontend_list *nwf_list,
		      struct sk_buff* skb_current,
		      int queue_idx)
{
	unsigned long 		flags;
	struct sk_buff 		*skb;
	struct sk_buff_head 	*skb_list;

        skb_list = config->list[queue_idx].skb_list;
	spin_lock_irqsave(&skb_list->lock, flags);

	skb = skb_peek_tail(nwf_list->skb_list);
	if (skb)
		rtp_queue_skb(config, queue_idx, skb_current);
	else
		__skb_queue_head(skb_list, skb_current);

	spin_unlock_irqrestore(&skb_list->lock, flags);
}

static void update_purepixel_late_pkt_stats(struct nf_wynet_frontend_list *nwf_list,
				     struct iphdr * iph)
{
#ifdef ENABLE_PUREPIXEL
	if (IN_MULTICAST(ntohl(iph->daddr)))
		nwf_list->pp_info.lp_stat.late_pkts++;
	else
		nwf_list->pp_info.rp_stat.late_pkts++;
#endif
}

static void check_max_pkt_late_and_flush_if_needed(struct nf_wynet_frontend_list *nwf_list, int queue_idx)
{
	/* limit not reached */
	if (nwf_list->stat.pkt_late <= WYNET_FLUSH_LIMIT)
		return;
	
	/* limit reached flush */
	trace_warning("%s(): Flush queue: %d late packets\n",
		      __func__,
		      WYNET_FLUSH_LIMIT);
	wynet_frontend_flush_queue(queue_idx);
}

static void update_pkt_stats_and_drop( struct nf_wynet_frontend_list *nwf_list, int queue_idx,
				struct sk_buff *skb_current, u32 timestamp_current,
				u32 seq_nr_current, struct iphdr * iph)
{
	trace_info("%s(): PKT: IN: TIMESTAMP/SEQ: %08x/%d < PKT: INJECTED: TIMESTAMP/SEQ: 0x%08x/%d\n",
		    __func__,
		    timestamp_current,
		    seq_nr_current,
		    nwf_list->timestamp,
		    nwf_list->seq_nr);

	/* Update statistics */
	nwf_list->stat.pkt_late++;
	update_purepixel_late_pkt_stats(nwf_list, iph);
	check_max_pkt_late_and_flush_if_needed(nwf_list, queue_idx);

	/* Free the late packet skb */
	kfree_skb(skb_current);
}

static void change_ssrc_handler_if_queue_empty(struct nf_wynet_frontend_list *nwf_list,
 					int queue_idx, u32 ssrc_current,
					u32 timestamp_current, u32 seq_nr_current)
{
	/* queue not empty */
	if (skb_queue_len(nwf_list->skb_list))
		return;
		
	/* quueue empty */
	__wynet_frontend_ssrc_changed_handler(queue_idx, ssrc_current,
					      timestamp_current, seq_nr_current);
}
/* rtp_timestamp wrap around often and srrc wrap around not so often
 * when srrc wrap around just after timestamp wrap this function reset the 
 * last injected in pti timestamp to zero to prevent packets drops */
static void handle_sequence_number_loop(struct nf_wynet_frontend_list *nwf_list,
				   u32 timestamp_current,
				   u32 seq_nr_current)
{
	if(seq_nr_current == 1 &&
		!RTP_TIMESTAMP_IS_NEWER_THAN(nwf_list->timestamp, timestamp_current)) {
			trace_info("%s(): sequence wrap reinit timestamp to 0\n", __func__);
			nwf_list->timestamp = 0;
	}
}

static int rtp_enqueue(struct nf_wynet_frontend_config *config,
			    struct nf_wynet_frontend_list *nwf_list,
			    int queue_idx,
			    struct sk_buff *skb_current)
 {
 	u16 seq_nr_current;
 	u32 timestamp_current;
 	u32 ssrc_current;

 	int l5off_current;
	struct iphdr  *iph = NULL;
	struct udphdr *uh = NULL;
 
	skb_current = do_checks_before_enqueue(config, nwf_list, queue_idx, skb_current);
	if(!skb_current)
		return 0;
 
	/* Get IP, UDP, and RTP headers */
	l5off_current = wynet_frontend_get_l5_hdr_offset(skb_current);
	seq_nr_current = RTP_HDR_GET_SEQNUMBER(skb_current->data + l5off_current);
	timestamp_current = RTP_HDR_GET_TIMESTAMP(skb_current->data + l5off_current);
	ssrc_current = RTP_HDR_GET_SSRC(skb_current->data + l5off_current);
 
	iph = (struct iphdr *)skb_current->data;
	uh = (struct udphdr *)skb_current->data + (iph->ihl<<2);
 
	/* Update statistics */
	nwf_list->stat.pkt_payload_size = skb_current->len - l5off_current -
					  RTP_GET_HDR_LENGTH(skb_current->data + l5off_current);

	change_ssrc_handler_if_queue_empty(nwf_list, queue_idx,
					   ssrc_current, timestamp_current,
					   seq_nr_current);

	trace_debug("%s(): PKT: IN: seq=%d, timestamp=%d\n", __func__, seq_nr_current, timestamp_current);
 
	handle_sequence_number_loop(nwf_list, timestamp_current, seq_nr_current);
 
	/* Determine if the current packet has to be enqueued
	 * Compare the timestamp of the current packet to enqueue with 
	 * the latest packet injected in the PTI:
	 **/
	if (RTP_TIMESTAMP_IS_NEWER_THAN(nwf_list->timestamp, timestamp_current))
		do_rtp_enqueue(config, nwf_list, skb_current, queue_idx);
	else
		update_pkt_stats_and_drop(nwf_list, queue_idx,
					  skb_current, timestamp_current,
					  ssrc_current, iph);
 

	/* Update statistics */
	nwf_list->stat.pkt_recv++;

	compute_fifo_size(nwf_list);

	/* must continue to process */
	return 1;
}

static void update_missing_pkt_stats(struct nf_wynet_frontend_list *nwf_list)
{
	nwf_list->stat.pkt_missing++;
#ifdef ENABLE_PUREPIXEL
	nwf_list->pp_info.lp_stat.missing_pkts++;
#endif
}

static void update_injected_pkt_stats(struct nf_wynet_frontend_list *nwf_list, int is_mcast)
{
	nwf_list->stat.pkt_injected++;
#ifdef ENABLE_PUREPIXEL
	if (is_mcast)
		nwf_list->pp_info.lp_stat.injected_pkts++;
	else
		nwf_list->pp_info.rp_stat.injected_pkts++;
#endif
}

static void profile_dequeue(struct nf_wynet_frontend_list *nwf_list, int queue_idx)
{
#ifdef ENABLE_PROFILING
	if (nwf_list->first == 1) {
		trace_info("PROFILING: Q[%d]: GETQ: %ums\n", queue_idx, jiffies_to_msecs(jiffies));
		nwf_list->first--;
	}
#endif
}

static void dequeue_rtp_packet( struct nf_wynet_frontend_list *nwf_list, int queue_idx,
				struct scatterlist *sg, struct sk_buff_head *sg_skb_list)
{
	struct sk_buff* skb;
	int l5off;
	u16 seq_nr;
	u32 timestamp;
	u32 ssrc;
	struct iphdr _iph, * iph;
	int nhoff;

	/* Get the first packet in the queue */
	skb = __skb_dequeue(nwf_list->skb_list);
	if (!skb)
		return;
		
	l5off = wynet_frontend_get_l5_hdr_offset(skb);
	seq_nr = RTP_HDR_GET_SEQNUMBER(skb->data + l5off);
	timestamp = RTP_HDR_GET_TIMESTAMP(skb->data + l5off);
	ssrc = RTP_HDR_GET_SSRC(skb->data + l5off);

	if (ssrc != nwf_list->ssrc)
		__wynet_frontend_ssrc_changed_handler(queue_idx, ssrc, timestamp, seq_nr);

	nhoff = skb_network_offset(skb);
	iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);

	trace_debug("%s(): DEQUEUE: Q[%d]: LIST: NET PKT: SEQ: [0x%08x] %d, %d/%d\n",
	    __func__,
	    queue_idx,
	    timestamp, seq_nr,
	    skb_queue_len(nwf_list->skb_list),
	    nwf_list->skb_list_size_max);
	trace_debug("%s(): DEQUEUE: LIST: NET PKT: INJECT: addr=0x%p,len=%d\n",
	    __func__,
	    skb->data + l5off,
	    skb->len - l5off - RTP_GET_HDR_LENGTH(skb->data + l5off));

	/* packets should be ordered and continuous : check it*/
	if (seq_nr != nwf_list->seq_nr + 1)
		update_missing_pkt_stats(nwf_list);

	/* scatterlist full => skip */
	if (skb_queue_len(sg_skb_list) >= MAX_SWTS_PAGES)
		return;

	/* Inject the data in the PTI */
	/* XXX: RTP_TIMESTAMP_IS_STRICTLY_NEWER_THAN() will be true even if the two timestamps are equal */
	if (seq_nr == (nwf_list->seq_nr + 1) % 65536 ||
	    (RTP_TIMESTAMP_IS_NEWER_THAN(nwf_list->timestamp, timestamp) && timestamp != nwf_list->timestamp))
		add_to_scatterlist( skb,
				    RTP_GET_PAYLOAD(skb->data + l5off),
				    skb->len - l5off - RTP_GET_HDR_LENGTH(skb->data + l5off),
				    sg, sg_skb_list);

	nwf_list->timestamp = timestamp;

	update_injected_pkt_stats(nwf_list, IN_MULTICAST(ntohl(iph->daddr)));

	/* Update the latest injected packet */
	nwf_list->seq_nr = seq_nr;

	profile_dequeue(nwf_list, queue_idx);
}

static void inject_rtp_handler(struct work_struct * work) {
	struct nf_wynet_frontend_config* config = container_of(work, struct nf_wynet_frontend_config, work_inject_rtp);

	int queue_idx;

	for (queue_idx = 0 ; queue_idx < WYNET_FRONTEND_LIST_MAX ; queue_idx++)
		check_fifo_size_and_inject(config, queue_idx,
					   config->list[queue_idx].skb_list,
					   dequeue_rtp_packet);
}

static int wynet_frontend_get_l5_hdr_offset(struct sk_buff * skb)
{
	int l5off = 0;
	struct iphdr * iph = NULL;
	struct udphdr * uh = NULL;

	/* Offset of RTP packet */
	if (skb != NULL) {
		iph = (struct iphdr*)skb->data;
		uh = (struct udphdr*)skb->data + (iph->ihl<<2);

		l5off = skb_network_offset(skb) + (iph->ihl<<2) + sizeof(*uh);
	}
        
	return l5off;
}

static void __wynet_frontend_ssrc_changed_handler(int queue_idx, u32 ssrc, u32 timestamp, u16 seq)
{
	wynet_frontend_config.list[queue_idx].ssrc      = ssrc;
	wynet_frontend_config.list[queue_idx].timestamp = timestamp - 1;
	wynet_frontend_config.list[queue_idx].seq_nr    = seq - 1;
}

/* --------------------------------------------------------------------------
 * EXTERNAL METHODS: USER API
 * -------------------------------------------------------------------------- */
#ifdef ENABLE_PUREPIXEL
void wynet_frontend_check_discontinuity(int queue_idx)
{
	struct sk_buff* skb = NULL;
	struct sk_buff* skb_top;
	u16 seq_nr_prev, seq_nr;
	int parsing_idx;
	int l5off;
	struct nf_rtp_missing_pkt * missing;
	unsigned int flags;
	int fifo_begin_skip_count;


	if (!skb_queue_len(wynet_frontend_config.list[queue_idx].skb_list)) {
		return;
	}

	/*
	 * Parse the queue up in order to find missing packets
	 *
	 */
	parsing_idx = 0;

	fifo_begin_skip_count = wynet_frontend_config.list[queue_idx].fifo_size / FIFO_INJECT_RATIO;

	spin_lock_irqsave(&(wynet_frontend_config.list[queue_idx].skb_list->lock), flags);

	skb = skb_peek(wynet_frontend_config.list[queue_idx].skb_list);
	if (skb == NULL) { /* list is empty */
		spin_unlock_irqrestore(&(wynet_frontend_config.list[queue_idx].skb_list->lock), flags);
		return;
	}

	skb_top = (struct sk_buff *)wynet_frontend_config.list[queue_idx].skb_list;

	/* Skip the really next packets to be processed */
	while ((skb != skb_top) && (parsing_idx++ < fifo_begin_skip_count))
		skb = skb->next;
		
	if (skb != skb_top && skb->prev == skb_top) /* move to next, if prev == top */
		skb = skb->next;

	if (skb == skb_top) { /* no more packets */
		spin_unlock_irqrestore(&(wynet_frontend_config.list[queue_idx].skb_list->lock), flags);
		return;
	}

	parsing_idx = 0;
	l5off = wynet_frontend_get_l5_hdr_offset(skb->prev);
	seq_nr_prev = RTP_HDR_GET_SEQNUMBER(skb->prev->data + l5off);

    while ((skb != skb_top)
           && (parsing_idx + fifo_begin_skip_count < skb_queue_len(wynet_frontend_config.list[queue_idx].skb_list))) {

        /* Get the next packet in queue */
        l5off = wynet_frontend_get_l5_hdr_offset(skb);
        seq_nr = RTP_HDR_GET_SEQNUMBER(skb->data + l5off);

        trace_debug("%s(): PP: PKT: INFO: %d -> %d\n", __func__, seq_nr_prev, seq_nr);

        /* Create list of missing packets between current and prev */
        if (seq_nr != seq_nr_prev + 1) {
            unsigned int missing_flags;

            missing = (struct nf_rtp_missing_pkt *)kzalloc(sizeof(struct nf_rtp_missing_pkt), GFP_ATOMIC);
            if (missing == NULL) {
                trace_info("%s(): PUREPIXEL: Not enough memory\n", __func__);
                break;
            }

            INIT_LIST_HEAD(&missing->list);

            missing->missing_pkt.range_start = seq_nr_prev + 1;
            missing->missing_pkt.range_stop  = seq_nr - 1;

            spin_lock_irqsave(&(wynet_frontend_config.list[queue_idx].missing_pkt_list_lock), missing_flags);
            list_add_tail(&(missing->list), &(wynet_frontend_config.list[queue_idx].missing_pkt_list));
            wynet_frontend_config.list[queue_idx].missing_pkt_list_size++;
            spin_unlock_irqrestore(&(wynet_frontend_config.list[queue_idx].missing_pkt_list_lock), missing_flags);

            trace_debug("%s(): PP: PKT: MISSING: %d -> %d\n", __func__, seq_nr_prev + 1, seq_nr - 1);
        }

        seq_nr_prev = seq_nr;
        skb = skb->next;
        parsing_idx++;
    }

    spin_unlock_irqrestore(&(wynet_frontend_config.list[queue_idx].skb_list->lock), flags);
}
#endif /* ENABLE_PUREPIXEL */

void wynet_frontend_enable()
{
	nf_register_hook(&(wynet_frontend_config.netfilter_ops));
}
EXPORT_SYMBOL(wynet_frontend_enable);

void wynet_frontend_disable()
{
	nf_unregister_hook(&(wynet_frontend_config.netfilter_ops));
}
EXPORT_SYMBOL(wynet_frontend_disable);

int wynet_frontend_enable_queue(int queue_idx)
{
	if (queue_idx < 0
		|| queue_idx >= WYNET_FRONTEND_LIST_MAX)
		return -EINVAL;

	wynet_frontend_config.list[queue_idx].is_enable = 1;

	return 0;
}
EXPORT_SYMBOL(wynet_frontend_enable_queue);

int wynet_frontend_disable_queue(int queue_idx)
{
	if (queue_idx < 0
		|| queue_idx >= WYNET_FRONTEND_LIST_MAX) {
		trace_warning("%s(): Q[%d]: Out of range\n", __func__, queue_idx);

		return -EINVAL;
	}

	wynet_frontend_config.list[queue_idx].is_enable = 0;

	return 0;
}
EXPORT_SYMBOL(wynet_frontend_disable_queue);

int wynet_frontend_register_pattern(int queue_idx, struct wynet_frontend_pattern * pattern)
{
	int pattern_idx = -1;

	if (queue_idx < 0 || queue_idx >= WYNET_FRONTEND_LIST_MAX) {
		trace_warning("%s(): Q[%d]: Out of range\n", __func__, queue_idx);
			
		return -EINVAL;
	}
	pattern_idx = 0;
	while ((pattern_idx < WYNET_FRONTEND_PATTERN_MAX)
	       && (wynet_frontend_config.list[queue_idx].filter[pattern_idx].is_enable == 1)) {
		pattern_idx++;
	}
	
	if (pattern_idx < WYNET_FRONTEND_PATTERN_MAX) {
		memcpy(&(wynet_frontend_config.list[queue_idx].filter[pattern_idx].pattern), pattern, sizeof(struct wynet_frontend_pattern));
		wynet_frontend_config.list[queue_idx].filter[pattern_idx].is_enable = 1;

	trace_info("Register pattern: queue_idx=%i pattern_idx=%i\n",
		   queue_idx, pattern_idx);

#ifdef ENABLE_PUREPIXEL
        if (pattern->type == IS_MULTICAST) {
            wynet_frontend_config.list[queue_idx].pp_info.channel_addr = pattern->p.multicast.daddr;
            wynet_frontend_config.list[queue_idx].pp_info.channel_port = pattern->p.multicast.dport;
        }
#endif /* ENABLE_PUREPIXEL */
	} else {
		pattern_idx = -EINVAL;
	}

	wynet_frontend_flush_queue(queue_idx);

	return pattern_idx;
}
EXPORT_SYMBOL(wynet_frontend_register_pattern);

int wynet_frontend_unregister_pattern(int queue_idx, int pattern_idx)
{
	trace_info("Unregister pattern: queue_idx=%i pattern_idx=%i\n",
		   queue_idx, pattern_idx);

	if (queue_idx < 0 || queue_idx >= WYNET_FRONTEND_LIST_MAX) {
		trace_warning("%s(): Out of range: queue_idx\n", __func__);

		return -EINVAL;
	}
	if (pattern_idx < 0 || pattern_idx >= WYNET_FRONTEND_PATTERN_MAX) {
		trace_warning("%s(): Out of range: pattern_idx\n", __func__);

		return -EINVAL;
	}
	wynet_frontend_config.list[queue_idx].filter[pattern_idx].is_enable = 0;

	wynet_frontend_flush_queue(queue_idx);

	wynet_frontend_config.list[queue_idx].received_packets  	= 0;
	wynet_frontend_config.list[queue_idx].fifo_size  		= INITIAL_FIFO_SIZE;
	wynet_frontend_config.list[queue_idx].inject_at_once_size 	= INITIAL_FIFO_SIZE / FIFO_INJECT_RATIO;

#ifdef ENABLE_PUREPIXEL
        if (wynet_frontend_config.list[queue_idx].filter[pattern_idx].pattern.type == IS_MULTICAST) {
            wynet_frontend_config.list[queue_idx].pp_info.channel_addr = 0;
            wynet_frontend_config.list[queue_idx].pp_info.channel_port = 0;
        }
#endif /* ENABLE_PUREPIXEL */

	return 0;
}
EXPORT_SYMBOL(wynet_frontend_unregister_pattern);

/**
 * @brief: Inject directly the buffer in the PTI
 * @param: queue_idx     [in] Index of the queue
 * @param: buffer        [in] Data to inject
 * @param: size          [in] Length of data
 * @return: number of bytes injected if OK, else -EINVAL if the given queue is invalid
 */
int wynet_frontend_inject(int queue_idx, const char __user * buffer, int size)
{
	trace_debug("%s(): INJECT: LIST: NET PKT: INJECT: addr=0x%p,len=%d\n",
				__func__,
				buffer,
				size);
	
	/* Inject the data in the PTI */
	while (stfe_write_user(stfe_get_handle(WYNET_LINUX_DVB_ADAPTER, queue_idx),
						   buffer,
						   size, 
						   0) != 0);

	return size;
}
EXPORT_SYMBOL(wynet_frontend_inject);


int wynet_frontend_set_size_max(int queue_idx, int size_max)
{
	if (queue_idx < 0 || queue_idx >= WYNET_FRONTEND_LIST_MAX) {
		trace_warning("%s(): Q[%d]: Out of range\n", __func__, queue_idx);

		return -EINVAL;
	}

	wynet_frontend_config.list[queue_idx].skb_list_size_max = size_max;

	return size_max;
}
EXPORT_SYMBOL(wynet_frontend_set_size_max);

int wynet_frontend_flush_queue(int queue_idx)
{
	int error = 0;

	if (queue_idx < 0 || queue_idx >= WYNET_FRONTEND_LIST_MAX) {
		trace_warning("%s(): Out of range: queue_idx\n", __func__);

		return -EINVAL;
	}

	if (wynet_frontend_config.list[queue_idx].lock == 0) {
		struct sk_buff *skb;
		unsigned int flags;

		spin_lock_irqsave(&wynet_frontend_config.list[queue_idx].skb_list->lock, flags);

		wynet_frontend_config.list[queue_idx].lock = 1;

		/* Purge remaining packets */
		while ((skb = __skb_dequeue(wynet_frontend_config.list[queue_idx].skb_list)) != NULL)
			kfree_skb(skb);

		/* Reset statistics */
		wynet_frontend_config.list[queue_idx].timestamp         = 0;
		wynet_frontend_config.list[queue_idx].ssrc              = 0;

#ifdef ENABLE_PROFILING
		wynet_frontend_config.list[queue_idx].first = 2;
#endif

		memset(&(wynet_frontend_config.list[queue_idx].stat), 0x00, sizeof(struct wynet_frontend_stat));

#ifdef ENABLE_PUREPIXEL
		wynet_frontend_config.list[queue_idx].pp_info.lp_stat.injected_pkts = 0;
		wynet_frontend_config.list[queue_idx].pp_info.lp_stat.missing_pkts  = 0;
		wynet_frontend_config.list[queue_idx].pp_info.lp_stat.late_pkts     = 0;

		wynet_frontend_config.list[queue_idx].pp_info.rp_stat.injected_pkts = 0;
		wynet_frontend_config.list[queue_idx].pp_info.rp_stat.missing_pkts  = 0;
		wynet_frontend_config.list[queue_idx].pp_info.rp_stat.late_pkts     = 0;
#endif /* ENABLE_PUREPIXEL */
		spin_unlock_irqrestore(&wynet_frontend_config.list[queue_idx].skb_list->lock, flags);

		wynet_frontend_config.list[queue_idx].lock = 0;
	}

	return error;
}
EXPORT_SYMBOL(wynet_frontend_flush_queue);

/**
 * @brief: Get statistics of the frontend use
 * @param: queue_idx       [in]     Index of the queue
 * @param: stat            [in/out] Statistic of frontend use
 */
int wynet_frontend_get_stat(int queue_idx, struct wynet_frontend_stat * stat)
{
	int error = 0;

	if (queue_idx < 0 || queue_idx >= WYNET_FRONTEND_LIST_MAX) {
		trace_warning("%s(): Out of range: queue_idx\n", __func__);

		return -EINVAL;
	}
	memcpy(stat, &(wynet_frontend_config.list[queue_idx].stat), sizeof(struct wynet_frontend_stat));
	stat->pkts = skb_queue_len(wynet_frontend_config.list[queue_idx].skb_list);

	/* Reset statistics */
	memset(&(wynet_frontend_config.list[queue_idx].stat), 0x00, sizeof(struct wynet_frontend_stat));

	return error;
}
EXPORT_SYMBOL(wynet_frontend_get_stat);

#ifdef ENABLE_PUREPIXEL
/**
 * @brief: Get pure pixel statistics of the frontend use
 * @param: queue_idx       [in]  Index of the queue
 * @param: pp_info         [out] Statistic of frontend use
 */
int wynet_frontend_get_purepixel_info(int queue_idx, struct purepixel_info * pp_info)
{
	int error = 0;

	if (queue_idx < 0 || queue_idx >= WYNET_FRONTEND_LIST_MAX) {
		trace_warning("%s(): Out of range: queue_idx\n", __func__);

		return -EINVAL;
	}
	memcpy(pp_info, &(wynet_frontend_config.list[queue_idx].pp_info), sizeof(struct purepixel_info));

    /* Reset purepixel info */
    wynet_frontend_config.list[queue_idx].pp_info.lp_stat.injected_pkts = 0;
    wynet_frontend_config.list[queue_idx].pp_info.lp_stat.missing_pkts  = 0;
    wynet_frontend_config.list[queue_idx].pp_info.lp_stat.late_pkts     = 0;
    
    wynet_frontend_config.list[queue_idx].pp_info.rp_stat.injected_pkts = 0;
    wynet_frontend_config.list[queue_idx].pp_info.rp_stat.missing_pkts  = 0;
    wynet_frontend_config.list[queue_idx].pp_info.rp_stat.late_pkts     = 0;
    
	return error;
}
EXPORT_SYMBOL(wynet_frontend_get_purepixel_info);
#endif /* ENABLE_PUREPIXEL */

/**
 * @brief: Set the number of packet to send to player in case a discontinuity is detected
 * @param: queue_idx       [in] Index of the queue
 * @param: pkts            [in] Number of TS packets in a RTP packet
 */
int wynet_frontend_set_ts_pkts_per_net_pkt(int queue_idx, int pkts)
{
	int error = 0;

	if (queue_idx < 0 || queue_idx >= WYNET_FRONTEND_LIST_MAX) {
		trace_warning("%s(): Out of range: queue_idx\n", __func__);

		return -EINVAL;
	}

	if (pkts <= 0)
		error = -1;
	else
		wynet_frontend_config.list[queue_idx].ts_pkts_per_net_pkt = pkts;

	return error;
}
EXPORT_SYMBOL(wynet_frontend_set_ts_pkts_per_net_pkt);

ssize_t wynet_frontend_read(int queue_idx, char __user * buffer, size_t buffer_len, loff_t * offset) {
    int idx = 0;

#ifdef ENABLE_PUREPIXEL
    unsigned int flags;
    struct nf_rtp_missing_pkt * nf_missing_pkt = NULL;
    
    wynet_frontend_check_discontinuity(queue_idx);

    if (wynet_frontend_config.list[queue_idx].missing_pkt_list_size <= 0) return 0;

    while ((idx < buffer_len) && (idx < wynet_frontend_config.list[queue_idx].missing_pkt_list_size)) {
        spin_lock_irqsave(&(wynet_frontend_config.list[queue_idx].missing_pkt_list_lock), flags);
        nf_missing_pkt = list_first_entry(&(wynet_frontend_config.list[queue_idx].missing_pkt_list),
                                          struct nf_rtp_missing_pkt,
                                          list);
        if (nf_missing_pkt == NULL) {
            spin_unlock_irqrestore(&(wynet_frontend_config.list[queue_idx].missing_pkt_list_lock), flags);
            break;
        }

        list_del(&(nf_missing_pkt->list));
        wynet_frontend_config.list[queue_idx].missing_pkt_list_size--;
        spin_unlock_irqrestore(&(wynet_frontend_config.list[queue_idx].missing_pkt_list_lock), flags);

        memcpy(buffer + (idx * sizeof(struct rtp_missing_pkt)), 
               &(nf_missing_pkt->missing_pkt),
               sizeof(struct rtp_missing_pkt));

        if (nf_missing_pkt != NULL)
            kfree(nf_missing_pkt);

        idx++;
    }

#endif /* ENABLE_PUREPIXEL */

    return idx;
}
EXPORT_SYMBOL(wynet_frontend_read);


MODULE_DESCRIPTION("Wynet frontend core");
MODULE_AUTHOR("Laurent Fazio <lfazio@wyplay.com>");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.1");
