#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#undef __KERNEL__
#include <linux/netfilter_ipv4.h>
#define __KERNEL__
#include <linux/netfilter_bridge.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>  /* Necessary because we use the proc fs */
#include <linux/list.h>
#include <net/ip.h>
#include <asm/uaccess.h>	/* For copy_from_user  */
#include "nl_int.h"

struct nf_hook_ops nfho_in;   //net filter hook option struct
struct nf_hook_ops nfho_out;  //net filter hook option struct


#define skb_filter_name "skb_filter"

struct c_ip_addr
{
   __u32   ip_addr;  // Условный ип адрес ipv6 must be 128 bit
};

struct filter_rule {
    unsigned char	h_dest[ETH_ALEN];
    unsigned char	h_source[ETH_ALEN];
 
/// 
    struct c_ip_addr d_addr;
    struct c_ip_addr s_addr;

    __u16 proto;
    __u16 src_port;
    __u16 dst_port;
          
    __u8  off;
    struct list_head full_list; /* kernel's list structure */
    struct list_head protocol_list; /* kernel's list structure */
};
 
static struct filter_rule frList;
static struct filter_rule frList_udp;
static struct filter_rule frList_tcp;

static  void addRules(void)
{    
    struct filter_rule *a_new_fr, *a_rule; 
    int i;  
    uint8_t rb;

/* adding elements to mylist */
    for(i=0; i<20000; ++i){
	
	get_random_bytes ( &rb, sizeof (uint8_t) );
        a_new_fr = kmalloc(sizeof(*a_new_fr), GFP_KERNEL);
        a_new_fr->d_addr.ip_addr = 0;
        a_new_fr->s_addr.ip_addr = 0;
        a_new_fr->proto = rb<128?IPPROTO_UDP:IPPROTO_TCP;
        a_new_fr->src_port = 53 + i;
	a_new_fr->dst_port = 53 + i;
	a_new_fr->off = 0;
        //INIT_LIST_HEAD(&a_new_fr->full_list);
        /* add the new node to mylist */
        list_add(&(a_new_fr->full_list), &(frList.full_list));//list_add_tail(&(a_new_fr->list), &(frList.list));
	if(a_new_fr->proto == IPPROTO_UDP)
		list_add(&(a_new_fr->protocol_list), &(frList_udp.protocol_list));
	else if (a_new_fr->proto == IPPROTO_TCP)
		list_add(&(a_new_fr->protocol_list), &(frList_tcp.protocol_list));		
	
    }
     
    i =0;
    list_for_each_entry(a_rule, &frList.full_list, full_list) {
        //access the member from aPerson
        printk(KERN_INFO "#%d Src_addr: %X; dst_addr: %X; proto: %d; src_port: %d dst_port: %d\n", i++,a_rule->s_addr.ip_addr, a_rule->d_addr.ip_addr, a_rule->proto, a_rule->src_port, a_rule->dst_port);
    
     }

}

static void delRules(void)
{ 
    struct filter_rule *a_rule, *tmp;
    printk(KERN_INFO "kernel module unloaded.\n");
    printk(KERN_INFO "deleting the list using list_for_each_entry_safe()\n");
    
    list_for_each_entry_safe(a_rule, tmp, &frList_udp.protocol_list, protocol_list){
         list_del(&a_rule->protocol_list);
    }

    list_for_each_entry_safe(a_rule, tmp, &frList_tcp.protocol_list, protocol_list){
         list_del(&a_rule->protocol_list);
    }
   
    list_for_each_entry_safe(a_rule, tmp, &frList.full_list, full_list){
         // printk(KERN_INFO "freeing node %s\n", a_rule->name);
         list_del(&a_rule->full_list);
         kfree(a_rule);
    }
}

static struct proc_dir_entry *skb_filter;
 
static int filter_value = 0;
 
unsigned int hook_func(unsigned int hooknum, 
            struct sk_buff *skb, 
            const struct net_device *in, 
            const struct net_device *out, 
            int (*okfn)(struct sk_buff *))
{	
    struct sk_buff *sock_buff;
    struct udphdr *udp_header;      // UDP header struct
    struct iphdr *ip_header;        // IP header struct
    struct icmphdr *icmp_header;	// ICMP Header
    struct tcphdr *tcp_header;	// TCP Header
    struct ethhdr  *ethheader;      // Ethernet Header

    sock_buff = skb;	
 
    ethheader = (struct ethhdr*) skb_mac_header(sock_buff); 
    ip_header = (struct iphdr *) skb_network_header(sock_buff);
 
    if(!sock_buff || !ip_header || !ethheader)
        return NF_ACCEPT;



    if(ip_header->protocol == IPPROTO_UDP){
        udp_header = (struct udphdr *)(skb_transport_header(sock_buff) + ip_hdrlen(sock_buff));
        if(udp_header){
            //printk(KERN_INFO "SRC: (%u.%u.%u.%u):%d --> DST: (%u.%u.%u.%u):%d\n",NIPQUAD(ip_header->saddr),ntohs(udp_header->source),NIPQUAD(ip_header->daddr),ntohs(udp_header->dest));
	    struct filter_rule  *a_rule;
	    
	   list_for_each_entry(a_rule, &frList_udp.protocol_list, protocol_list) {
		// access the member from aPerson
		// printk(KERN_INFO "Ip_addr: %X; proto: %d; port: %d\n", a_rule->ia.ip_addr, a_rule->proto, a_rule->port);
		if((ntohs(udp_header->source) == a_rule->src_port || ntohs(udp_header->dest) == a_rule->dst_port) &&
		!a_rule->off){
			printk(KERN_INFO "SRC: (%u.%u.%u.%u):%d --> DST: (%u.%u.%u.%u):%d proto: %d; \n", NIPQUAD(ip_header->saddr),ntohs(udp_header->source),NIPQUAD(ip_header->daddr),ntohs(udp_header->dest), a_rule->proto);
			return NF_DROP;
		}
	    }

        }else
            return NF_DROP;
    } else  if(ip_header->protocol == IPPROTO_TCP){
        printk(KERN_INFO "---------- TCP -------------\n");
        tcp_header = (struct tcphdr *)(skb_transport_header(sock_buff) + ip_hdrlen(sock_buff));
        if(tcp_header){		
            //printk(KERN_INFO "SRC: (%u.%u.%u.%u) --> DST: (%u.%u.%u.%u)\n",NIPQUAD(ip_header->saddr),NIPQUAD(ip_header->daddr));
            //printk(KERN_INFO "ICMP type: %d - ICMP code: %d\n",icmp_header->type, icmp_header->code);
        }else
            return NF_DROP;	
    } else  if(ip_header->protocol == IPPROTO_ICMP){
        printk(KERN_INFO "---------- ICMP -------------\n");
        icmp_header = (struct icmphdr *)(skb_transport_header(sock_buff) + ip_hdrlen(sock_buff));
        if(icmp_header){		
	    // printk(KERN_INFO "SRC: (%pM) --> DST: (%pM)\n",ethheader->h_source,ethheader->h_dest);

            if(ethheader && !out) printk(KERN_INFO "SRC: (%pM) --> DST: (%pM)\n",ethheader->h_source,ethheader->h_dest); // WTH On postrouting we got freeze when try access hw address 
	    //if(ethheader->h_source) printk(KERN_INFO "SRC: (%pM) -->",ethheader->h_source);
	    //if(ethheader->h_dest) printk(KERN_INFO " DST: (%pM)\n",ethheader->h_dest); else printk(" \n");
            printk(KERN_INFO "SRC: (%u.%u.%u.%u) --> DST: (%u.%u.%u.%u)\n",NIPQUAD(ip_header->saddr),NIPQUAD(ip_header->daddr));
            printk(KERN_INFO "ICMP type: %d - ICMP code: %d  in %s  out %s \n",icmp_header->type, icmp_header->code,in!=NULL?"true":"false",out!=NULL?"true":"false");
        }else
            return NF_DROP;	
    }
 
    return filter_value == 0 ? NF_ACCEPT : NF_DROP;
}
 
int skb_read(char *page, char **start, off_t off,
            int count, int *eof, void *data)
{	
    int len;
 
    if(off > 0){
        *eof = 1;
        return 0;
    }
 
    if(count < sizeof(int)){
        *eof = 1;
        return -ENOSPC;
    }
 
    /* cpy to userspace */
    memcpy(page, &filter_value, sizeof(int));
    len = sizeof(int);
 
    return len;
}
 
int skb_write(struct file *file, const char *buffer, unsigned long len,
            void *data)
{
    unsigned char userData;
 
    if(len > PAGE_SIZE || len < 0){
        printk(KERN_INFO "SKB System: cannot allow space for data\n");
        return -ENOSPC;
    }
 
    /* write data to the buffer */
    if(copy_from_user(&userData, buffer, 1)){
        printk(KERN_INFO "SKB System: cannot copy data from userspace. OH NOES\n");
        return -EFAULT;
    }
 
    filter_value = simple_strtol(&userData, NULL, 10);
 
    return len;
}
 
int init_module()
{   

    struct proc_dir_entry proc_root;
    int ret = 0;
    
    // LIST_HEAD(frList);  // This macro leads to kernel panic on  list_add
    INIT_LIST_HEAD(&frList.full_list);	
    INIT_LIST_HEAD(&frList_udp.protocol_list);	
    INIT_LIST_HEAD(&frList_tcp.protocol_list);

    addRules();
	
    skb_filter = create_proc_entry( skb_filter_name, 0644, NULL);
 
    // If we cannot create the proc entry
    if(skb_filter == NULL){
        ret = -ENOMEM;
        if( skb_filter )
            remove_proc_entry( skb_filter_name, &proc_root);
 
        printk(KERN_INFO "SKB Filter: Could not allocate memory.\n");
        goto error;
 
    }else{		
        skb_filter->read_proc = skb_read;
        skb_filter->write_proc = skb_write;
        //skb_filter->owner = THIS_MODULE;	
    }	
 
    // Netfilter hook information, specify where and when we get the SKB
    nfho_out.hook = hook_func;
    // nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho_out.hooknum = NF_INET_POST_ROUTING;

    nfho_out.pf = PF_INET;
    nfho_out.priority = NF_IP_PRI_LAST;
    //nfho_out.priority = NF_IP_PRI_FIRST;
#if (LINUX_VERSION_CODE >= 0x020500)     nfho_out.owner = THIS_MODULE;
#endif

    nf_register_hook(&nfho_out);
 
    nfho_in.hook = hook_func;
    nfho_in.hooknum = NF_INET_PRE_ROUTING;
    // nfho.hooknum = NF_INET_POST_ROUTING;

    nfho_in.pf = PF_INET;
    //nfho.priority = NF_IP_PRI_LAST;
    nfho_in.priority = NF_IP_PRI_FIRST;
#if (LINUX_VERSION_CODE >= 0x020500)     nfho_in.owner = THIS_MODULE;
#endif
    nf_register_hook(&nfho_in);

    printk(KERN_INFO "Registering SK Parse Module\n");
    
    nl_init();

error:
    return ret;
}
 
void cleanup_module()
{
    nf_unregister_hook(&nfho_in);
    nf_unregister_hook(&nfho_out);

    if ( skb_filter )
        remove_proc_entry(skb_filter_name, NULL);
    
    nl_exit();
    
    delRules();

    printk(KERN_INFO "Unregistered the SK Parse Module\n");
}
 
MODULE_AUTHOR("Erik Schweigert");
MODULE_DESCRIPTION("SK Buff Parse Module");
MODULE_LICENSE("GPL");
