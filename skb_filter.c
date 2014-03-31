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
#include <linux/proc_fs.h>  /* Necessary because we use the proc fs */
#include <linux/list.h>
#include <net/ip.h>
#include <asm/uaccess.h>	/* For copy_from_user  */
#include "nl_int.h"

struct nf_hook_ops nfho;   //net filter hook option struct
struct sk_buff *sock_buff;
struct udphdr *udp_header;          // UDP header struct
struct iphdr *ip_header;            // IP header struct
struct icmphdr *icmp_header;		// ICMP Header
 
#define skb_filter_name "skb_filter"

struct c_ip_addr
{
   __u32   ip_addr;  // Условный ип адрес ipv6 must be 128 bit
};

struct filter_rule {
     
    struct c_ip_addr ia;
    __u16 proto;
    __u16 port;
    struct list_head list; /* kernel's list structure */
};
 
static struct filter_rule frList;

static struct proc_dir_entry *skb_filter;
 
static int filter_value = 0;
 
unsigned int hook_func(unsigned int hooknum, 
            struct sk_buff *skb, 
            const struct net_device *in, 
            const struct net_device *out, 
            int (*okfn)(struct sk_buff *))
{	
    sock_buff = skb;	
 
    ip_header = (struct iphdr *)skb_network_header(sock_buff);
 
    if(!sock_buff)
        return NF_ACCEPT;
 
    if(ip_header->protocol == IPPROTO_UDP){
        udp_header = (struct udphdr *)(skb_transport_header(sock_buff) + ip_hdrlen(sock_buff));
        if(udp_header)
            printk(KERN_INFO "SRC: (%u.%u.%u.%u):%d --> DST: (%u.%u.%u.%u):%d\n",NIPQUAD(ip_header->saddr),ntohs(udp_header->source),NIPQUAD(ip_header->daddr),ntohs(udp_header->dest));
        else
            return NF_DROP;
    }
 
    if(ip_header->protocol == IPPROTO_ICMP){
        printk(KERN_INFO "---------- ICMP -------------\n");
        icmp_header = (struct icmphdr *)(skb_transport_header(sock_buff) + ip_hdrlen(sock_buff));
        if(icmp_header){		
            printk(KERN_INFO "SRC: (%u.%u.%u.%u) --> DST: (%u.%u.%u.%u)\n",NIPQUAD(ip_header->saddr),NIPQUAD(ip_header->daddr));
            printk(KERN_INFO "ICMP type: %d - ICMP code: %d\n",icmp_header->type, icmp_header->code);
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
    struct filter_rule* a_new_fr;

    struct proc_dir_entry proc_root;
    int ret = 0;
    
    LIST_HEAD(frList);
	
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
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_LAST;
    nfho.owner = THIS_MODULE;

    nf_register_hook(&nfho);
 
    printk(KERN_INFO "Registering SK Parse Module\n");
    
    nl_init();

error:
    return ret;
}
 
void cleanup_module()
{
    nf_unregister_hook(&nfho);
 
    if ( skb_filter )
        remove_proc_entry(skb_filter_name, NULL);
    
    nl_exit();

    printk(KERN_INFO "Unregistered the SK Parse Module\n");
}
 
MODULE_AUTHOR("Erik Schweigert");
MODULE_DESCRIPTION("SK Buff Parse Module");
MODULE_LICENSE("GPL");
