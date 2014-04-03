#pragma once

#pragma pack (1)
typedef struct _ip_addr
{
   __u32   addr;  // WARNING ipv6 must be 128 bit
} ip_addr_t;

typedef struct filter_rule_base {
    ip_addr_t d_addr;
    ip_addr_t s_addr;

    __u16 proto;
    __u16 src_port;
    __u16 dst_port;
} filter_rule_base_t;

typedef struct trx_data{
    unsigned char	h_dest[ETH_ALEN];
    unsigned char	h_source[ETH_ALEN];
   filter_rule_base_t base_rule;
   __u8  off;	    
   __u32 id;	
} trx_data_t; 

#pragma pack ()

#define MSG_ADD_RULE (0x10 + 2)  // + 2 is arbitrary. same value for kern/usr
#define MSG_ALL_DONE (0x10 + 3)
#define MSG_RULE_ERR (0x10 + 4)
