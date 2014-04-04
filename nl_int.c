#include <linux/kernel.h>
#include <linux/module.h>
#include <net/sock.h>
#include <net/netlink.h>
#include "nl_int.h"
#include "base/hash_table.h"
#include "trx_data.h"


static struct sock *_nl_sock;

int find_rule(unsigned char* data);
void add_rule(struct filter_rule* fr);

DEFINE_MUTEX(nl_mutex);

static int
nl_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
    int type;
    unsigned char *data;

    type = nlh->nlmsg_type;

    switch (type)
    {
	case MSG_ADD_RULE:
	        data = NLMSG_DATA(nlh);
                if(find_rule((unsigned char*)&((filter_rule_t*)data)->base_rule)==0)
			printk("%s we have this rule ",__func__);
		else{
			printk("%s new rule added ",__func__);
			add_rule((filter_rule_t*)data);
		}
		printk("%s from netlink  TID %d index: %d src port: %d  dst_port: %d d_addr: %d s_addr: %d proto: %d\n",__func__,(int)current->pid,((filter_rule_t*)data)->id,((filter_rule_t*)data)->base_rule.src_port,((filter_rule_t*)data)->base_rule.dst_port,((filter_rule_t*)data)->base_rule.d_addr.addr,((filter_rule_t*)data)->base_rule.s_addr.addr,((filter_rule_t*)data)->base_rule.proto);
		break;
        case MSG_DELETE_RULE:
		break;
        case MSG_GET_RULES:
		break;
        case MSG_ALL_DONE:
		break;
	default:
		printk("%s: expect something else got %#x\n", __func__, type);
	        return -EINVAL;
    }

//    printk("%s: %02x %02x %02x %02x %02x %02x %02x %02x\n", __func__,
//            data[0], data[1], data[2], data[3],
//            data[4], data[5], data[6], data[7]);

//    printk("%s: %02x %02x \n", __func__,
//            *(unsigned int*)&data[0],
//            *(unsigned int*)&data[4]);

    return 0;
}

static void
nl_skb_rcv_msg(struct sk_buff *skb)
{
    mutex_lock(&nl_mutex);
    netlink_rcv_skb(skb, &nl_rcv_msg);
    mutex_unlock(&nl_mutex);
}

/*static*/ int
nl_init(void)
{
    _nl_sock = netlink_kernel_create(&init_net, NETLINK_USERSOCK, 0,
            nl_skb_rcv_msg, NULL, THIS_MODULE);
    if (!_nl_sock) {
        printk(KERN_ERR "%s: receive handler registration failed\n", __func__);
        return -ENOMEM;
    }

    return 0;
}

/*static*/ void
nl_exit(void)
{
    if (_nl_sock) {
        netlink_kernel_release(_nl_sock);
    }
}

void input (struct sock *sk, int len)
{
  wait_queue_head_t w;
  wake_up_interruptible(&w/*sk->sleep*/);
	wake_up_interruptible(sk->sk_sleep);
}

EXPORT_SYMBOL( nl_init );
EXPORT_SYMBOL( nl_exit );
