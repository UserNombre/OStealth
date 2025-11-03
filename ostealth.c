#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

#define DEVICE_NAME "ostealth"
#define IOCTL_MAGIC 0x05
#define IOCTL_SET_TTL _IOW(IOCTL_MAGIC, 1, unsigned char)
#define IOCTL_GET_TTL _IOR(IOCTL_MAGIC, 2, unsigned char)

static struct nf_hook_ops hook_ops;
static unsigned char custom_ttl = 64;


/**
* Netfilter hook function that modifies all the outgoing IPv4 packets
* @priv: Optional private data passed to the hook (unused here)
* @skb:  Socket buffer representing the network packet (headers + payload)
* @state: Hook context (hook point, netns, in/out interfaces)
* Return: NF_ACCEPT to continue normal packet processing.
*/
static unsigned int ttl_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    if(skb)
    {
        struct iphdr *ip_header = ip_hdr(skb);
        ip_header->ttl = custom_ttl;
        ip_header->check = 0;
        ip_header->check = ip_fast_csum((unsigned char *)ip_header, ip_header->ihl);
        pr_info("Modified TTL of packet to %u\n", custom_ttl);
    }
    return NF_ACCEPT;
}

static long misc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch(cmd)
    {
        case IOCTL_SET_TTL:
            if(copy_from_user(&custom_ttl, (unsigned char __user *)arg, sizeof(custom_ttl)))
                return -EFAULT;
            return 0;
        case IOCTL_GET_TTL:
            if(copy_to_user((unsigned char __user *)arg, &custom_ttl, sizeof(custom_ttl)))
                return -EFAULT;
            return 0;
        default:
            return -ENOTTY;
    }
}

static const struct file_operations misc_ops =
{
    .owner = THIS_MODULE,
    .unlocked_ioctl = misc_ioctl,
};

static struct miscdevice misc_device =
{
    .minor = MISC_DYNAMIC_MINOR,
    .name = DEVICE_NAME,
    .fops = &misc_ops,
};

static int __init ostealth_init(void)
{
    // NetFilter hook configuration
    hook_ops.hook = ttl_hook;
    hook_ops.hooknum = NF_INET_POST_ROUTING;
    hook_ops.pf = PF_INET;
    hook_ops.priority = NF_IP_PRI_FIRST;
    // Hook registration
    if(nf_register_net_hook(&init_net, &hook_ops) < 0)
    {
        pr_err("OStealth hook registration failed\n");
        goto error;
    }
    // Device registration
    if(misc_register(&misc_device))
    {
        pr_err("Failed to register misc device\n");
        nf_unregister_net_hook(&init_net, &hook_ops);
        goto error;
    }

    pr_info("OStealth module loaded\n");
    return 0;

error:
    return -1;
}

static void __exit ostealth_exit(void)
{
    misc_deregister(&misc_device);
    nf_unregister_net_hook(&init_net, &hook_ops);
    pr_info("OStealth module unloaded\n");
}

module_init(ostealth_init);
module_exit(ostealth_exit);
