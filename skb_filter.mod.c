#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x3758301, "mutex_unlock" },
	{ 0x8ce3169d, "netlink_kernel_create" },
	{ 0xea147363, "printk" },
	{ 0xd4defbf4, "netlink_kernel_release" },
	{ 0x779d7efc, "netlink_rcv_skb" },
	{ 0xb4390f9a, "mcount" },
	{ 0xfee8a795, "mutex_lock" },
	{ 0x1c740bd6, "init_net" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "FEE3A63861BA1D20F7347AD");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 5,
};
