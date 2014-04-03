#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);

struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
 .name = KBUILD_MODNAME,
 .init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
 .exit = cleanup_module,
#endif
 .arch = MODULE_ARCH_INIT,
};

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x14522340, "module_layout" },
	{ 0x4f1939c7, "per_cpu__current_task" },
	{ 0x79aa04a2, "get_random_bytes" },
	{ 0xd691cba2, "malloc_sizes" },
	{ 0xa367b551, "__rt_mutex_init" },
	{ 0x1a6d6e4f, "remove_proc_entry" },
	{ 0x3758301, "mutex_unlock" },
	{ 0xca975b7a, "nf_register_hook" },
	{ 0x343a1a8, "__list_add" },
	{ 0x8ce3169d, "netlink_kernel_create" },
	{ 0xea147363, "printk" },
	{ 0x2fa5a500, "memcmp" },
	{ 0xd4defbf4, "netlink_kernel_release" },
	{ 0x779d7efc, "netlink_rcv_skb" },
	{ 0xb4390f9a, "mcount" },
	{ 0xfee8a795, "mutex_lock" },
	{ 0x521445b, "list_del" },
	{ 0x1c740bd6, "init_net" },
	{ 0x6d6b15ff, "create_proc_entry" },
	{ 0x2044fa9e, "kmem_cache_alloc_trace" },
	{ 0x642e54ac, "__wake_up" },
	{ 0x7e5a6ea3, "nf_unregister_hook" },
	{ 0x37a0cba, "kfree" },
	{ 0xb742fd7, "simple_strtol" },
	{ 0x3302b500, "copy_from_user" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "934C202A22864135DF8F334");

static const struct rheldata _rheldata __used
__attribute__((section(".rheldata"))) = {
	.rhel_major = 6,
	.rhel_minor = 5,
};
