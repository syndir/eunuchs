#include <linux/build-salt.h>
#include <linux/module.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__attribute__((section(".gnu.linkonce.this_module"))) = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used
__attribute__((section("__versions"))) = {
	{ 0x48ff17dd, "module_layout" },
	{ 0xeebc73cb, "kern_path" },
	{ 0xdb7305a1, "__stack_chk_fail" },
	{ 0x6c2e3320, "strncmp" },
	{ 0x37a0cba, "kfree" },
	{ 0xe1537255, "__list_del_entry_valid" },
	{ 0x68f31cbd, "__list_add_valid" },
	{ 0xb6ed1e53, "strncpy" },
	{ 0x12da5bb2, "__kmalloc" },
	{ 0xd0d8621b, "strlen" },
	{ 0x4c452f97, "kmem_cache_alloc_trace" },
	{ 0x84520edb, "kmalloc_caches" },
	{ 0xd2387e80, "device_destroy" },
	{ 0x1161ac57, "class_destroy" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xb53c5755, "device_create" },
	{ 0x69faa559, "__class_create" },
	{ 0xdacc6fbc, "__register_chrdev" },
	{ 0x78e340f9, "__x86_indirect_thunk_ebx" },
	{ 0xe2d5255a, "strcmp" },
	{ 0xe445e0e7, "printk" },
	{ 0xe3460c96, "__x86_indirect_thunk_ecx" },
	{ 0xf7d9209, "__x86_indirect_thunk_eax" },
	{ 0xbdfb6dbb, "__fentry__" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "2BDE66739848FF5A2C3715F");
