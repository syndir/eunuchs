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
	{ 0xd61f518f, "class_unregister" },
	{ 0xd2387e80, "device_destroy" },
	{ 0x1161ac57, "class_destroy" },
	{ 0x6bc3fbc0, "__unregister_chrdev" },
	{ 0xb53c5755, "device_create" },
	{ 0x69faa559, "__class_create" },
	{ 0xdacc6fbc, "__register_chrdev" },
	{ 0xe445e0e7, "printk" },
	{ 0xf7d9209, "__x86_indirect_thunk_eax" },
	{ 0xbdfb6dbb, "__fentry__" },
};

static const char __module_depends[]
__used
__attribute__((section(".modinfo"))) =
"depends=";


MODULE_INFO(srcversion, "11104AA585661F37A980723");
