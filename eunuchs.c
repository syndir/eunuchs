/*
 * Targets Debian 10, x86-32bit
 * Kernel 4.19.0
 *
 * From https://www.kernel.org/doc/html/v4.15/admin-guide/kernel-signing.html
 * This module needs to be signed to avoid tainting the kernel.
 * To do so:
 *
 * openssl req -new -nodes -utf8 -sha256 -days 36500 -batch -x509 \
 *      -config x509.genkey -outform PEM -out kernel_key.pem \
 *      -keyout kernel_key.pem
 *
 * scripts/sign-file sha256 kernel-signkey.priv \
 *      kernel-signkey.x509 eunuchs.ko
 *
 * TODO: figure out how to import keys or be able to use a newly generated one
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/syscalls.h>

#include "eunuchs.h"

MODULE_AUTHOR("yes");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("yes");
MODULE_VERSION("1.0");
MODULE_ALIAS("yes");

/* This is the original value of CR0 */
unsigned original_cr0;

/*
 * 1. add `nokaslr` to /etc/default/grub in GRUB_CMDLINE_LINUX_DEFAULT
 * 2. execute `update-grub`
 * 3. `grep sys_call_table /boot/System.map-$(uname -r)` to
 *    find the address of the system call table
 */
static unsigned long *sct = 0xc167b180;

/* Pointers to save the original functions to. */
static typeof(sys_read) *orig_read;

asmlinkage long eunuchs_read(int fd, char __user *buf, size_t count)
{
    printk("reading..\n");
    return orig_read(fd, buf, count);
}

/* Twiddles CR0 to enable writing to read-only memory */
void cr0_enable_write()
{
    unsigned cr0 = 0;
    debug("disabling page write protection\n");
    asm volatile("movl %%cr0, %%eax"
                 :"=a"(cr0));
    original_cr0 = cr0;
    cr0 &= 0xfffeffff;
    asm volatile("movl %%eax, %%cr0"
                :
                :"a"(cr0));
}

/* Twiddles CR0 to disable writing to read-only memory */
void cr0_disable_write()
{
    debug("restoring write protection on cr0\n");
    asm volatile("movl %%eax, %%cr0"
                :
                :"a"(original_cr0));
}

/* Installs our hooks, saving the old system call function pointers */
int eunuchs_hooks_install()
{
    orig_read = (typeof(sys_read) *)sct[__NR_read];
    sct[__NR_read] = (void *)&eunuchs_read;

    return 0;
}

/* Removes our hooks, restoring the original system call function pointers */
void eunuchs_hooks_remove()
{
    sct[__NR_read] = (void *)orig_read;
}

/**
 * Initializes the LKM.
 **/
int eunuchs_init()
{
    debug("init\n");

    cr0_enable_write();
    eunuchs_hooks_install();
    cr0_disable_write();

    return 0;
}

/**
 * Unloads the LKM.
 **/
void eunuchs_exit()
{
    debug("exit\n");

    cr0_enable_write();
    eunuchs_hooks_remove();
    cr0_disable_write();
}

module_init(eunuchs_init);
module_exit(eunuchs_exit);
