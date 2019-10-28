#ifndef EUNUCHS_H
#define EUNUCHS_H

#define DEBUG 1

#define debug(fmt, ...) \
    if(DEBUG) \
    { \
        printk("[eunuchs] [%s] " fmt, __func__, ##__VA_ARGS__); \
    }

extern int eunuchs_init(void);
extern void eunuchs_exit(void);
extern int eunuchs_hooks_install(void);
extern void eunuchs_hooks_remove(void);
extern void cr0_enable_write(void);
extern void cr0_disable_write(void);

#endif
