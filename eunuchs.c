#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include "eunuchs.h"


int eunuchs_init()
{
    printk("init\n");
    return 0;
}

void eunuchs_exit()
{
    printk("exit\n");
}
module_init(eunuchs_init);
module_exit(eunuchs_exit);
