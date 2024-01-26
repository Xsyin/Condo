#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

static int __init kernel_module_init(void)
{
    
    printk(KERN_ALERT"module insert!!");
    return 0;
}

static void __exit kernel_module_exit(void)
{
    printk(KERN_ALERT"module exit!!");

}


module_init(kernel_module_init);
module_exit(kernel_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("xsyin");
