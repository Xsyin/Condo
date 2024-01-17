#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "a3device"
#define DEVICE_PATH "/dev/a3device"
#define CLASS_NAME "a3module"

static int major_num;
static struct class * module_class = NULL;
static struct device * module_device = NULL;
static struct file * __file = NULL;
struct inode * __inode = NULL;

static ssize_t a3_module_read(struct file * __file, char __user * user_buf, size_t size, loff_t * __loff);

static struct file_operations a3_module_fo = 
{
    .owner = THIS_MODULE,
    .read = a3_module_read,
};

static int __init kernel_module_init(void)
{
    major_num = register_chrdev(0, DEVICE_NAME, &a3_module_fo);
    module_class = class_create(THIS_MODULE, CLASS_NAME);
    module_device = device_create(module_class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);
    __file = filp_open(DEVICE_PATH, O_RDONLY, 0);
    __inode = file_inode(__file);
    __inode->i_mode |= 0666;
    filp_close(__file, NULL);
    printk(KERN_ALERT"module insert!!");
    return 0;
}

static void __exit kernel_module_exit(void)
{
    device_destroy(module_class, MKDEV(major_num, 0));
    class_destroy(module_class);
    unregister_chrdev(major_num, DEVICE_NAME);
}

static ssize_t a3_module_read(struct file * __file, char __user * user_buf, size_t size, loff_t * __loff)
{
    char buf[0x10];
    int count;
    *((long long *)buf) = (long long *) &(current->cred->euid);

    count = copy_to_user(user_buf, buf, 8);

    return count;
}

module_init(kernel_module_init);
module_exit(kernel_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("arttnba3");
