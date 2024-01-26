#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/printk.h>

int init_module(void) {
    printk(KERN_INFO "Loading hello module\n");
    return 0;
}

void cleanup_module(void) {
    printk(KERN_INFO "Removing hello module\n");
}

int main() {
    /* 打开内核符号 */ 
    extern long init_module(void *, unsigned long, const char *);
    extern long cleanup_module(const char *);

    /* 动态加载hello模块 */
    init_module(NULL, 0, "hello");

    /* 卸载hello模块 */
    cleanup_module("hello");

    return 0;
} 
