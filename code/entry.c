#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>
#include "comm.h"

// 内核配置选项（可通过编译参数控制）
#define CONFIG_STEALTH_MODE 1      // 启用高级隐身模式
#define CONFIG_INPUT_VALIDATION 1  // 启用输入验证
#define CONFIG_CACHE_OPTIMIZE 1    // 启用缓存优化

static DEFINE_MUTEX(drv_mutex);    // 全局互斥锁
static char stealth_name[16];      // 动态设备名
static struct {
    dev_t dev_t;
    struct cdev cdev;
    struct class *class;
    struct device *device;
    bool is_hidden;
    pid_t owner_pid;              // 只允许指定进程操作
} drv_context = {0};

// 高级输入验证
static bool validate_request(pid_t pid, uintptr_t addr, size_t size) {
    if (pid <= 0 || addr < PAGE_OFFSET || size == 0 || size > 16*1024*1024)
        return false;
    if (addr + size < addr) // 检查溢出
        return false;
    return true;
}

// 优化的内存读取（批量页表操作）
static bool read_process_memory_opt(pid_t pid, uintptr_t addr, void *buffer, size_t size) {
    struct pid *proc_pid;
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf;
    size_t total_read = 0;
    bool ret = false;

    if (!validate_request(pid, addr, size)) return false;

    proc_pid = find_get_pid(pid);
    if (!proc_pid) return false;
    
    task = get_pid_task(proc_pid, PIDTYPE_PID);
    put_pid(proc_pid);
    if (!task) return false;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) return false;

    kbuf = vmalloc(size); // 使用vmalloc支持大内存
    if (!kbuf) goto out_mm;

    down_read(&mm->mmap_sem);
    
    // 批量读取优化
    while (total_read < size) {
        size_t chunk = min(size - total_read, PAGE_SIZE * 16);
        int bytes = access_process_vm(task, addr + total_read, 
                                      kbuf + total_read, chunk, 0);
        if (bytes <= 0) break;
        total_read += bytes;
    }
    
    up_read(&mm->mmap_sem);

    if (total_read == size && copy_to_user(buffer, kbuf, size) == 0)
        ret = true;

    vfree(kbuf);
out_mm:
    mmput(mm);
    return ret;
}

// 优化的内存写入
static bool write_process_memory_opt(pid_t pid, uintptr_t addr, void *buffer, size_t size) {
    // 类似read_process_memory_opt实现，方向相反
    // 省略重复代码...
    return true; // 示意
}

// 动态生成隐蔽设备名
static void generate_stealth_name(void) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyz";
    int i;
    
    get_random_bytes(&i, sizeof(i));
    for (i = 0; i < 8; i++) {
        char c;
        get_random_bytes(&c, 1);
        stealth_name[i] = charset[c % (sizeof(charset)-1)];
    }
    stealth_name[i] = '\0';
}

// 增强的隐身模式
static void apply_stealth_mode(void) {
    #if CONFIG_STEALTH_MODE
    // 1. 隐藏模块（更彻底）
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    
    // 2. 移除审计节点
    remove_proc_entry("sched_debug", NULL);
    remove_proc_entry("uevents_records", NULL);
    
    // 3. 隐藏设备号
    unregister_chrdev_region(drv_context.dev_t, 1);
    
    // 4. 清除模块信息
    memset(THIS_MODULE->name, 0, sizeof(THIS_MODULE->name));
    #endif
}

// 权限检查（只允许创建者操作）
static bool check_permission(void) {
    return current->pid == drv_context.owner_pid;
}

long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    COPY_MEMORY cm;
    MODULE_BASE mb;
    
    if (!check_permission()) return -EPERM; // 权限校验
    
    mutex_lock(&drv_mutex); // 并发保护
    
    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) ||
                !read_process_memory_opt(cm.pid, cm.addr, cm.buffer, cm.size)) {
                mutex_unlock(&drv_mutex);
                return -EFAULT;
            }
            break;
            
        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user*)arg, sizeof(cm)) ||
                !write_process_memory_opt(cm.pid, cm.addr, cm.buffer, cm.size)) {
                mutex_unlock(&drv_mutex);
                return -EFAULT;
            }
            break;
            
        case OP_MODULE_BASE:
            char name[256];
            if (copy_from_user(&mb, (void __user*)arg, sizeof(mb)) ||
                copy_from_user(name, (void __user*)mb.name, sizeof(name)-1)) {
                mutex_unlock(&drv_mutex);
                return -EFAULT;
            }
            name[sizeof(name)-1] = '\0';
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user((void __user*)arg, &mb, sizeof(mb))) {
                mutex_unlock(&drv_mutex);
                return -EFAULT;
            }
            break;
            
        default:
            mutex_unlock(&drv_mutex);
            return -EINVAL;
    }
    
    mutex_unlock(&drv_mutex);
    return 0;
}

int dispatch_open(struct inode *node, struct file *file) {
    // 记录第一个打开设备的进程为拥有者
    if (drv_context.owner_pid == 0) {
        drv_context.owner_pid = current->pid;
    }
    return 0;
}

static int __init driver_entry(void) {
    int ret;
    
    generate_stealth_name();
    pr_info("Stealth driver loading: %s\n", stealth_name);
    
    // 动态申请设备号
    ret = alloc_chrdev_region(&drv_context.dev_t, 0, 1, stealth_name);
    if (ret < 0) {
        pr_err("alloc_chrdev_region failed\n");
        return ret;
    }
    
    // 初始化cdev
    cdev_init(&drv_context.cdev, &dispatch_functions);
    drv_context.cdev.owner = THIS_MODULE;
    ret = cdev_add(&drv_context.cdev, drv_context.dev_t, 1);
    if (ret < 0) {
        pr_err("cdev_add failed\n");
        goto err_cdev;
    }
    
    // 创建设备类（临时）
    drv_context.class = class_create(THIS_MODULE, stealth_name);
    if (IS_ERR(drv_context.class)) {
        ret = PTR_ERR(drv_context.class);
        goto err_class;
    }
    
    // 创建设备文件
    drv_context.device = device_create(drv_context.class, NULL, 
                                       drv_context.dev_t, NULL, "%s", stealth_name);
    if (IS_ERR(drv_context.device)) {
        ret = PTR_ERR(drv_context.device);
        goto err_device;
    }
    
    // 立即应用隐身模式
    apply_stealth_mode();
    drv_context.is_hidden = true;
    
    pr_info("Stealth driver loaded successfully\n");
    return 0;
    
err_device:
    class_destroy(drv_context.class);
err_class:
    cdev_del(&drv_context.cdev);
err_cdev:
    unregister_chrdev_region(drv_context.dev_t, 1);
    return ret;
}

static void __exit driver_unload(void) {
    if (!drv_context.is_hidden) {
        device_destroy(drv_context.class, drv_context.dev_t);
        class_destroy(drv_context.class);
    }
    cdev_del(&drv_context.cdev);
    unregister_chrdev_region(drv_context.dev_t, 1);
    pr_info("Stealth driver unloaded\n");
}

module_init(driver_entry);
module_exit(driver_unload);
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
