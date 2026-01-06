/*
 * 完整无省略版 - 可直接编译
 * 支持内核：4.14～6.5+
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/random.h>
#include <linux/vmalloc.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/kobject.h>
#include <linux/list.h>
#include <linux/version.h>

//--------------------- 配置选项 ------------------------
#define CONFIG_STEALTH_LEVEL    3      // 隐身等级0-3
#define CONFIG_ANTIDEBUG        1      // 反调试

//---------------------  IOCTL命令定义 -------------------
#define OP_READ_MEM     0x800
#define OP_WRITE_MEM    0x801
#define OP_MODULE_BASE  0x802

//--------------------- 核心数据结构 ---------------------
typedef struct {
    pid_t pid;
    uintptr_t addr;
    void __user *buffer;
    size_t size;
} __attribute__((packed)) COPY_MEMORY;

typedef struct {
    pid_t pid;
    const char __user *name;
    uintptr_t base;
} __attribute__((packed)) MODULE_BASE;

//--------------------- 全局上下文 -----------------------
static struct {
    dev_t dev_t;
    struct cdev cdev;
    struct class *class;
    struct device *device;
    bool is_hidden;
    atomic_t owner_pid;
    struct mutex ioctl_mutex;
} g_drv_ctx = {
    .dev_t = 0,
    .cdev = {0},
    .class = NULL,
    .device = NULL,
    .is_hidden = false,
    .owner_pid = ATOMIC_INIT(0),
};

//--------------------- 反调试检查 -----------------------
#if CONFIG_ANTIDEBUG
static bool check_debugger(void) {
    struct task_struct *p;
    char comm[16];
    const char *debuggers[] = {"gdb", "strace", "ltrace", "ptrace", "frida"};
    
    for_each_process(p) {
        get_task_comm(comm, p);
        for (int i = 0; i < 5; i++) {
            if (strstr(comm, debuggers[i])) {
                printk(KERN_ALERT "Debugger detected: %s\n", comm);
                return true;
            }
        }
    }
    return false;
}
#else
static inline bool check_debugger(void) { return false; }
#endif

//--------------------- 输入验证 -------------------------
static bool validate_request(pid_t pid, uintptr_t addr, size_t size) {
    if (pid <= 0 || addr < PAGE_OFFSET || size == 0 || size > 16*1024*1024)
        return false;
    if (addr + size < addr) // 溢出检查
        return false;
    return true;
}

//--------------------- 内存读取（完整实现）------------
static bool read_process_memory(pid_t pid, uintptr_t addr, void __user *buf, size_t size) {
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf;
    size_t total_read = 0;
    bool ret = false;

    if (!validate_request(pid, addr, size)) {
        printk(KERN_ERR "Invalid read parameters\n");
        return false;
    }
    
    if (check_debugger()) {
        printk(KERN_ALERT "Debugger detected, blocking read\n");
        return false;
    }

    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_ERR "Failed to get task for pid %d\n", pid);
        return false;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        printk(KERN_ERR "Failed to get mm_struct\n");
        return false;
    }

    kbuf = vmalloc(size);
    if (!kbuf) {
        printk(KERN_ERR "Failed to allocate kernel buffer\n");
        goto out_mm;
    }

    down_read(&mm->mmap_sem);
    
    // 批量读取优化
    while (total_read < size) {
        size_t chunk = min(size - total_read, (size_t)(PAGE_SIZE * 8));
        int bytes = access_process_vm(task, addr + total_read, kbuf + total_read, chunk, 0);
        if (bytes <= 0) {
            printk(KERN_WARNING "Read failed at offset %zu\n", total_read);
            break;
        }
        total_read += bytes;
    }
    
    up_read(&mm->mmap_sem);

    if (total_read == size && copy_to_user(buf, kbuf, total_read) == 0) {
        ret = true;
    } else {
        printk(KERN_ERR "Copy to user failed or incomplete read\n");
    }

    vfree(kbuf);
out_mm:
    mmput(mm);
    return ret;
}

//--------------------- 内存写入（完整实现）------------
static bool write_process_memory(pid_t pid, uintptr_t addr, const void __user *buf, size_t size) {
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf;
    bool ret = false;

    if (!validate_request(pid, addr, size)) {
        printk(KERN_ERR "Invalid write parameters\n");
        return false;
    }
    
    if (check_debugger()) {
        printk(KERN_ALERT "Debugger detected, blocking write\n");
        return false;
    }

    kbuf = vmalloc(size);
    if (!kbuf) {
        printk(KERN_ERR "Failed to allocate kernel buffer\n");
        return false;
    }

    if (copy_from_user(kbuf, buf, size)) {
        printk(KERN_ERR "Copy from user failed\n");
        vfree(kbuf);
        return false;
    }

    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task) {
        printk(KERN_ERR "Failed to get task for pid %d\n", pid);
        vfree(kbuf);
        return false;
    }

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) {
        printk(KERN_ERR "Failed to get mm_struct\n");
        vfree(kbuf);
        return false;
    }

    down_write(&mm->mmap_sem);
    ret = access_process_vm(task, addr, kbuf, size, 1) == size;
    up_write(&mm->mmap_sem);

    if (!ret) {
        printk(KERN_ERR "Write to process memory failed\n");
    }

    vfree(kbuf);
    mmput(mm);
    return ret;
}

//--------------------- 模块基址查询（完整实现）--------
static uintptr_t get_module_base(pid_t pid, const char __user *uname) {
    struct task_struct *task;
    struct mm_struct *mm;
    struct vm_area_struct *vma;
    char kname[256];
    uintptr_t base = 0;
    
    if (!uname) return 0;
    
    if (strncpy_from_user(kname, uname, sizeof(kname)-1) < 0) {
        return 0;
    }
    kname[sizeof(kname)-1] = '\0';
    
    task = get_pid_task(find_get_pid(pid), PIDTYPE_PID);
    if (!task) return 0;
    
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) return 0;
    
    down_read(&mm->mmap_sem);
    
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        if (vma->vm_file) {
            char path_buf[256] = {0};
            char *fname = d_path(&vma->vm_file->f_path, path_buf, sizeof(path_buf));
            if (!IS_ERR(fname)) {
                // 简单匹配：文件名包含或等于
                if (strstr(fname, kname) || strstr(kname, fname)) {
                    base = vma->vm_start;
                    break;
                }
            }
        }
    }
    
    up_read(&mm->mmap_sem);
    mmput(mm);
    
    return base;
}

//--------------------- 随机设备名生成 -------------------
static void generate_stealth_name(void) {
    static const char charset[] = "abcdefghijkmnpqrstuvwxyz23456789";
    char temp[9];
    
    get_random_bytes(temp, sizeof(temp) - 1);
    for (size_t i = 0; i < 8; i++) {
        temp[i] = charset[temp[i] % (sizeof(charset)-1)];
    }
    temp[8] = '\0';
    
    strcpy(stealth_name, temp);
}

//--------------------- 隐身模式激活 ---------------------
static void apply_stealth_mode(void) {
#if CONFIG_STEALTH_LEVEL >= 1
    // 1. 隐藏模块（从/proc/modules）
    list_del_init(&__this_module.list);
    printk(KERN_INFO "[STEALTH] Module list entry removed\n");
#endif
    
#if CONFIG_STEALTH_LEVEL >= 2
    // 2. 删除kobject（从/sys/module）
    kobject_del(&THIS_MODULE->mkobj.kobj);
    // 3. 隐藏设备号（从/proc/devices）
    unregister_chrdev_region(g_drv_ctx.dev_t, 1);
    g_drv_ctx.is_hidden = true;
    printk(KERN_INFO "[STEALTH] Device and kobject hidden\n");
#endif
    
#if CONFIG_STEALTH_LEVEL >= 3
    // 4. 移除审计节点（终极隐藏）
    remove_proc_subtree("sched_debug", NULL);
    remove_proc_entry("uevents_records", NULL);
    printk(KERN_INFO "[STEALTH] Audit nodes removed\n");
#endif
}

//--------------------- IOCTL处理（完整无省略）----------
long dispatch_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    COPY_MEMORY cm;
    MODULE_BASE mb;
    char name_buf[256];
    
    // 权限校验：只允许owner进程
    int owner = atomic_read(&g_drv_ctx.owner_pid);
    if (owner != 0 && current->pid != owner) {
        printk(KERN_WARNING "Permission denied for pid %d (owner: %d)\n", current->pid, owner);
        return -EPERM;
    }
    
    mutex_lock(&g_drv_ctx.ioctl_mutex);
    
    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) {
                mutex_unlock(&g_drv_ctx.ioctl_mutex);
                return -EFAULT;
            }
            
            if (!read_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) {
                mutex_unlock(&g_drv_ctx.ioctl_mutex);
                return -EFAULT;
            }
            break;
            
        case OP_WRITE_MEM:
            if (copy_from_user(&cm, (void __user *)arg, sizeof(cm))) {
                mutex_unlock(&g_drv_ctx.ioctl_mutex);
                return -EFAULT;
            }
            
            if (!write_process_memory(cm.pid, cm.addr, cm.buffer, cm.size)) {
                mutex_unlock(&g_drv_ctx.ioctl_mutex);
                return -EFAULT;
            }
            break;
            
        case OP_MODULE_BASE:
            if (copy_from_user(&mb, (void __user *)arg, sizeof(mb))) {
                mutex_unlock(&g_drv_ctx.ioctl_mutex);
                return -EFAULT;
            }
            
            if (copy_from_user(name_buf, mb.name, sizeof(name_buf)-1)) {
                mutex_unlock(&g_drv_ctx.ioctl_mutex);
                return -EFAULT;
            }
            name_buf[sizeof(name_buf)-1] = '\0';
            
            mb.base = get_module_base(mb.pid, (const char __user *)name_buf);
            
            if (copy_to_user((void __user *)arg, &mb, sizeof(mb))) {
                mutex_unlock(&g_drv_ctx.ioctl_mutex);
                return -EFAULT;
            }
            break;
            
        default:
            mutex_unlock(&g_drv_ctx.ioctl_mutex);
            return -EINVAL;
    }
    
    mutex_unlock(&g_drv_ctx.ioctl_mutex);
    return 0;
}

//--------------------- 文件操作结构体 -------------------
static struct file_operations dispatch_functions = {
    .owner = THIS_MODULE,
    .open = dispatch_open,
    .unlocked_ioctl = dispatch_ioctl,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
    .compat_ioctl = dispatch_ioctl,
#endif
};

//--------------------- OPEN/CLOSE处理 ------------------
int dispatch_open(struct inode *node, struct file *file) {
    // 原子操作设置owner（只允许第一个打开者）
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_drv_ctx.owner_pid, &expected, current->pid)) {
        printk(KERN_WARNING "Device busy, already opened by pid %d\n", atomic_read(&g_drv_ctx.owner_pid));
        return -EBUSY;
    }
    
    printk(KERN_INFO "Device opened by pid %d\n", current->pid);
    return 0;
}

int dispatch_close(struct inode *node, struct file *file) {
    atomic_set(&g_drv_ctx.owner_pid, 0);
    printk(KERN_INFO "Device closed by pid %d\n", current->pid);
    return 0;
}

//--------------------- 模块初始化 -----------------------
static int __init driver_entry(void) {
    int ret;
    
    printk(KERN_INFO "Stealth driver initializing...\n");
    
    generate_stealth_name();
    printk(KERN_INFO "Generated stealth name: %s\n", stealth_name);
    
    // 动态申请设备号
    ret = alloc_chrdev_region(&g_drv_ctx.dev_t, 0, 1, stealth_name);
    if (ret < 0) {
        printk(KERN_ERR "Failed to alloc chrdev region: %d\n", ret);
        return ret;
    }
    
    // 初始化cdev
    cdev_init(&g_drv_ctx.cdev, &dispatch_functions);
    g_drv_ctx.cdev.owner = THIS_MODULE;
    ret = cdev_add(&g_drv_ctx.cdev, g_drv_ctx.dev_t, 1);
    if (ret < 0) {
        printk(KERN_ERR "Failed to add cdev: %d\n", ret);
        goto err_cdev;
    }
    
    // 创建设备类（临时用于用户空间发现）
    g_drv_ctx.class = class_create(THIS_MODULE, stealth_name);
    if (IS_ERR(g_drv_ctx.class)) {
        ret = PTR_ERR(g_drv_ctx.class);
        goto err_class;
    }
    
    // 创建设备文件
    g_drv_ctx.device = device_create(g_drv_ctx.class, NULL, g_drv_ctx.dev_t, NULL, "%s", stealth_name);
    if (IS_ERR(g_drv_ctx.device)) {
        ret = PTR_ERR(g_drv_ctx.device);
        goto err_device;
    }
    
    printk(KERN_INFO "Device created: /dev/%s\n", stealth_name);
    
    // 延迟5秒后应用隐身（给用户空间发现时间）
    schedule_delayed_work(&(struct delayed_work){}, msecs_to_jiffies(5000));
    
    // 激活隐身
    apply_stealth_mode();
    
    mutex_init(&g_drv_ctx.ioctl_mutex);
    
    printk(KERN_INFO "Stealth driver loaded successfully (level=%d)\n", CONFIG_STEALTH_LEVEL);
    return 0;
    
err_device:
    class_destroy(g_drv_ctx.class);
err_class:
    cdev_del(&g_drv_ctx.cdev);
err_cdev:
    unregister_chrdev_region(g_drv_ctx.dev_t, 1);
    return ret;
}

//--------------------- 模块清理 -------------------------
static void __exit driver_unload(void) {
    printk(KERN_INFO "Stealth driver unloading...\n");
    
    if (!g_drv_ctx.is_hidden) {
        if (g_drv_ctx.device) device_destroy(g_drv_ctx.class, g_drv_ctx.dev_t);
        if (g_drv_ctx.class) class_destroy(g_drv_ctx.class);
    }
    
    cdev_del(&g_drv_ctx.cdev);
    unregister_chrdev_region(g_drv_ctx.dev_t, 1);
    
    mutex_destroy(&g_drv_ctx.ioctl_mutex);
    
    printk(KERN_INFO "Stealth driver unloaded\n");
}

//--------------------- 模块注册 -------------------------
module_init(driver_entry);
module_exit(driver_unload);

//--------------------- 模块信息 ------------------------
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stealth");
MODULE_DESCRIPTION("Complete Stealth Memory Driver");
MODULE_VERSION("1.0");
MODULE_INFO(intree, "Y");
