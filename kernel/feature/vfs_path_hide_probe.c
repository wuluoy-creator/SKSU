#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/smp.h>
#include <linux/uidgid.h>
#include <linux/workqueue.h>

#include "arch.h"
#include "feature/vfs_path_hide_probe.h"
#include "klog.h" // IWYU pragma: keep

#define KSU_VFS_PROBE_RECORDS 256
#define KSU_VFS_PROBE_INTERVAL (2 * HZ)

enum ksu_vfs_probe_kind {
    KSU_VFS_PROBE_LOOKUP,
    KSU_VFS_PROBE_OPEN,
    KSU_VFS_PROBE_GETATTR,
    KSU_VFS_PROBE_ITERATE,
};

struct ksu_vfs_probe_call {
    const struct path *path;
    unsigned int flags;
    u8 kind;
};

struct ksu_vfs_probe_record {
    const void *mnt;
    const void *dentry;
    const void *mnt_ns;
    pid_t pid;
    long result;
    unsigned int flags;
    u8 kind;
};

static struct ksu_vfs_probe_record records[KSU_VFS_PROBE_RECORDS];
static atomic_t record_gate = ATOMIC_INIT(0);
static atomic_t record_writers = ATOMIC_INIT(0);
static atomic_t record_head = ATOMIC_INIT(0);
static atomic_t record_dropped = ATOMIC_INIT(0);
static int registered_count;
static bool probe_running;

/* Android 6.12 C-call arguments are read through arch.h; KMI builds must
 * still verify that these named kernel functions remain probeable at runtime.
 */
static int probe_lookup_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ksu_vfs_probe_call *call = (void *)ri->data;

    if (!uid_eq(current_fsuid(), KUIDT_INIT(2000)))
        return 1;
    call->kind = KSU_VFS_PROBE_LOOKUP;
    call->path = (const struct path *)PT_REGS_CCALL_PARM4(regs);
    call->flags = (unsigned int)PT_REGS_PARM3(regs);
    return 0;
}

static int probe_open_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ksu_vfs_probe_call *call = (void *)ri->data;

    if (!uid_eq(current_fsuid(), KUIDT_INIT(2000)))
        return 1;
    call->kind = KSU_VFS_PROBE_OPEN;
    call->path = NULL;
    call->flags = 0;
    return 0;
}

static int probe_getattr_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ksu_vfs_probe_call *call = (void *)ri->data;

    if (!uid_eq(current_fsuid(), KUIDT_INIT(2000)))
        return 1;
    call->kind = KSU_VFS_PROBE_GETATTR;
    call->path = (const struct path *)PT_REGS_PARM1(regs);
    call->flags = (unsigned int)PT_REGS_CCALL_PARM4(regs);
    return 0;
}

static int probe_iterate_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ksu_vfs_probe_call *call = (void *)ri->data;
    const struct file *file = (const struct file *)PT_REGS_PARM1(regs);

    if (!uid_eq(current_fsuid(), KUIDT_INIT(2000)))
        return 1;
    call->kind = KSU_VFS_PROBE_ITERATE;
    call->path = file ? &file->f_path : NULL;
    call->flags = 0;
    return 0;
}

static void probe_record(const struct ksu_vfs_probe_call *call, const struct path *path, long result)
{
    struct ksu_vfs_probe_record *record;
    int index;

    if (atomic_read(&record_gate)) {
        atomic_inc(&record_dropped);
        return;
    }

    atomic_inc(&record_writers);
    smp_mb__after_atomic();
    if (atomic_read(&record_gate)) {
        atomic_dec(&record_writers);
        atomic_inc(&record_dropped);
        return;
    }

    index = atomic_inc_return(&record_head) - 1;
    if (index >= 0 && index < KSU_VFS_PROBE_RECORDS) {
        record = &records[index];
        record->mnt = path ? READ_ONCE(path->mnt) : NULL;
        record->dentry = path ? READ_ONCE(path->dentry) : NULL;
        record->mnt_ns = current->nsproxy ? READ_ONCE(current->nsproxy->mnt_ns) : NULL;
        record->pid = current->pid;
        record->result = result;
        record->flags = call->flags;
        record->kind = call->kind;
    } else {
        atomic_inc(&record_dropped);
    }
    smp_mb__before_atomic();
    atomic_dec(&record_writers);
}

static int probe_return(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    const struct ksu_vfs_probe_call *call = (const void *)ri->data;
    const struct path *path = call->path;
    long result = call->kind == KSU_VFS_PROBE_OPEN ? (long)PT_REGS_RC(regs) : (int)PT_REGS_RC(regs);

    if (call->kind == KSU_VFS_PROBE_OPEN) {
        const struct file *file = (const struct file *)result;

        path = !IS_ERR_OR_NULL(file) ? &file->f_path : NULL;
        if (!file)
            result = -EFAULT;
        else if (IS_ERR(file))
            result = PTR_ERR(file);
        else
            result = 0;
    } else if (call->kind == KSU_VFS_PROBE_LOOKUP && result) {
        path = NULL;
    }

    probe_record(call, path, result);
    return 0;
}

static struct kretprobe probes[] = {
    { .kp.symbol_name = "filename_lookup", .entry_handler = probe_lookup_entry,
      .handler = probe_return, .data_size = sizeof(struct ksu_vfs_probe_call), .maxactive = 64 },
    { .kp.symbol_name = "do_filp_open", .entry_handler = probe_open_entry,
      .handler = probe_return, .data_size = sizeof(struct ksu_vfs_probe_call), .maxactive = 64 },
    { .kp.symbol_name = "vfs_getattr", .entry_handler = probe_getattr_entry,
      .handler = probe_return, .data_size = sizeof(struct ksu_vfs_probe_call), .maxactive = 64 },
    { .kp.symbol_name = "iterate_dir", .entry_handler = probe_iterate_entry,
      .handler = probe_return, .data_size = sizeof(struct ksu_vfs_probe_call), .maxactive = 64 },
};

static const char *const probe_names[] = { "lookup", "open", "getattr", "iterate" };
static int last_missed[ARRAY_SIZE(probes)];

static void probe_flush(void)
{
    int count, dropped, i;

    atomic_set(&record_gate, 1);
    smp_mb();
    while (atomic_read(&record_writers))
        cpu_relax();
    smp_mb();

    count = min(atomic_read(&record_head), KSU_VFS_PROBE_RECORDS);
    for (i = 0; i < count; i++) {
        const struct ksu_vfs_probe_record *record = &records[i];

        pr_info("vfs_probe: %s pid=%d ret=%ld flags=0x%x ns=%p mnt=%p dentry=%p\n",
                probe_names[record->kind], record->pid, record->result, record->flags,
                record->mnt_ns, record->mnt, record->dentry);
    }
    atomic_set(&record_head, 0);
    smp_mb();
    atomic_set(&record_gate, 0);

    dropped = atomic_xchg(&record_dropped, 0);
    if (dropped)
        pr_info("vfs_probe: dropped %d records\n", dropped);
    for (i = 0; i < registered_count; i++) {
        int missed = READ_ONCE(probes[i].nmissed);

        if (missed != last_missed[i]) {
            pr_info("vfs_probe: %s missed %d callbacks\n", probe_names[i], missed);
            last_missed[i] = missed;
        }
    }
}

static void probe_workfn(struct work_struct *work);
static DECLARE_DELAYED_WORK(probe_work, probe_workfn);

static void probe_workfn(struct work_struct *work)
{
    (void)work;
    probe_flush();
    if (READ_ONCE(probe_running))
        schedule_delayed_work(&probe_work, KSU_VFS_PROBE_INTERVAL);
}

void ksu_vfs_path_hide_probe_init(void)
{
    int i, ret;
    int count = ARRAY_SIZE(probes);

    for (i = 0; i < count; i++) {
        ret = register_kretprobe(&probes[i]);
        if (ret) {
            pr_warn("vfs_probe: %s unavailable: %d\n", probe_names[i], ret);
            while (i--)
                unregister_kretprobe(&probes[i]);
            return;
        }
    }

    registered_count = count;
    WRITE_ONCE(probe_running, true);
    schedule_delayed_work(&probe_work, KSU_VFS_PROBE_INTERVAL);
    pr_info("vfs_probe: observing fsuid 2000 on Android 6.12\n");
}

void ksu_vfs_path_hide_probe_exit(void)
{
    int i;

    if (!registered_count)
        return;

    WRITE_ONCE(probe_running, false);
    for (i = registered_count - 1; i >= 0; i--)
        unregister_kretprobe(&probes[i]);
    cancel_delayed_work_sync(&probe_work);
    probe_flush();
    registered_count = 0;
}
