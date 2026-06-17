#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/atomic.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define SYCMEM_NAME "sycmem"
#define SYCMEM_MAX_SLOTS 0x400
#define SYCMEM_OBJ_SIZE 0x1000

#define SYCMEM_IOC_MAGIC 0x53
#define SYCMEM_ALLOC _IOW(SYCMEM_IOC_MAGIC, 0x10, struct sycmem_req)
#define SYCMEM_FREE  _IOW(SYCMEM_IOC_MAGIC, 0x11, struct sycmem_req)
#define SYCMEM_READ  _IOWR(SYCMEM_IOC_MAGIC, 0x12, struct sycmem_req)
#define SYCMEM_WRITE _IOW(SYCMEM_IOC_MAGIC, 0x13, struct sycmem_req)

struct sycmem_req {
	u32 idx;
	u32 size;
	u64 offset;
	u64 user_buf;
	u64 sync;
};

struct sycmem_slot {
	void *ptr;
	u32 size;
	bool freeing;
};

static struct sycmem_slot slots[SYCMEM_MAX_SLOTS];
static struct kmem_cache *sycmem_area;
static atomic_t sycmem_state = ATOMIC_INIT(0);
static DEFINE_MUTEX(sycmem_lock);

static void __user *sycmem_user_ptr(u64 addr)
{
	return (void __user *)(uintptr_t)addr;
}

static bool sycmem_bad_idx(u32 idx)
{
	return idx >= SYCMEM_MAX_SLOTS;
}

static bool sycmem_bad_range(const struct sycmem_req *req, u32 slot_size)
{
	if (!req->size)
		return true;
	if (req->offset > slot_size)
		return true;
	if (req->size > slot_size - req->offset)
		return true;
	return false;
}

static int sycmem_alloc(const struct sycmem_req *req)
{
	struct sycmem_slot *slot;
	void *ptr;
	u32 init_size;

	if (sycmem_bad_idx(req->idx))
		return -EINVAL;
	if (req->size > SYCMEM_OBJ_SIZE)
		return -EINVAL;

	mutex_lock(&sycmem_lock);
	slot = &slots[req->idx];
	if (atomic_read(&sycmem_state) ||
	    READ_ONCE(slot->ptr) || READ_ONCE(slot->freeing)) {
		mutex_unlock(&sycmem_lock);
		return -EBUSY;
	}

	ptr = kmem_cache_zalloc(sycmem_area, GFP_KERNEL);
	if (!ptr) {
		mutex_unlock(&sycmem_lock);
		return -ENOMEM;
	}

	init_size = req->size;
	if (req->user_buf && init_size &&
	    copy_from_user(ptr, sycmem_user_ptr(req->user_buf), init_size)) {
		kmem_cache_free(sycmem_area, ptr);
		mutex_unlock(&sycmem_lock);
		return -EFAULT;
	}

	WRITE_ONCE(slot->size, SYCMEM_OBJ_SIZE);
	WRITE_ONCE(slot->ptr, ptr);
	mutex_unlock(&sycmem_lock);
	return 0;
}

static int sycmem_free(const struct sycmem_req *req)
{
	struct sycmem_slot *slot;
	void *ptr;
	u8 sync_byte = 0;
	int ret = 0;

	if (sycmem_bad_idx(req->idx))
		return -EINVAL;

	mutex_lock(&sycmem_lock);
	slot = &slots[req->idx];
	ptr = READ_ONCE(slot->ptr);
	if (!ptr || READ_ONCE(slot->freeing)) {
		mutex_unlock(&sycmem_lock);
		return -EINVAL;
	}

	WRITE_ONCE(slot->freeing, true);
	atomic_inc(&sycmem_state);
	kmem_cache_free(sycmem_area, ptr);
	mutex_unlock(&sycmem_lock);

	kmem_cache_shrink(sycmem_area);

	if (req->sync &&
	    copy_to_user(sycmem_user_ptr(req->sync), &sync_byte,
			 sizeof(sync_byte)))
		ret = -EFAULT;

	mutex_lock(&sycmem_lock);
	WRITE_ONCE(slot->ptr, NULL);
	WRITE_ONCE(slot->size, 0);
	WRITE_ONCE(slot->freeing, false);
	atomic_dec(&sycmem_state);
	mutex_unlock(&sycmem_lock);
	return ret;
}

static int sycmem_read(const struct sycmem_req *req)
{
	struct sycmem_slot *slot;
	void *ptr;
	u32 slot_size;

	if (sycmem_bad_idx(req->idx) || !req->user_buf)
		return -EINVAL;

	slot = &slots[req->idx];
	ptr = READ_ONCE(slot->ptr);
	slot_size = READ_ONCE(slot->size);
	if (!ptr || sycmem_bad_range(req, slot_size))
		return -EINVAL;

	if (copy_to_user(sycmem_user_ptr(req->user_buf),
			 (u8 *)ptr + req->offset, req->size))
		return -EFAULT;

	return 0;
}

static int sycmem_write(const struct sycmem_req *req)
{
	struct sycmem_slot *slot;
	void *ptr;
	u32 slot_size;

	if (sycmem_bad_idx(req->idx) || !req->user_buf)
		return -EINVAL;

	slot = &slots[req->idx];
	ptr = READ_ONCE(slot->ptr);
	slot_size = READ_ONCE(slot->size);
	if (!ptr || sycmem_bad_range(req, slot_size))
		return -EINVAL;

	if (copy_from_user((u8 *)ptr + req->offset,
			   sycmem_user_ptr(req->user_buf), req->size))
		return -EFAULT;

	return 0;
}

static long sycmem_ioctl(struct file *file, unsigned int cmd,
			 unsigned long user_arg)
{
	struct sycmem_req req;
	void __user *argp = (void __user *)user_arg;

	if (_IOC_TYPE(cmd) != SYCMEM_IOC_MAGIC)
		return -ENOTTY;

	if (copy_from_user(&req, argp, sizeof(req)))
		return -EFAULT;

	switch (cmd) {
	case SYCMEM_ALLOC:
		return sycmem_alloc(&req);
	case SYCMEM_FREE:
		return sycmem_free(&req);
	case SYCMEM_READ:
		return sycmem_read(&req);
	case SYCMEM_WRITE:
		return sycmem_write(&req);
	default:
		return -ENOTTY;
	}
}

static const struct file_operations sycmem_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = sycmem_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice sycmem_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = SYCMEM_NAME,
	.fops = &sycmem_fops,
	.mode = 0666,
};

static int __init sycmem_init(void)
{
	int ret;

	sycmem_area = kmem_cache_create("kmage_node", SYCMEM_OBJ_SIZE, 0, 0,
					NULL);
	if (!sycmem_area)
		return -ENOMEM;

	ret = misc_register(&sycmem_dev);
	if (ret) {
		kmem_cache_destroy(sycmem_area);
		sycmem_area = NULL;
		return ret;
	}

	pr_info("%s: /dev/%s registered\n", SYCMEM_NAME, SYCMEM_NAME);
	return 0;
}

static void __exit sycmem_exit(void)
{
	int i;

	misc_deregister(&sycmem_dev);

	for (i = 0; i < SYCMEM_MAX_SLOTS; i++) {
		if (slots[i].ptr && !slots[i].freeing)
			kmem_cache_free(sycmem_area, slots[i].ptr);
		slots[i].ptr = NULL;
		slots[i].size = 0;
		slots[i].freeing = false;
	}

	kmem_cache_destroy(sycmem_area);
	sycmem_area = NULL;
}

module_init(sycmem_init);
module_exit(sycmem_exit);

MODULE_DESCRIPTION("sycmem");
MODULE_LICENSE("GPL");
