#include <linux/kernel.h>
#include <linux/module.h>
#include<linux/spinlock.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/virtio.h>
#include "virtio_blk.h"
#include <linux/scatterlist.h>
#include <linux/string_helpers.h>
#include <scsi/scsi_cmnd.h>
#include <linux/idr.h>
#define MAX_IO_BUFFER	8192	
#define VIRTIO_ID_PCIE 3 
struct frontendcard
{
	struct cdev cdev;
	char * io_buffer;//缓存应用层传递下来的缓冲区
	int flag ;
	wait_queue_head_t front_wait_on_interrupt;
	void * priv;//暂空一备它用
	
};

struct virtio_blk
{
	struct frontendcard frontendcard;
	struct virtio_device *vdev;
	struct virtqueue *vq;
	wait_queue_head_t queue_wait;

	/* The disk structure for the kernel. */
//	struct gendisk *disk;

	mempool_t *pool;

	/* Process context for config space updates */
	struct work_struct config_work;

	/* Lock for config space updates */
	struct mutex config_lock;

	/* enable config space updates */
	bool config_enable;

	/* What host tells us, plus 2 for header & tailer. */
	unsigned int sg_elems;

	/* Ida index - used to track minor number allocations. */
	int index;
	int flag;//只是一个标记，测试在read和write方法中是否能正确找到
	/* Scatterlist: can be too big for stack. */
	struct scatterlist sg[/*sg_elems*/];
};
struct virtblk_req
{
//	struct request *req;//这个肯定是不需要了的
//	struct bio *bio;// 这个也不需要
	struct virtio_pcie_outhdr out_hdr;
	struct virtio_scsi_inhdr in_hdr;
	struct work_struct work;
	struct virtio_blk *vblk;
	int flags;
	u8 status;
	struct scatterlist sg[];//这个也不需要
};

int  process_req(struct virtio_blk * vblk ,int length);
int major = 234;//字符设备主设备号
int frontcard_open(struct inode * inode, struct file * filep)
{
	struct frontendcard * frontcard;
	printk("opens start\n");
	frontcard = container_of(inode->i_cdev,struct frontendcard,cdev);
	if(frontcard == NULL)
	{
		printk("opens dev error\n");
		return -1;
	}
	filep->private_data = frontcard;
	printk("open successfully\n");
	return 0;
}
int frontcard_close(struct inode * inode,struct file * filep)
{
	printk("closing...\n");
	return 0;
}
ssize_t frontcard_write(struct file * filep,const char __user * buf,size_t count,loff_t * fpos)
{
	int  ret = -1;
	struct frontendcard * frontcard = filep->private_data;
	struct virtio_blk * vblk = container_of(frontcard,struct virtio_blk,frontendcard);
	if(vblk == NULL)
	{
		printk("vblk null\n");
		return -1;
	}
//	printk("count:%d\n",(int)count);
	if(count > 8192 -8)
		count = 8192 -8;
	if(copy_from_user(frontcard->io_buffer,buf,count))
		return -EFAULT;
//	printk("successfully write\n");
	ret = process_req(vblk,count);
	if(ret != 0)
	{
		printk("process_req error\n");
		return -EFAULT;
	}
//在此等待
	while(frontcard->flag != 1)//等于1不用等待
	{
		wait_event_interruptible(frontcard->front_wait_on_interrupt,frontcard->flag==1);

	}
	if(frontcard->flag != 1)
		return 0;
	frontcard->flag = 0;

	return 0;
		

}
ssize_t frontcard_read(struct file * filep, char __user * buf,size_t count,loff_t * fpos)
{
	struct frontendcard * frontcard = filep->private_data;
	if(frontcard == NULL)
	{
		printk("read errro\n");
		return -1;
	}
	if(copy_to_user(buf,frontcard->io_buffer,count))
		return -EFAULT;
//	printk("successfully read\n");
	return 0;
}	
static const struct file_operations frontcard_ops ={
	.open = frontcard_open,
	.release = frontcard_close,
	.read = frontcard_read,
	.write = frontcard_write,
	.owner = THIS_MODULE,
};

//该函数在virtio_probe函数中调用
static int setup_chardev(struct frontendcard * frontcard)
{
	int retval = 0,err = 0;
	dev_t dev,devno;
/*	frontcard = (struct frontendcard *)kzalloc(sizeof(struct frontendcard),GFP_KERNEL);
	if(frontcard == NULL)
	{
		printk("alloc memory for frontcard error\n");
		kfree(frontcard);
		return -1;
	}*/
	//对I/Obuffer的分配不应该在set_chardev函数中处理,移至virtio_probe函数中，包括中断的注册，
	frontcard->io_buffer = (char *)kzalloc(MAX_IO_BUFFER,GFP_KERNEL);
	if(frontcard->io_buffer==NULL)
	{
		printk("alloc memory for IO_buffer error\n");
		return -1;
	}

	frontcard->priv = NULL;
	init_waitqueue_head(&frontcard->front_wait_on_interrupt);
	if(major)
	{
		dev = MKDEV(major,0);
		retval = register_chrdev_region(dev,1,"frontcard");
		if(retval != 0)
		{
			printk("register_chardev_region error\n");
			return -1;
		}
				
	}
	else
	{
		retval = alloc_chrdev_region(&dev,0,1,"frontcard");
		if(retval != 0)
		{
			printk("alloc_chrdev_region error\n");
			return -1;
		}
		major = MAJOR(dev);
		
	}
	devno = MKDEV(major,0);
	memset(&frontcard->cdev,0,sizeof(struct cdev));
	cdev_init(&frontcard->cdev,&frontcard_ops);
	frontcard->cdev.owner = THIS_MODULE;
	frontcard->cdev.ops = &frontcard_ops;
	err = cdev_add(&frontcard->cdev,devno,1);
	if(err)
	{
		printk("create ");
		cdev_del(&frontcard->cdev);
		unregister_chrdev_region(devno,1);
		if(frontcard->io_buffer)
			kfree(frontcard->io_buffer);
		return -1;
	}
	return 0;//成功注册字符设备	
}
//该函数在virtio_remove函数中调用
static void destroy_chardev(struct frontendcard * frontcard)
{
	if(frontcard)//只有当frontcard非空时才执行如下操作
	{
		dev_t dev = MKDEV(major,0);
		cdev_del(&frontcard->cdev);
		unregister_chrdev_region(dev,1);
		//IO内存的释放该放在virtio_remove函数中执行
		if(frontcard->io_buffer)
			kfree(frontcard->io_buffer);
	}
	
}

static void virtblk_config_changed(struct virtio_device *vdev)
{
//	struct virtio_blk *vblk = vdev->priv;

	printk("just a declare\n");
	return ;
//	queue_work(virtblk_wq, &vblk->config_work);
}

static inline int virtblk_result(struct virtblk_req *vbr)
{
	switch (vbr->status) {
	case VIRTIO_BLK_S_OK:
		return 0;
	case VIRTIO_BLK_S_UNSUPP:
		return -ENOTTY;
	default:
		return -EIO;
	}
}
//分配virtblk_req结构
static inline struct virtblk_req *virtblk_alloc_req(struct virtio_blk *vblk,
						    gfp_t gfp_mask)
{
	struct virtblk_req *vbr;

	vbr = mempool_alloc(vblk->pool, gfp_mask);
	if (!vbr)
		return NULL;

	vbr->vblk = vblk;

	return vbr;
}
static void virtblk_add_buf_wait(struct virtio_blk *vblk,
				 struct virtblk_req *vbr,
				 unsigned long out,
				 unsigned long in)
{
	DEFINE_WAIT(wait);

	for (;;) {
		prepare_to_wait_exclusive(&vblk->queue_wait, &wait,
					  TASK_UNINTERRUPTIBLE);

	//	spin_lock_irq(vblk->disk->queue->queue_lock);
		if (virtqueue_add_buf(vblk->vq, vbr->sg, out, in, vbr,
				      GFP_ATOMIC) < 0) {
		//	spin_unlock_irq(vblk->disk->queue->queue_lock);
			io_schedule();
		} else {
			virtqueue_kick(vblk->vq);
		//	spin_unlock_irq(vblk->disk->queue->queue_lock);
			break;
		}

	}

	finish_wait(&vblk->queue_wait, &wait);
}
//该是向virtqueue队列中添加virtblk_req
static inline void virtblk_add_req(struct virtblk_req *vbr,
				   unsigned int out, unsigned int in)
{
	struct virtio_blk *vblk = vbr->vblk;

//	spin_lock_irq(vblk->disk->queue->queue_lock);
	if (unlikely(virtqueue_add_buf(vblk->vq, vbr->sg, out, in, vbr,
					GFP_ATOMIC) < 0)) {
	//	spin_unlock_irq(vblk->disk->queue->queue_lock);
		virtblk_add_buf_wait(vblk, vbr, out, in);
		return;
	}
	virtqueue_kick(vblk->vq);
//	spin_unlock_irq(vblk->disk->queue->queue_lock);
}


static void virtblk_done(struct virtqueue *vq)
{
	struct virtio_blk *vblk = vq->vdev->priv;
	struct virtblk_req *vbr;
//	unsigned long flags;
	unsigned int len;
//	printk("get information from backend\n");
	vbr = virtqueue_get_buf(vblk->vq,&len);
	//检查结果，
//	printk("from backend:,strlen():%d\n",strlen(vblk->frontendcard.io_buffer));
	//唤醒front_write
	vblk->frontendcard.flag = 1;
	wake_up(&vblk->frontendcard.front_wait_on_interrupt);

	//释放vbr内存
	mempool_free(vbr,vblk->pool);
	return ;
	
	
}

int  process_req(struct virtio_blk * vblk,int length)
{
	unsigned long num=0,out = 0, in = 0;
	struct virtblk_req * vbr;
//	printk("prepare to alloc req\n");
	vbr = virtblk_alloc_req(vblk,GFP_ATOMIC);
	if(!vbr)
	{
		printk("alloc req error\n");
		return -1;
	}
	//开始填充virtio_blk_outhdr,并且传递给后端
	vbr->out_hdr.type = 1;
	vbr->out_hdr.ioprio = 4;
	vbr->out_hdr.sector = 2;
	vbr->out_hdr.real_len = length;
	sg_set_buf(&vblk->sg[out++], &vbr->out_hdr, sizeof(vbr->out_hdr));
	sg_set_buf(&vblk->sg[out++],vbr->vblk->frontendcard.io_buffer,MAX_IO_BUFFER);
	sg_set_buf(&vblk->sg[num + out + in++], &vbr->status,
		   sizeof(vbr->status));

	if (virtqueue_add_buf(vblk->vq, vblk->sg, out, in, vbr,
			      GFP_ATOMIC) < 0) {
		mempool_free(vbr, vblk->pool);
		return -1;
	}

	virtqueue_kick(vblk->vq);
//	printk("Send to backend\n");
	return 0;	
}

static int init_vq(struct virtio_blk *vblk)
{
	int err = 0;
	/* We expect one virtqueue, for output. */
	vblk->vq = virtio_find_single_vq(vblk->vdev, virtblk_done, "requests");
	if (IS_ERR(vblk->vq))
		err = PTR_ERR(vblk->vq);

	return err;
}

//virtblk_freeze和virtblk_restore暂时不动，估计是支持动态迁移的
static int  virtblk_probe(struct virtio_device *vdev)
{
	struct virtio_blk *vblk;
	int err, index = 0;
	int pool_size;
	u32  bufflength;
	u32  sg_elems;
	u32  flag;
	/* We need to know how many segments before we allocate. */
	err = virtio_config_val(vdev, VIRTIO_PCIE_F_SEG_MAX,
				offsetof(struct virtio_pcie_config, seg_max),
				&sg_elems);
	if (err || !sg_elems)
		sg_elems = 1;

	/* We need an extra sg elements at head and tail. */
	sg_elems += 2;
	printk("sg_elems = %d\n",sg_elems);
	err = virtio_config_val(vdev,VIRTIO_PCIE_F_BUFFLENGTH,
				offsetof(struct virtio_pcie_config,bufflength),
				&bufflength);
	if(err)
		bufflength = 0;
	printk("bufflength = %d\n",bufflength);
	err = virtio_config_val(vdev,VIRTIO_PCIE_F_FLAG,
				offsetof(struct virtio_pcie_config,flag),
				&flag);
	if(err)
		flag = 0;
	printk("flag :%d\n",flag);
	vdev->priv = vblk = kzalloc(sizeof(*vblk) +
				    sizeof(vblk->sg[0]) * sg_elems, GFP_KERNEL);
	if (!vblk) {
		err = -ENOMEM;
		return err;
	}

	err = setup_chardev(&vblk->frontendcard);
	init_waitqueue_head(&vblk->queue_wait);//这一部分暂时留着，可能有用
	vblk->vdev = vdev;
	vblk->sg_elems = sg_elems;
	sg_init_table(vblk->sg, vblk->sg_elems);
	mutex_init(&vblk->config_lock);
	vblk->config_enable = true;

	err = init_vq(vblk);
	if (err)
		goto out_free_vblk;
	pool_size = sizeof(struct virtblk_req);
	vblk->pool = mempool_create_kmalloc_pool(1, pool_size);
	if (!vblk->pool) {
		err = -ENOMEM;
		goto out_free_vq;
	}
//队列的初始化部分就不要了
	vblk->index = index;
	vblk->flag = 8;

	return 0;


out_free_vq:
	vdev->config->del_vqs(vdev);
out_free_vblk:
	kfree(vblk);
//out_free_index:
//	ida_simple_remove(&vd_index_ida, index);
	return err;
}

static void virtblk_remove(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
//	int index = vblk->index;


	/* Prevent config work handler from accessing the device. */
	mutex_lock(&vblk->config_lock);
	vblk->config_enable = false;
	mutex_unlock(&vblk->config_lock);


	/* Stop all the virtqueues. */
	vdev->config->reset(vdev);

//	flush_work(&vblk->config_work);

	mempool_destroy(vblk->pool);
	vdev->config->del_vqs(vdev);
	destroy_chardev(&vblk->frontendcard);
	kfree(vblk);

	/* Only free device id if we don't have any users */
}


static int virtblk_freeze(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;

	/* Ensure we don't receive any more interrupts */
	vdev->config->reset(vdev);

	/* Prevent config work handler from accessing the device. */
	mutex_lock(&vblk->config_lock);
	vblk->config_enable = false;
	mutex_unlock(&vblk->config_lock);

	flush_work(&vblk->config_work);

//	spin_lock_irq(vblk->disk->queue->queue_lock);
//	blk_stop_queue(vblk->disk->queue);
//	spin_unlock_irq(vblk->disk->queue->queue_lock);
//	blk_sync_queue(vblk->disk->queue);

	vdev->config->del_vqs(vdev);
	return 0;
}

static int virtblk_restore(struct virtio_device *vdev)
{
	struct virtio_blk *vblk = vdev->priv;
	int ret;

	vblk->config_enable = true;
	ret = init_vq(vdev->priv);
	if (!ret) {
		printk("init_vq successfully\n");
	//	spin_lock_irq(vblk->disk->queue->queue_lock);
	//	blk_start_queue(vblk->disk->queue);
	//	spin_unlock_irq(vblk->disk->queue->queue_lock);
	}
	return ret;
}


static const struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_PCIE, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static unsigned int features[] = {
	VIRTIO_PCIE_F_CAPACITY, VIRTIO_PCIE_F_BUFFLENGTH, VIRTIO_PCIE_F_FLAG,
	VIRTIO_PCIE_F_SEG_MAX
};



static struct virtio_driver virtio_blk={
	.feature_table	= features,
	.feature_table_size  = ARRAY_SIZE(features),
	.driver.name	= KBUILD_MODNAME,
	.driver.owner	= THIS_MODULE,
	.id_table	= id_table,
	.probe		= virtblk_probe,
	.remove		= __devexit_p(virtblk_remove),
	.config_changed	= virtblk_config_changed,

};
static int __init init(void)
{
	int error;

//建立字符设备

	error = register_virtio_driver(&virtio_blk);
	if (error)
		goto out_unregister_blkdev;
	return 0;

out_unregister_blkdev:
	return error;
}

static void __exit fini(void)
{
	unregister_virtio_driver(&virtio_blk);
}
module_init(init);
module_exit(fini);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio pcie driver");
MODULE_LICENSE("GPL");
