#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/perf_event.h>

#include "rowharm.h"

MODULE_AUTHOR("Victor van der Veen");
MODULE_DESCRIPTION("Sailfish Module");
MODULE_LICENSE("GPL");


// get an interrupt every SAMPLE_PERIOD memory accesses 
// #define SAMPLE_PERIOD 100000000 // seems ok for the PIXEL
//   #define SAMPLE_PERIOD 1000000 // this still works, but very slow, on N5. still bit flips though
   #define SAMPLE_PERIOD 600000

// if the last SAMPLE_PERIOD memory accesses occured within REFRS_MSEC ms...
#define REFRS_MSEC 50

// ... delay for DELAY_MSEC ms (default refresh rate)
#define DELAY_MSEC 64

// number of interrupts, multiply this with SAMPLE_PERIOD to get the total number of memory accesses
long overflows;

// number of delays
long delays;


#define BILLION 1000000000L
inline uint64_t getns(void)
{
    struct timespec ts;
    getnstimeofday(&ts);
    return (BILLION * ts.tv_sec) + ts.tv_nsec;
}


static struct perf_event_attr rh_attr = {
	.type	= PERF_TYPE_HARDWARE,

    // msm/arch/arm64/kernel/perf_event.c was changed so that this is MEM_ACCESSES
	.config = PERF_COUNT_HW_CACHE_MISSES, 

    .size	= sizeof(struct perf_event_attr),
	.pinned	= 1,
	.sample_period = SAMPLE_PERIOD,
};

static DEFINE_PER_CPU(struct perf_event *, rh_event);
static DEFINE_PER_CPU(u64, rh_timestamp);

static void rh_overflow(struct perf_event *event, struct perf_sample_data *data, struct pt_regs *regs)
{
	u64 *ts = this_cpu_ptr(&rh_timestamp); 
	u64 now = getns();
	s64 delta = now - *ts;

	*ts = now;

    overflows++;

	if (delta < REFRS_MSEC * NSEC_PER_MSEC) {
        delays++; 
		mdelay(DELAY_MSEC);
    }

}

int rh_open(struct inode *inode, struct file *filp)
{
	overflows = 0;
    return 0;
}

int rh_close(struct inode *inode, struct file *filp)
{
    return 0;
}


static long rh_ioctl(struct file *file, unsigned int cmd, unsigned long arg1)
{
    uint64_t *val = (uint64_t *) arg1;

	if (cmd == RH_IOC_RST_OVERFLOWS) {
        printk("resetting overflows\n");
        overflows = 0;
        return 0;
    }
    if (cmd == RH_IOC_GET_OVERFLOWS) {
        printk("returning overflows: %ld\n", overflows);
        *val = overflows;
        return 0;
    }
    if (cmd == RH_IOC_RST_DELAYS) {
        printk("resetting delays\n");
        delays = 0;
        return 0;
    }
    if (cmd == RH_IOC_GET_DELAYS) {
        printk("return delays: %ld\n", delays);
        *val = delays;
        return 0;
    }
		
	return 0;
}






static struct file_operations rh_fops = 
{
    .owner          = THIS_MODULE,
    .unlocked_ioctl = rh_ioctl,
    .compat_ioctl   = rh_ioctl,
    .open           = rh_open,
    .release        = rh_close,
};
static struct miscdevice rh_miscdev = 
{
    .minor          = MISC_DYNAMIC_MINOR,
    .name           = "rh",
    .fops           = &rh_fops,
};


static int __init rh_init(void) 
{
	int cpu;

    if (misc_register(&rh_miscdev)) {
        printk(KERN_ERR "cannot register miscdev\n");
        return -1;
    }
    

    printk("Rowhammer protection limit is set to %d memory accesses per %d msec\n",
                      (int) SAMPLE_PERIOD, REFRS_MSEC);

    for_each_possible_cpu(cpu) {
        struct perf_event *event;
    
        event = perf_event_create_kernel_counter(&rh_attr, cpu, NULL, rh_overflow, NULL);
        per_cpu(rh_event, cpu) = event;     
        if (IS_ERR(event)) {
            pr_err("Not enough resources to initialize nohammer on cpu %d\n", cpu);
            continue;
        }
        pr_info("Nohammer initialized on cpu %d\n", cpu);
    }

    return 0;
}

static void __exit rh_exit(void) {
	int cpu;

	for_each_possible_cpu(cpu) {
		struct perf_event *event = per_cpu(rh_event, cpu);
        printk("releasing: %p\n", event);
		if (!IS_ERR(event))
			perf_event_release_kernel(event);
	}

    misc_deregister(&rh_miscdev);
}





module_init(rh_init);
module_exit(rh_exit);

