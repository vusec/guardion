#ifndef __ROWHARM_H__
#define __ROWHARM_H__

#include <linux/ioctl.h>

#define RH_IOC_MAGIC 'l'
#define RH_IOC_RST_OVERFLOWS      _IO(RH_IOC_MAGIC, 1)
#define RH_IOC_GET_OVERFLOWS      _IO(RH_IOC_MAGIC, 2)
#define RH_IOC_RST_DELAYS         _IO(RH_IOC_MAGIC, 3)
#define RH_IOC_GET_DELAYS         _IO(RH_IOC_MAGIC, 4)

#endif

