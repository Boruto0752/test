#include <linux/pci.h>
#include <linux/bug.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rtnetlink.h>
#include <linux/lockdep.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/swap.h>
#include <linux/completion.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/version.h>
#include <linux/blk-mq.h>
#include <linux/ftrace.h>

#include "misc.h"

# define PATH "/dev/rbd0"

#ifdef LINUX_VERSION_CODE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
    #define KERNEL_VERSION_5_9_OR_NEWER 
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 12, 0)
    #define USE_BI_BDEV
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
    #define USE_SET_INSTRUCTION_POINTER
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
    #define HAS_FTRACE_OPS
#endif
#endif

MODULE_AUTHOR("Chetan Atole");
MODULE_LICENSE("GPL");

static struct miscdevice misc_help;
static struct block_device *blkdev = NULL;
static spinlock_t my_spinlock = __SPIN_LOCK_UNLOCKED(my_spinlock);

#ifndef KERNEL_VERSION_5_9_OR_NEWER
static blk_qc_t (*original_make_request_fn)(struct request_queue*, struct bio*);
#endif


/* Sample ioctl code - not used. Can be used to trigger on/off filtering. */
static long mischelp_ioctl(/*struct inode *inode,*/ struct file *fp,
                unsigned int cmd, unsigned long arg) {

        if (cmd == MISC_GET)    {
                printk ("Can perform get ops %d.\n", (int) arg);
        }

        if (cmd == MISC_PUT)    {
                printk ("Can perform put ops %d.\n", (int) arg);
        }

        return 0;
}


struct file_operations misc_fops = {
        .unlocked_ioctl = mischelp_ioctl,
        .owner = THIS_MODULE,
        .mmap = NULL,
};

#pragma pack(push, 1)
struct BlockDeviceChangeMetadata
{
        uint64_t starting_sector;
        uint64_t data_size;
};
#pragma pack(pop)

void WriteToFile( struct bio* bio )
{
        struct BlockDeviceChangeMetadata blockDeviceChangeMetadata;
        blockDeviceChangeMetadata.starting_sector = bio->bi_iter.bi_sector;
        blockDeviceChangeMetadata.data_size       = bio_sectors(bio)*512;

        printk( KERN_DEBUG "Opening tracker file..." );
        struct file *block_changes_file = filp_open("/root/block_changes", O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0644 );
        if ( block_changes_file == NULL || IS_ERR(block_changes_file) )
        {
                printk(KERN_DEBUG "Failed to open block_changes file %ld\n", PTR_ERR(block_changes_file) );
                return;
        }
        printk( KERN_DEBUG "Opened block_changes file." );

        printk( KERN_DEBUG "Writing metadata to block_changes file" );

        loff_t offset = 0; // File opened in append mode so offset is 0
        ssize_t bytes_written = kernel_write( block_changes_file, (const char*)&blockDeviceChangeMetadata, sizeof( blockDeviceChangeMetadata ), &offset );
        if (bytes_written < 0)
        {
                printk ( KERN_DEBUG "Failed to write metadata.\n" );
                filp_close(block_changes_file, NULL);
                return;
        }
        printk ( KERN_DEBUG "bytes_written %lu.\n", bytes_written );

        printk( KERN_DEBUG "Writing data to block_changes file" );

        struct bio_vec bvec;
        struct bvec_iter i;
        ssize_t totalBytes = 0;

        bio_for_each_segment(bvec, bio, i)
        {
                struct page *page = bvec.bv_page;
                if( page == NULL )
                {
                        printk( KERN_INFO "Got Null page!" );
                        continue;
                }

                char *src = kmap_atomic(page);
                char* dst = kmalloc(bvec.bv_len, GFP_KERNEL);
                memcpy( dst, src, bvec.bv_len );
                kunmap_atomic(src);

                ssize_t bytes_written = kernel_write( block_changes_file, dst, bvec.bv_len, &offset );
                if (bytes_written < 0)
                {
                        printk ( KERN_DEBUG "Failed to write data.\n" );
                        filp_close(block_changes_file, NULL);
                        return;
                }

                totalBytes += bytes_written;

                kfree( dst );
        }

        printk ( KERN_DEBUG "total bytes_written %lu.\n", totalBytes );

        filp_close(block_changes_file, NULL);
        printk( KERN_DEBUG "Written and closed" );
}

void ExtractBio( struct bio* bio )
{
        int bioCount = 0;
        while( bio != NULL ) 
        {
                // printk(KERN_DEBUG "Bio Flag : %d\n", bio->bi_flags);
                // if( bio_flagged( bio, BIO_NO_PAGE_REF ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_NO_PAGE_REF set" );  
                // }
                // if( bio_flagged( bio, BIO_CLONED ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_CLONED set" );  
                // }
                // if( bio_flagged( bio, BIO_BOUNCED ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_BOUNCED set" );  
                // }
                // if( bio_flagged( bio, BIO_USER_MAPPED ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_USER_MAPPED set" );  
                // }
                // if( bio_flagged( bio, BIO_NULL_MAPPED ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_NULL_MAPPED set" );  
                // }
                // if( bio_flagged( bio, BIO_WORKINGSET ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_WORKINGSET set" );  
                // }
                // if( bio_flagged( bio, BIO_QUIET ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_QUIET set" );  
                // }
                // if( bio_flagged( bio, BIO_CHAIN ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_CHAIN set" );  
                // }
                // if( bio_flagged( bio, BIO_REFFED ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_REFFED set" );  
                // }
                // if( bio_flagged( bio, BIO_THROTTLED ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_THROTTLED set" );  
                // }
                // if( bio_flagged( bio, BIO_TRACE_COMPLETION ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_TRACE_COMPLETION set" );  
                // }
                // if( bio_flagged( bio, BIO_QUEUE_ENTERED ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_QUEUE_ENTERED set" );  
                // }
                // if( bio_flagged( bio, BIO_TRACKED ) )
                // {
                //         printk( KERN_DEBUG "BIO has BIO_TRACKED set" );  
                // }

                // printk(KERN_DEBUG "Bio opf : %d\n", bio->bi_opf);
                // if( bio_op( bio ) == REQ_OP_READ )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_READ" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_WRITE )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_WRITE" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_FLUSH )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_FLUSH" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_DISCARD )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_DISCARD" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_SECURE_ERASE )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_SECURE_ERASE" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_ZONE_RESET )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_ZONE_RESET" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_WRITE_SAME )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_WRITE_SAME" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_ZONE_RESET_ALL )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_ZONE_RESET_ALL" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_WRITE_ZEROES )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_WRITE_ZEROES" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_SCSI_IN )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_SCSI_IN" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_SCSI_OUT )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_SCSI_OUT" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_DRV_IN )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_DRV_IN" ); 
                // }
                // if( bio_op( bio ) == REQ_OP_DRV_OUT )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_OP_DRV_OUT" ); 
                // }

                // // REQ Flags
                // if( bio->bi_opf & REQ_FAILFAST_DEV )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_FAILFAST_DEV" ); 
                // }
                // if( bio->bi_opf & REQ_FAILFAST_TRANSPORT )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_FAILFAST_TRANSPORT" ); 
                // }
                // if( bio->bi_opf & REQ_FAILFAST_DRIVER )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_FAILFAST_DRIVER" ); 
                // }
                // if( bio->bi_opf & REQ_SYNC )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_SYNC" ); 
                // }
                // if( bio->bi_opf & REQ_META )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_META" ); 
                // }
                // if( bio->bi_opf & REQ_PRIO )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_PRIO" ); 
                // }
                // if( bio->bi_opf & REQ_NOMERGE )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_NOMERGE" ); 
                // }
                // if( bio->bi_opf & REQ_IDLE )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_IDLE" ); 
                // }
                // if( bio->bi_opf & REQ_INTEGRITY )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_INTEGRITY" ); 
                // }
                // if( bio->bi_opf & REQ_FUA )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_FUA" ); 
                // }
                // if( bio->bi_opf & REQ_PREFLUSH )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_PREFLUSH" ); 
                // }
                // if( bio->bi_opf & REQ_RAHEAD )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_RAHEAD" ); 
                // }
                // if( bio->bi_opf & REQ_BACKGROUND )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_BACKGROUND" ); 
                // }
                // if( bio->bi_opf & REQ_NOWAIT )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_NOWAIT" ); 
                // }
                // if( bio->bi_opf & REQ_NOWAIT_INLINE )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_NOWAIT_INLINE" ); 
                // }
                // if( bio->bi_opf & REQ_CGROUP_PUNT )
                // {
                //         printk( KERN_DEBUG "BIO is REQ_CGROUP_PUNT" ); 
                // }
                
                bioCount++;
                sector_t sector = bio->bi_iter.bi_sector;

                unsigned int num_sectors = bio_sectors(bio);

                int operation = bio_data_dir(bio);
                if( operation == READ )
                {
                        printk(KERN_DEBUG "This is read op\n");
                        printk(KERN_DEBUG "Read operation starting at sector %llu with size %u in bytes, covering %u sectors\n", sector, num_sectors*512, num_sectors);
                        printk(KERN_DEBUG "This read bio has %u number of bio_vec structures\n", bio->bi_vcnt);
                }
                else if( operation == WRITE )
                {
                        printk(KERN_DEBUG "This is write op\n");
                        printk(KERN_DEBUG "Write operation starting at sector %llu with size %u in bytes, covering %u sectors\n", sector, num_sectors*512, num_sectors);
                        printk(KERN_DEBUG "This write bio has %u number of bio_vec structures\n", bio->bi_vcnt);
                }
                else
                        return;

                struct bio_vec bvec;
                struct bvec_iter i;
                int bvecCount = 0;
                bio_for_each_segment( bvec, bio, i )
                {
                        sector_t sector = i.bi_sector;
                        unsigned int offset = bvec.bv_offset;
                        unsigned int length = bvec.bv_len;
                        unsigned long page_addr;
                        if( bvec.bv_page!=NULL )
                                page_addr = page_to_phys( bvec.bv_page );

                        printk(KERN_DEBUG "bvec[%d] sector = %llu length = %u, offset = %u Page_addr = %lx\n", bvecCount, sector, length, offset, page_addr );
                        bvecCount++;
                }

                if( operation == WRITE )
                {
                        printk( KERN_DEBUG "Current bio is a write bio. Initiating writing to file" );
                        spin_lock(&my_spinlock);
                        WriteToFile( bio );
                        spin_unlock(&my_spinlock);
                }

                bio = bio->bi_next;
        }
        printk( KERN_DEBUG "Got %d number of bios", bioCount );
}

#ifdef KERNEL_VERSION_5_9_OR_NEWER

void (*submit_bio_noacct_passthrough)(struct bio *) =
	(void(*)(struct bio *))((unsigned long)(submit_bio_noacct) +
        5);

void tracing_fn(struct bio* bio) 
{
        struct bio* initialBio = bio;
        #ifdef USE_BI_BDEV
        if( bio->bi_bdev == blkdev )
        #else
        // Assuming that there will be no partitions for the disk
        if( bio->bi_disk == blkdev->bd_disk )
        #endif
        {
                printk("Got tracking bdev");
                if( bio_data_dir(bio) == WRITE )
                {
                        ExtractBio( bio );
                }
        }
        else
        {
                printk("Got non tracking bdev, skipping...");
        }
        submit_bio_noacct_passthrough( initialBio );
}
#else
blk_qc_t misc_make_request_fn(struct request_queue *q, struct bio* bio) 
{
        struct bio* initialBio = bio;
        ExtractBio( bio );
        return original_make_request_fn( q, initialBio );
}
#endif

#ifdef KERNEL_VERSION_5_9_OR_NEWER
#ifdef HAS_FTRACE_OPS
static void notrace ftrace_handler_submit_bio_noacct(unsigned long ip,
        unsigned long parent_ip,
        struct ftrace_ops *fops,
        struct ftrace_regs *fregs)
{
        #ifdef USE_SET_INSTRUCTION_POINTER
        ftrace_regs_set_instruction_pointer( fregs, (unsigned long) tracing_fn );
        #else
        ftrace_instruction_pointer_set( fregs, (unsigned long) tracing_fn );
        #endif
}
#else
static void notrace ftrace_handler_submit_bio_noacct(unsigned long ip,
        unsigned long parent_ip,
        struct ftrace_ops *fops,
        struct pt_regs *fregs)
{
        fregs->ip = (unsigned long) tracing_fn;
}
#endif

unsigned char* funcname_submit_bio_noacct = "submit_bio_noacct";
struct ftrace_ops ops_submit_bio_noacct = {
	.func = ftrace_handler_submit_bio_noacct,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_PERMANENT | FTRACE_OPS_FL_IPMODIFY
};
#endif

void register_block_device(char *path)  {

        if ( path == NULL )
        {
                printk ("Block device path is empty.\n");
                return;
        }

        printk ("Will open %s.\n", path);

        #ifdef KERNEL_VERSION_5_9_OR_NEWER
        blkdev = blkdev_get_by_path( path, FMODE_READ, NULL );
        #else
        blkdev = lookup_bdev(path);
        #endif

        if ( blkdev == NULL || IS_ERR(blkdev) )
        {
                printk ("No such block device.\n");
                return;
        }

        printk ("Found block device %p\n", blkdev );

        #ifdef KERNEL_VERSION_5_9_OR_NEWER
        int ret = ftrace_set_filter(
                &ops_submit_bio_noacct,
                funcname_submit_bio_noacct,
                strlen(funcname_submit_bio_noacct),
                0);
        if (ret)
        {
                printk("Failed to ftrace_set_filter");
                return;
        }

        ret = register_ftrace_function(&ops_submit_bio_noacct);
        #else
        struct request_queue *blkdev_queue = NULL;
        blkdev_queue = blkdev->bd_queue;

        if( !blkdev_queue )
        {
                printk ("Block dev queue is NULL.\n");
                return; 
        }

        original_make_request_fn = blkdev_queue->make_request_fn;
        if( original_make_request_fn == NULL )
        {
                printk("Got NULL for original_make_request_fn");
        }

        blkdev_queue->make_request_fn = misc_make_request_fn;
        #endif
}

void unregister_block_device(void)
{
        #ifdef KERNEL_VERSION_5_9_OR_NEWER
        if( unregister_ftrace_function(&ops_submit_bio_noacct) )
        {
                printk ("Failed to unregister!\n");
        }
        blkdev_put( blkdev, FMODE_READ );
        #else
        struct request_queue *blkdev_queue = NULL;
        blkdev_queue = blkdev->bd_queue;
        if( blkdev_queue == NULL )
        {
                printk ("Blockdev queue is NULL.\n");
                return; 
        }

        if( ( blkdev_queue->make_request_fn != NULL ) && ( original_make_request_fn != NULL ) )
        {
                blkdev_queue->make_request_fn = original_make_request_fn;
        }
        #endif
        printk ("Successfully unregistered block device.\n");
}



int init_module(void)   {
        int retval = 0;
        static char *mischelp_name = "mischelp";

        misc_help.minor = MISC_MINOR;
        misc_help.name = mischelp_name;
        misc_help.fops = &misc_fops;
        retval = misc_register(&misc_help);

        if (retval)
                return retval;

        register_block_device(PATH);

        printk ("block tracer initialized successfully.\n");
        return 0;
}

void cleanup_module(void){
        unregister_block_device();

        misc_deregister(&misc_help);

        printk ("It's over for block tracer.. \n");
}
