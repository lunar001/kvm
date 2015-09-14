/*
 * Virtio Block Device
 *
 * Copyright IBM, Corp. 2007
 *
 * Authors:
 *  Anthony Liguori   <aliguori@us.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _QEMU_VIRTIO_PCIE_H
#define _QEMU_VIRTIO_PCIE_H

#include "virtio.h"
#include "hw/block-common.h"

/* from Linux's linux/virtio_blk.h */

/* The ID for virtio_block */
#define VIRTIO_ID_PCIE 3 

/* Feature bits */
#define VIRTIO_BLK_F_BARRIER    0       /* Does host support barriers? */
#define VIRTIO_BLK_F_SIZE_MAX   1       /* Indicates maximum segment size */
#define VIRTIO_BLK_F_SEG_MAX    2       /* Indicates maximum # of segments */
#define VIRTIO_BLK_F_GEOMETRY   4       /* Indicates support of legacy geometry */
#define VIRTIO_BLK_F_RO         5       /* Disk is read-only */
#define VIRTIO_BLK_F_BLK_SIZE   6       /* Block size of disk is available*/
#define VIRTIO_BLK_F_SCSI       7       /* Supports scsi command passthru */
/* #define VIRTIO_BLK_F_IDENTIFY   8       ATA IDENTIFY supported, DEPRECATED */
#define VIRTIO_BLK_F_WCE        9       /* write cache enabled */
#define VIRTIO_BLK_F_TOPOLOGY   10      /* Topology information is available */
#define VIRTIO_BLK_F_CONFIG_WCE 11      /* write cache configurable */

#define VIRTIO_BLK_ID_BYTES     20      /* ID string length */

struct virtio_pcie_config
{
    uint64_t capacity;
} QEMU_PACKED;

/* These two define direction. */
#define VIRTIO_BLK_T_IN         0
#define VIRTIO_BLK_T_OUT        1

/* This bit says it's a scsi command, not an actual read or write. */
#define VIRTIO_BLK_T_SCSI_CMD   2

/* Flush the volatile write cache */
#define VIRTIO_BLK_T_FLUSH      4

/* return the device ID string */
#define VIRTIO_BLK_T_GET_ID     8

/* Barrier before this op. */
#define VIRTIO_BLK_T_BARRIER    0x80000000

/* This is the first element of the read scatter-gather list. */
struct virtio_pcie_outhdr
{
    /* VIRTIO_BLK_T* */
    uint32_t type;
    /* io priority. */
    uint32_t ioprio;
    /* Sector (ie. 512 byte offset) */
    uint64_t sector;
    uint32_t rea_len;
};

#define VIRTIO_BLK_S_OK         0
#define VIRTIO_BLK_S_IOERR      1
#define VIRTIO_BLK_S_UNSUPP     2

/* This is the last element of the write scatter-gather list */
struct virtio_pcie_inhdr
{
    unsigned char status;
};


struct VirtIOPCIEConf
{
   
    uint32_t flag;//只是一个标记，不做他用

};

#define DEFINE_VIRTIO_BLK_FEATURES(_state, _field) \
        DEFINE_VIRTIO_COMMON_FEATURES(_state, _field), \
        DEFINE_PROP_BIT("config-wce", _state, _field, VIRTIO_BLK_F_CONFIG_WCE, true)

#endif
