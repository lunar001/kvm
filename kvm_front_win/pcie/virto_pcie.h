#ifndef _VIRTIO_PCIE_H_

#define _VIRTIO_PCIE_H_

#include <stddef.h>
#include <stdarg.h>
#include <ntddk.h>
#include <wdf.h>
#define NTSTRSAFE_LIB
#include <ntstrsafe.h>
#include <initguid.h> // required for GUID definitions
#include <wdmguid.h> // required for WMILIB_CONTEXT
#include <wmistr.h>
#include <wmilib.h>
#include <ntintsafe.h>


#ifndef u8
#define u8 UCHAR
#endif

#ifndef u16
#define u16 USHORT
#endif

#ifndef u32
#define u32 ULONG
#endif

#ifndef bool
#define bool INT
#endif

#include "virtio_pci.h"
#include "virtio.h"

#include "trace.h"

#define BUFFERLENGTH 8192

#define MAXNLEN   8192
#define QUEUE_DESCRIPTORS 128


#define PCIE_MEMORY	'PCIE'

#ifdef INDIRECT_SUPPORTED
#define MAX_PHYS_SEGMENTS       64
#else
#define MAX_PHYS_SEGMENTS       16
#endif
#define VIRTIO_MAX_SG           (3+MAX_PHYS_SEGMENTS)

DEFINE_GUID(VirtioPCIE_DEVINTERFACE_GUID, \
			0xd952c203, 0x56d4, 0x4289, 0x88, 0x92, 0xd4, 0x30, 0xf, 0x2a, 0x8, 0xd5);


EVT_WDF_DRIVER_DEVICE_ADD PCIE_EvtDeviceAdd;
EVT_WDF_INTERRUPT_ISR                           PCIE_EvtInterruptIsr;
EVT_WDF_INTERRUPT_DPC                           PCIE_EvtEInterruptDpc;
EVT_WDF_INTERRUPT_ENABLE                        PCIE_EvtInterruptEnable;
EVT_WDF_INTERRUPT_DISABLE                       PCIE_EvtInterruptDisable;






typedef struct virtio_pcie_outhdr {  
u32 type;   
u32 ioprio;    
u32 sector;
u32 real_len;
}pcie_outhdr, *ppcie_outhdr;


typedef struct {
	VirtIODevice        *pIODevice;
	bool                bPortMapped;
	PHYSICAL_ADDRESS    PortBasePA;
       ULONG               uPortLength;
	PVOID               pPortBase;
	WDFINTERRUPT	WdfInterrupt;
	struct virtqueue    *vq;
	WDFSPINLOCK         CVqLock; //自旋锁，先保留
	PVOID	config_page;			//配置信息页地址
	
	ULONG config_page_length;
    //准备缓冲区，保存应用层传递下来的数据
	PVOID pInputBuffer;
	PVOID pOutputBuffer;
	KEVENT packet_returned_event;   //中断事件
	BOOLEAN             DeviceOK;

	
} VIRTIOPCIE_DEVICE_DATA, *PVIRTIOPCIE_DEVICE_DATA;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(VIRTIOPCIE_DEVICE_DATA, GetXedd);


typedef struct Virtio_PCIE_Req {    
	pcie_outhdr  out_hdr;
       PVIRTIOPCIE_DEVICE_DATA pXedd;
	u8         status;    
	struct VirtIOBufferDescriptor sg[VIRTIO_MAX_SG];
}PCIE_REQ, *PPCIE_REQ;





NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
    );

static VOID
PCIE_EvtDriverUnload(WDFDRIVER Driver);

NTSTATUS
PCIE_EvtDeviceAdd(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit);

NTSTATUS
PCIE_EvtDevicePrepareHardware(
    IN WDFDEVICE Device,
    IN WDFCMRESLIST ResourcesRaw,
    IN WDFCMRESLIST ResourcesTranslated);


NTSTATUS
PCIE_EvtDeviceReleaseHardware(
    IN WDFDEVICE Device,
    IN WDFCMRESLIST ResourcesTranslated);

VOID
PCIE_EvtIoWrite(
    IN WDFQUEUE		Queue,
    IN WDFREQUEST	Request,
    IN size_t		Length
    );

VOID
PCIE_EvtIoRead(
    IN WDFQUEUE		Queue,
    IN WDFREQUEST	Request,
    IN size_t		Length
    );






BOOLEAN
PCIE_EvtInterruptIsr(
    IN WDFINTERRUPT Interrupt,
    IN ULONG MessageID);


VOID
PCIE_EvtInterruptDpc(
    IN WDFINTERRUPT Interrupt,
    IN WDFOBJECT AssociatedObject);


NTSTATUS
PCIE_EvtInterruptEnable(
    IN WDFINTERRUPT Interrupt,
    IN WDFDEVICE AssociatedDevice);

NTSTATUS
PCIE_EvtInterruptDisable(
    IN WDFINTERRUPT Interrupt,
    IN WDFDEVICE AssociatedDevice);


static
NTSTATUS
PCIEInitInterruptHandling(
    IN WDFDEVICE hDevice);



ULONG
PCIESendToBack(IN PVIRTIOPCIE_DEVICE_DATA pXedd,
							IN PVOID Buffer,
							ULONG Length);


static PPCIE_REQ PCIEAllocateReq(IN PVIRTIOPCIE_DEVICE_DATA pXedd);

VOID PCIEFreeReq(PPCIE_REQ  vbr);

#endif
