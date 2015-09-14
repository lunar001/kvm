#include"virto_pcie.h"
VOID
PCIE_EvtIoWrite(
    IN WDFQUEUE		Queue,
    IN WDFREQUEST	Request,
    IN size_t		Length
    )
{
    NTSTATUS		status;
    WDFDEVICE		device;
    PVIRTIOPCIE_DEVICE_DATA pXedd;
    PVOID 	inputbuf;
    ULONG			length;

    // Get the memory buffer
    status = WdfRequestRetrieveInputBuffer(Request, Length,&inputbuf,NULL);
    if( !NT_SUCCESS(status) ) {
        WdfRequestComplete(Request, status);
        return;
    }

    device = WdfIoQueueGetDevice(Queue);
    pXedd= GetXedd(device);
    length = Length;
    if (length > MAXNLEN) length = MAXNLEN;

   //将应用程序的数据拷贝到pXedd缓冲区
 memcpy(pXedd->pInputBuffer,inputbuf,length);
	//交给后端处理
	//等待后端通知
//	DbgPrint("inputbuf:%s\n",pXedd->pInputBuffer);
   PCIESendToBack(pXedd,pXedd->pInputBuffer,length);
   KeWaitForSingleObject(&pXedd->packet_returned_event, Executive, KernelMode, FALSE, NULL);
 //  DbgPrint("after isr\n");
    WdfRequestCompleteWithInformation(Request, status, length);

    return;
}

VOID
PCIE_EvtIoRead(
    IN WDFQUEUE		Queue,
    IN WDFREQUEST	Request,
    IN size_t		Length
    )
{
	NTSTATUS          status;
	PVIRTIOPCIE_DEVICE_DATA 	  pXedd;
	 PVOID 	outputbuf;
	 ULONG			length;
	// DbgPrint("entry -->%s\n",__FUNCTION__);
	status = WdfRequestRetrieveOutputBuffer(Request,Length ,&outputbuf,NULL);
	if( !NT_SUCCESS(status) ) 
	{
	       WdfRequestComplete(Request, status);
		return;
	}

    pXedd = GetXedd(WdfIoQueueGetDevice(Queue));
   length = Length;   
   if (length > MAXNLEN) length = MAXNLEN;
   memcpy(outputbuf,pXedd->pInputBuffer,length);
 //  DbgPrint("outputbuf:%s\n",pXedd->pInputBuffer);
   WdfRequestCompleteWithInformation(Request, status, length);
   //DbgPrint("exit <---%s\n",__FUNCTION__);

   
    return;
}

static PPCIE_REQ 
PCIEAllocateReq(
	IN PVIRTIOPCIE_DEVICE_DATA pXedd)
{
	PPCIE_REQ vbr = NULL;
	vbr  = ExAllocatePoolWithTag(
		NonPagedPool,
		sizeof(PCIE_REQ),
		PCIE_MEMORY
		);
	if(!vbr)
		return NULL;
	vbr->pXedd  = pXedd;
	return vbr;
}


ULONG
PCIESendToBack(IN PVIRTIOPCIE_DEVICE_DATA pXedd,
							IN PVOID Buffer,
							ULONG Length)
{
	struct virtqueue * vq = pXedd->vq;
	struct VirtIOBufferDescriptor  sg[QUEUE_DESCRIPTORS];
	PVOID buffer = Buffer;
	ULONG length = Length;
	int out = 0;
	int in = 0;
	PPCIE_REQ  vbr =NULL;
	//DbgPrint("entry---->%s\n",__FUNCTION__);
	vbr =  PCIEAllocateReq(pXedd);
	if(vbr == NULL)
	{
		DbgPrint("vbr == NULL %s\n",__FUNCTION__);
		return 0;
	}
	//DbgPrint("vbr:%p\n",vbr);
	vbr->out_hdr.type = 1;
	vbr->out_hdr.ioprio = 2;
	vbr->out_hdr.sector = 4;
	vbr->out_hdr.real_len = length;
	vbr->status = 0;
	sg[out].physAddr= MmGetPhysicalAddress(&(vbr->out_hdr));
	sg[out].length= sizeof(pcie_outhdr);
	out++;
	sg[out].physAddr= MmGetPhysicalAddress(buffer);
	sg[out].length = length;
	out++;
	sg[out+in].physAddr = MmGetPhysicalAddress(&(vbr->status));
   	sg[out+in].length = sizeof(u8);
	in++;
	if(0 > virtqueue_add_buf(vq, sg, out, in, vbr, NULL, 0))
        { 
           DbgPrint("virtqueue_add_buf error %s\n",__FUNCTION__);
		 PCIEFreeReq(vbr);
		 return 0;
        }

    virtqueue_kick(vq);
   // DbgPrint("exit<----%s\n",__FUNCTION__);
    return length;
	
}


VOID PCIEFreeReq(PPCIE_REQ  vbr)
{
	if(vbr)
		ExFreePoolWithTag(vbr,PCIE_MEMORY);
	
}


//这个函数可以不需要
NTSTATUS
PCIEAddInReq(
    IN struct virtqueue *vq,
    IN PPCIE_REQ vbr)
{
    NTSTATUS  status = STATUS_SUCCESS;
    struct VirtIOBufferDescriptor sg[2];
    DbgPrint("entry---->%s\n,vbr=%p\n",__FUNCTION__,vbr);
   
    if (vbr == NULL)
    {
        ASSERT(0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (vq == NULL)
    {
        ASSERT(0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    memset(vbr->pXedd->pInputBuffer,'c',10);
   vbr->out_hdr.type = 2;
   vbr->out_hdr.ioprio = 4;
   vbr->out_hdr.sector = 2;
   vbr->out_hdr.real_len = 10;
   vbr->status = 0;
   sg[0].physAddr = MmGetPhysicalAddress(&(vbr->out_hdr));
   sg[0].length = sizeof(pcie_outhdr);
   //sg[1].physAddr = MmGetPhysicalAddress(vbr->pXedd->pInputBuffer);
   //sg[1].length = 10;
   sg[1].physAddr = MmGetPhysicalAddress(&(vbr->status));
   sg[1].length = sizeof(u8);
	//virtqueue_add_buf(vq, sg, out, 0, Buffer, NULL, 0);
//virtqueue_add_buf该上自旋锁
    if(0 > virtqueue_add_buf(vq, sg, 1, 1, vbr, NULL, 0))
    {
    	 DbgPrint("cant't not add_buf %s\n",__FUNCTION__);
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    virtqueue_kick(vq);
    DbgPrint("exit<----%s\n",__FUNCTION__);
  
    return status;
}





BOOLEAN
PCIE_EvtInterruptIsr(
    IN WDFINTERRUPT Interrupt,
    IN ULONG MessageID)
{
    PVIRTIOPCIE_DEVICE_DATA pXedd = GetXedd(WdfInterruptGetDevice(Interrupt));
    WDF_INTERRUPT_INFO info;
    BOOLEAN serviced ;
    //DbgPrint("entry--->%s\n",__FUNCTION__);


    WDF_INTERRUPT_INFO_INIT(&info);
    WdfInterruptGetInfo(Interrupt, &info);

    // Schedule a DPC if the device is using message-signaled interrupts, or
    // if the device ISR status is enabled.
    if (info.MessageSignaled || VirtIODeviceISR(pXedd->pIODevice))
    {
       // DbgPrint("info.MessageSignaled:%d\n",info.MessageSignaled);
        WdfInterruptQueueDpcForIsr(Interrupt);
        serviced = TRUE;
    }
    else
    {
        serviced = FALSE;
    }
 // DbgPrint("exit<---%s %d\n",__FUNCTION__,serviced);
    

    return TRUE;
}

VOID
PCIE_EvtEInterruptDpc(
    IN WDFINTERRUPT Interrupt,
    IN WDFOBJECT AssociatedObject)
{
    WDFDEVICE Device = WdfInterruptGetDevice(Interrupt);
    PVIRTIOPCIE_DEVICE_DATA pXedd = GetXedd(Device);
    int len = 0;
    struct virtqueue* vq = pXedd->vq;
	PPCIE_REQ vbr = NULL;

     //唤醒PCIE_EvtIoWrite,并且释放vbr
  //  DbgPrint("entry--->:%s\n",__FUNCTION__);

	
    if(vq)
    {
        //virtqueue_get_buf调用需要用自旋锁保护
	vbr = virtqueue_get_buf(vq,&len);
	//DbgPrint("vbr:%p\nlen =%d\n",vbr,len);
	PCIEFreeReq(vbr);
	KeSetEvent(&pXedd->packet_returned_event, 0, FALSE);
  }
	//DbgPrint("exit<---%s\n",__FUNCTION__);
    
return;
 
}


static
VOID
PCIEEnableInterrupt(PVIRTIOPCIE_DEVICE_DATA pXedd)
{
	DbgPrint("entry<---%s\n",__FUNCTION__);


    if(!pXedd)
    {
    	DbgPrint("pXedd == NULL %s\n",__FUNCTION__);
        return;
    }

    if(pXedd->vq)
    {
    	
        virtqueue_enable_cb(pXedd->vq);
        virtqueue_kick(pXedd->vq);
    }

    DbgPrint("exit<---%s\n",__FUNCTION__);
}

static
VOID
PCIEDisableInterrupt(PVIRTIOPCIE_DEVICE_DATA pXedd)
{
	DbgPrint("entry---> %s\n",__FUNCTION__);

  

    if(!pXedd)
        return;

    if(pXedd->vq)
    {
        virtqueue_disable_cb(pXedd->vq);
    }

    DbgPrint("exit<---%s\n",__FUNCTION__);
}


NTSTATUS
PCIE_EvtInterruptEnable(
    IN WDFINTERRUPT Interrupt,
    IN WDFDEVICE AssociatedDevice)
{
    UNREFERENCED_PARAMETER(AssociatedDevice);
   DbgPrint("entry---> %s\n",__FUNCTION__);
    
    PCIEEnableInterrupt(GetXedd(WdfInterruptGetDevice(Interrupt)));

   DbgPrint("exit<---%s\n",__FUNCTION__);
    return STATUS_SUCCESS;
}

NTSTATUS
PCIE_EvtInterruptDisable(
    IN WDFINTERRUPT Interrupt,
    IN WDFDEVICE AssociatedDevice)
{
    UNREFERENCED_PARAMETER(AssociatedDevice);
    DbgPrint("entry---->%s\n",__FUNCTION__); 
    
    PCIEDisableInterrupt(GetXedd(WdfInterruptGetDevice(Interrupt)));
    DbgPrint("exit<---%s\n",__FUNCTION__);
    return STATUS_SUCCESS;
}




NTSTATUS
PCIE_EvtDevicePrepareHardware(
    IN WDFDEVICE Device,
    IN WDFCMRESLIST ResourcesRaw,
    IN WDFCMRESLIST ResourcesTranslated)
{
    int nListSize = 0;
    PCM_PARTIAL_RESOURCE_DESCRIPTOR pResDescriptor;
    int i = 0;
    PVIRTIOPCIE_DEVICE_DATA  pXedd = GetXedd(Device);
    bool bPortFound = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    UINT nr_ports, max_queues, size_to_allocate;
    BOOLEAN MessageSignaled = FALSE;
    USHORT Interrupts = 0;
    u32 u32HostFeatures;
    u32 u32GuestFeatures = 0;
    WDF_OBJECT_ATTRIBUTES  attributes;

    UNREFERENCED_PARAMETER(ResourcesRaw);
    PAGED_CODE();
    DbgPrint("entry--->%s\n",__FUNCTION__);
  
    max_queues = 64; // 2 for each of max 32 ports
   
    size_to_allocate = VirtIODeviceSizeRequired((USHORT)max_queues);
    DbgPrint("size_to_allocate :%d\n",size_to_allocate);

    pXedd->pIODevice = ExAllocatePoolWithTag(
			NonPagedPool,
			size_to_allocate,
			PCIE_MEMORY);
    if (NULL == pXedd->pIODevice)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

	//分配缓冲区
    pXedd->pInputBuffer = ExAllocatePoolWithTag(
						NonPagedPool,
						BUFFERLENGTH,
						PCIE_MEMORY);
    if(pXedd->pInputBuffer == NULL)
    {
    	DbgPrint("Allocate pInputBuffer error\n");
	ExFreePoolWithTag(pXedd->pIODevice,PCIE_MEMORY);
	return STATUS_INSUFFICIENT_RESOURCES;
    }
    pXedd->pOutputBuffer  = ExAllocatePoolWithTag(
						 	NonPagedPool,
						 	BUFFERLENGTH,
						 	PCIE_MEMORY);
   if(NULL == pXedd->pOutputBuffer)
   {
   	DbgPrint("Allocate pOutputBuffer error\n");
	ExFreePoolWithTag(pXedd->pIODevice,PCIE_MEMORY);
	ExFreePoolWithTag(pXedd->pInputBuffer,PCIE_MEMORY);
	return STATUS_INSUFFICIENT_RESOURCES;
   }

    nListSize = WdfCmResourceListGetCount(ResourcesTranslated);
    DbgPrint("nListSize :%d\n",nListSize);

    for (i = 0; i < nListSize; i++)
    {
        if(pResDescriptor = WdfCmResourceListGetDescriptor(ResourcesTranslated, i))
        {
            switch(pResDescriptor->Type)
            {
                case CmResourceTypePort :
					DbgPrint("CmResourceTypePort\n");
                    pXedd->bPortMapped = (pResDescriptor->Flags & CM_RESOURCE_PORT_IO) ? FALSE : TRUE;
                    pXedd->PortBasePA = pResDescriptor->u.Port.Start;
                    pXedd->uPortLength = pResDescriptor->u.Port.Length;
		      DbgPrint("IO Port Info [%08I64X-%08I64X]\n",
			  	pResDescriptor->u.Port.Start.QuadPart,
                                 pResDescriptor->u.Port.Start.QuadPart +
                                 pResDescriptor->u.Port.Length);		
                  

                    if (pXedd->bPortMapped )
                    {
                        pXedd->pPortBase = MmMapIoSpace(pXedd->PortBasePA,
                                                           pXedd->uPortLength,
                                                           MmNonCached);
			 DbgPrint("first way\n");		

                        if (!pXedd->pPortBase) {
				DbgPrint("%s >>> Failed to map IO port!\n",__FUNCTION__);
				return STATUS_INSUFFICIENT_RESOURCES;
                        }
                    }
                    else
                    {
                        pXedd->pPortBase = (PVOID)(ULONG_PTR)pXedd->PortBasePA.QuadPart;
			   DbgPrint("Second way\n");	 		
                    }

                    bPortFound = TRUE;
			
                    break;
                case CmResourceTypeInterrupt:
			   DbgPrint("cmResourceTypeInterrupt\n");
			   DbgPrint("Interrupt Level:%08x,Vector:0x%08x\n",
			   pResDescriptor->u.Interrupt.Level,
                         pResDescriptor->u.Interrupt.Vector);
                    
                    Interrupts += 1;
                    MessageSignaled = !!(pResDescriptor->Flags &
                        (CM_RESOURCE_INTERRUPT_LATCHED | CM_RESOURCE_INTERRUPT_MESSAGE));
		     DbgPrint("before :MessageSignaled:%d Interrupts:%x.\n",MessageSignaled,Interrupts);
                    break;
            }
        }
    }

    if(!bPortFound)
    {
    	DbgPrint("%s>>>%s",__FUNCTION__,"IO port wasn't found!\n");
        
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    VirtIODeviceInitialize(pXedd->pIODevice, (ULONG_PTR)pXedd->pPortBase, size_to_allocate);
    VirtIODeviceSetMSIXUsed(pXedd->pIODevice, MessageSignaled);
    VirtIODeviceReset(pXedd->pIODevice);
    VirtIODeviceAddStatus(pXedd->pIODevice, VIRTIO_CONFIG_S_ACKNOWLEDGE);

   if (MessageSignaled)
    {
        WriteVirtIODeviceWord(
            pXedd->pIODevice->addr + VIRTIO_MSI_CONFIG_VECTOR, Interrupts);
        Interrupts= ReadVirtIODeviceWord(
            pXedd->pIODevice->addr + VIRTIO_MSI_CONFIG_VECTOR);
    }
    DbgPrint("after:MessageSignaled:%d Interrupts:%x.\n",MessageSignaled,Interrupts);



    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = Device;
    status = WdfSpinLockCreate(&attributes,
						     &pXedd->CVqLock	);
    if (!NT_SUCCESS(status))
     {
	  DbgPrint("WdfSpinLockCreate failed 0x%x\n", status);
	  return status;
     }


    u32HostFeatures = VirtIODeviceReadHostFeatures(pXedd->pIODevice);

    VirtIODeviceWriteGuestFeatures(pXedd->pIODevice, u32GuestFeatures);


    pXedd->DeviceOK = TRUE;
    DbgPrint("exit<---%s\n",__FUNCTION__);
   
    return status;
}

NTSTATUS
PCIE_EvtDeviceReleaseHardware(
    IN WDFDEVICE Device,
    IN WDFCMRESLIST ResourcesTranslated)
{
    PVIRTIOPCIE_DEVICE_DATA  pXedd = GetXedd(Device);

    UNREFERENCED_PARAMETER(ResourcesTranslated);
    PAGED_CODE();

    DbgPrint("entry %s\n",__FUNCTION__);
    if (pXedd->pPortBase && pXedd->bPortMapped)
    {
        MmUnmapIoSpace(pXedd->pPortBase, pXedd->uPortLength);
    }

    pXedd->pPortBase = (ULONG_PTR)NULL;


    if (pXedd->pIODevice)
    {
        ExFreePoolWithTag(pXedd->pIODevice, PCIE_MEMORY);
        pXedd->pIODevice = NULL;
    }

    if(pXedd->pInputBuffer) 
    {
    	ExFreePoolWithTag(pXedd->pInputBuffer,PCIE_MEMORY);
	pXedd->pInputBuffer = NULL;
    }
   if(pXedd->pOutputBuffer)
   {
   	ExFreePoolWithTag(pXedd->pOutputBuffer,PCIE_MEMORY);
	pXedd->pOutputBuffer = NULL;
   }
    DbgPrint("exit %s\n",__FUNCTION__);
    return STATUS_SUCCESS;
}

static struct virtqueue * FindVirtualQueue(VirtIODevice *dev, ULONG index, USHORT vector)
{
    struct virtqueue *pq = NULL;
    PVOID p;
    ULONG size, allocSize;
    DbgPrint("entry---> %s\n",__FUNCTION__);	
    VirtIODeviceQueryQueueAllocation(dev, index, &size, &allocSize);
    DbgPrint("allocSize:%d\n",allocSize);
    if (allocSize)
    {
        PHYSICAL_ADDRESS HighestAcceptable;
        HighestAcceptable.QuadPart = 0xFFFFFFFFFF;
        p = MmAllocateContiguousMemory(allocSize, HighestAcceptable);
        if (p)
        {
            DbgPrint("p:%p\n",p);
            pq = VirtIODevicePrepareQueue(dev, index, MmGetPhysicalAddress(p), p, allocSize, p, FALSE);
	    if(pq==NULL)
	    {
	    	DbgPrint("allocate queue error\n");
	    }
            if (vector != VIRTIO_MSI_NO_VECTOR)
            {
                WriteVirtIODeviceWord(dev->addr + VIRTIO_MSI_QUEUE_VECTOR, vector);
                vector = ReadVirtIODeviceWord(dev->addr + VIRTIO_MSI_QUEUE_VECTOR);
            }
        }
    }
    DbgPrint("exit<--- %s\n",__FUNCTION__);
    return pq;
}


static
NTSTATUS
PCIEInitInterruptHandling(
    IN WDFDEVICE hDevice)
{
    WDF_OBJECT_ATTRIBUTES        attributes;
    WDF_INTERRUPT_CONFIG         interruptConfig;
    PVIRTIOPCIE_DEVICE_DATA  pXedd = GetXedd(hDevice);
    NTSTATUS                     status = STATUS_SUCCESS;

    DbgPrint("Entry---->%s\n",__FUNCTION__);
    

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, VIRTIOPCIE_DEVICE_DATA);
    WDF_INTERRUPT_CONFIG_INIT(
                                 &interruptConfig,
                                PCIE_EvtInterruptIsr,
                                 PCIE_EvtEInterruptDpc
                                 );

    interruptConfig.EvtInterruptEnable = PCIE_EvtInterruptEnable;
    interruptConfig.EvtInterruptDisable = PCIE_EvtInterruptDisable;

    status = WdfInterruptCreate(
                                 hDevice,
                                 &interruptConfig,
                                 &attributes,
                                 &pXedd->WdfInterrupt
                                 );

    if (!NT_SUCCESS (status))
    {
    	DbgPrint("Create interrupt error %s\n",__FUNCTION__);

        return status;
    }

    DbgPrint("exit<---%s\n",__FUNCTION__);
  
    return status;
}

static
NTSTATUS
PCIEInitAllQueues(
    IN WDFOBJECT Device)
{
    NTSTATUS               status = STATUS_SUCCESS;
    PVIRTIOPCIE_DEVICE_DATA         pXedd = GetXedd(Device);
    UINT                   nr_ports, i, j;
    USHORT ControlVector, QueuesVector;
    WDF_INTERRUPT_INFO info;
    DbgPrint("entry--->%s\n",__FUNCTION__);
    
    WDF_INTERRUPT_INFO_INIT(&info);
    WdfInterruptGetInfo(pXedd->WdfInterrupt, &info);
    ControlVector = info.MessageSignaled ? 0 : VIRTIO_MSI_NO_VECTOR;
    DbgPrint("ControlVector:%d\n",ControlVector);

    if(pXedd->vq)
    	VirtIODeviceRenewQueue(pXedd->vq);
    else
		pXedd->vq = FindVirtualQueue(pXedd->pIODevice,0,ControlVector);
   if(pXedd->vq == NULL)
   {
   	DbgPrint("allocate vq error:%s\n",__FUNCTION__);
	 	
   }
   DbgPrint("exit<----%s\n",__FUNCTION__);	
		
   
   
        
   
    return status;
}

static void DeleteQueue(struct virtqueue **ppq)
{
    PVOID p;
    struct virtqueue *pq = *ppq;

  
    DbgPrint("entry--->%s\n",__FUNCTION__);

    if (pq)
    {
        VirtIODeviceDeleteQueue(pq, &p);
        *ppq = NULL;
        MmFreeContiguousMemory(p);
    }

    DbgPrint("exit<---%s\n",__FUNCTION__);
}

VOID PCIEShutDownAllQueues(IN WDFOBJECT WdfDevice)
{
    PVIRTIOPCIE_DEVICE_DATA pXedd = GetXedd(WdfDevice);
    UINT nr_ports, i;

   DbgPrint("entry--->%s\n",__FUNCTION__);
   VirtIODeviceRemoveStatus(pXedd->pIODevice , VIRTIO_CONFIG_S_DRIVER_OK);
   if(pXedd->vq)
	DeleteQueue(&pXedd->vq);
   DbgPrint("exit<---%s\n",__FUNCTION__);

}

NTSTATUS
PCIEFillQueue(
    IN struct virtqueue *vq,
    IN WDFSPINLOCK Lock,
    IN PVIRTIOPCIE_DEVICE_DATA pXedd
)
{
    NTSTATUS     status = STATUS_SUCCESS;

    PPCIE_REQ vbr = NULL;
    DbgPrint("entry--->%s\n",__FUNCTION__);

        
    vbr = PCIEAllocateReq(pXedd);
    if(vbr == NULL)
    {
           DbgPrint("PCIEAllocateReq failed %s\n",__FUNCTION__);
           
           return STATUS_INSUFFICIENT_RESOURCES;
     }
   DbgPrint("vbr:%p\n",vbr);
	if(vq == NULL)
	{
		DbgPrint("vq == NULL %s\n",__FUNCTION__);
		return STATUS_SUCCESS;
	}

        WdfSpinLockAcquire(Lock);

        status = PCIEAddInReq(vq, vbr);
        if(!NT_SUCCESS(status))
        {
         
	   PCIEFreeReq(vbr);
     
          DbgPrint("error happend:%s\n",__FUNCTION__);

        }
        WdfSpinLockRelease(Lock);

  DbgPrint("exit<---%s\n",__FUNCTION__);
    
    return STATUS_SUCCESS;
}


NTSTATUS
PCIE_EvtDeviceD0Entry(
    IN  WDFDEVICE Device,
    IN  WDF_POWER_DEVICE_STATE PreviousState
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PVIRTIOPCIE_DEVICE_DATA  pXedd = GetXedd(Device);

    UNREFERENCED_PARAMETER(PreviousState);

    DbgPrint("entry --->%s\n",__FUNCTION__);
    

    if(!pXedd->DeviceOK)
    {
        DbgPrint("Setting VIRTIO_CONFIG_S_FAILED flag\n");
        VirtIODeviceAddStatus(pXedd->pIODevice, VIRTIO_CONFIG_S_FAILED);
    }
    else
    {
        status = PCIEInitAllQueues(Device);//开始分配队列
       if (NT_SUCCESS(status) )
        {
            PCIEFillQueue(pXedd->vq, pXedd->CVqLock,pXedd);
        }
    }



    DbgPrint("exit <---%s\n",__FUNCTION__);	
    

    return status;
}

NTSTATUS
PCIE_EvtDeviceD0Exit(
    IN  WDFDEVICE Device,
    IN  WDF_POWER_DEVICE_STATE TargetState
    )
{
    PVIRTIOPCIE_DEVICE_DATA pXedd= GetXedd(Device);
    PPCIE_REQ  vbr = NULL;
    DbgPrint("entry --->%s\n",__FUNCTION__);
    PAGED_CODE();

    while ((vbr= (PPCIE_REQ)virtqueue_detach_unused_buf(pXedd->vq)))
    {
    	DbgPrint("vbr:%p\n",vbr);
        PCIEFreeReq(vbr);
    }

    PCIEShutDownAllQueues(Device);

    DbgPrint("exit <---%s\n",__FUNCTION__);
    return STATUS_SUCCESS;
}



NTSTATUS
PCIE_EvtDeviceAdd(
    IN WDFDRIVER Driver,
    IN PWDFDEVICE_INIT DeviceInit)
{
    NTSTATUS                     status = STATUS_SUCCESS;
    WDF_OBJECT_ATTRIBUTES        Attributes;
    WDFDEVICE                    hDevice;
    WDF_PNPPOWER_EVENT_CALLBACKS PnpPowerCallbacks;
    WDF_IO_QUEUE_CONFIG		ioQueueConfig;
    PVIRTIOPCIE_DEVICE_DATA                pXedd = NULL;

   DbgPrint("in function PCIE_EvtDeviceAdd\n");

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

  DbgPrint("entry--->%s\n",__FUNCTION__);

    
    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&PnpPowerCallbacks);
    PnpPowerCallbacks.EvtDevicePrepareHardware = PCIE_EvtDevicePrepareHardware;
    PnpPowerCallbacks.EvtDeviceReleaseHardware = PCIE_EvtDeviceReleaseHardware;
    PnpPowerCallbacks.EvtDeviceD0Entry         = PCIE_EvtDeviceD0Entry;
    PnpPowerCallbacks.EvtDeviceD0Exit          = PCIE_EvtDeviceD0Exit;
    
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &PnpPowerCallbacks);

    //创建Device,与设备扩展联系起来

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&Attributes, VIRTIOPCIE_DEVICE_DATA );
    status = WdfDeviceCreate(&DeviceInit, &Attributes, &hDevice);
    if (!NT_SUCCESS(status))
    {
    	DbgPrint("WdfDeviceCreate failed-0x%x\n",status);
        
        return status;
    } 
	
    pXedd = GetXedd(hDevice);
   
//创建中断对象
   status = PCIEInitInterruptHandling(hDevice);
    if(!NT_SUCCESS(status))
    {
       DbgPrint("PCIEInitInterruptHandling failed -0x%x\n",status);
        
    }
    KeInitializeEvent(&pXedd->packet_returned_event, SynchronizationEvent, FALSE);

//创建i/o处理队列
   WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig, WdfIoQueueDispatchSequential);

    ioQueueConfig.EvtIoWrite  = PCIE_EvtIoWrite;
    ioQueueConfig.EvtIoRead  = PCIE_EvtIoRead;

    status = WdfIoQueueCreate(hDevice, &ioQueueConfig, WDF_NO_OBJECT_ATTRIBUTES, NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
//创建与应用层通信的接口
    status = WdfDeviceCreateDeviceInterface(
                                 hDevice,
                                 &VirtioPCIE_DEVINTERFACE_GUID,
                                 NULL
                                 );
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, DBG_PNP, "WdfDeviceCreateDeviceInterface failed - 0x%x\n", status);
        return status;
    }

   TraceEvents(TRACE_LEVEL_INFORMATION, DBG_HW_ACCESS, "<-- %s\n", __FUNCTION__);
   DbgPrint("error not happend\n");
    return status;
}

static VOID
PCIE_EvtDriverUnload(WDFDRIVER Driver)
{
		DbgPrint("Driver unload\n");
		return ;
	
}

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
{
    WDF_DRIVER_CONFIG  config;
    NTSTATUS           status;
    DbgPrint("DriverEntry>>>>>>>\n");

    WDF_DRIVER_CONFIG_INIT(&config, PCIE_EvtDeviceAdd);
   config.EvtDriverUnload = PCIE_EvtDriverUnload;
    //
    // Create a framework driver object to represent our driver.
    //
    
    status = WdfDriverCreate(
        DriverObject,
        RegistryPath,
        WDF_NO_OBJECT_ATTRIBUTES,	// Driver Attributes
        &config,					// Driver Config Info
        WDF_NO_HANDLE				// hDriver
        );

    return status;
}
