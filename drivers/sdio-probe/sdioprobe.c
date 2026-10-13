/*
 * sdioprobe v3 - minimal WDM SDIO function driver (probe only).
 *
 * WHY WDM: KMDF FDOs query the PDO below them for GUID_REENUMERATE_SELF_INTERFACE_STANDARD;
 * sdbus.sys answers with its own (larger) SDBUS interface, which corrupts KMDF's FxPkgFdo and
 * crashes at removal in Wdf01000!FxPkgFdo::ReleaseReenumerationInterface (BAD_POOL_CALLER 0xC2/0x99).
 * Microsoft's SD function drivers are WDM for the same reason.
 *
 * Binds to SD\VID_02d0&PID_a9a6&FN_1 (CYW43455 backplane function) and records what it finds under
 *   HKLM\SYSTEM\CurrentControlSet\Enum\SD\VID_02D0&PID_A9A6&FN_1\<inst>\Device Parameters
 * Each step stores <name>_St (NTSTATUS) and <name>_Val. Expected chip signature: Sig_Val = 0x15294345.
 * Never enables card interrupts, never touches the WiFi firmware.
 */
#include <ntddk.h>
#include <initguid.h>   /* instantiate GUID_SDBUS_INTERFACE_STANDARD for sdbus.lib */
#include <ntddsd.h>

#define PROBE_TAG 'bPdS'
#define PROBE_VERSION 3

typedef struct _DEV_CTX {
    PDEVICE_OBJECT           Self;
    PDEVICE_OBJECT           Lower;
    PDEVICE_OBJECT           Pdo;
    IO_REMOVE_LOCK           RemoveLock;
    SDBUS_INTERFACE_STANDARD Bus;
    BOOLEAN                  BusOpen;
    NTSTATUS                 OpenSt;
    NTSTATUS                 InitSt;
    UCHAR                    Fn;
    HANDLE                   Key;
    PULONG                   XferBuf;
    PMDL                     XferMdl;
    volatile LONG            Removing;     /* probe must stop / not start */
    KEVENT                   WorkDone;     /* signaled when no probe work item is outstanding */
} DEV_CTX, *PDEV_CTX;

DRIVER_INITIALIZE   DriverEntry;
DRIVER_ADD_DEVICE   AddDevice;
DRIVER_DISPATCH     DispatchPnp;
DRIVER_DISPATCH     DispatchPower;
DRIVER_DISPATCH     DispatchPass;
IO_WORKITEM_ROUTINE ProbeWorker;
IO_COMPLETION_ROUTINE StartCompletion;

static const SDCMD_DESCRIPTOR g_Cmd52Read  = { SDCMD_IO_RW_DIRECT,   SDCC_STANDARD, SDTD_READ,  SDTT_CMD_ONLY,      SDRT_5 };
static const SDCMD_DESCRIPTOR g_Cmd52Write = { SDCMD_IO_RW_DIRECT,   SDCC_STANDARD, SDTD_WRITE, SDTT_CMD_ONLY,      SDRT_5 };
static const SDCMD_DESCRIPTOR g_Cmd53Read  = { SDCMD_IO_RW_EXTENDED, SDCC_STANDARD, SDTD_READ,  SDTT_SINGLE_BLOCK,  SDRT_5 };

/* ---------- registry logging (WDM) ------------------------------------------- */

static VOID Put(_In_ PDEV_CTX Ctx, _In_ PCWSTR Name, _In_ ULONG Value)
{
    UNICODE_STRING n;
    if (Ctx->Key == NULL) return;
    RtlInitUnicodeString(&n, Name);
    (VOID)ZwSetValueKey(Ctx->Key, &n, 0, REG_DWORD, &Value, sizeof(Value));
    (VOID)ZwFlushKey(Ctx->Key);          /* survive a bugcheck right after */
}

static BOOLEAN GetU32(_In_ PDEV_CTX Ctx, _In_ PCWSTR Name, _Out_ PULONG Value)
{
    UNICODE_STRING n;
    UCHAR buf[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buf;
    ULONG got = 0;

    *Value = 0;
    if (Ctx->Key == NULL) return FALSE;
    RtlInitUnicodeString(&n, Name);
    if (!NT_SUCCESS(ZwQueryValueKey(Ctx->Key, &n, KeyValuePartialInformation, info, sizeof(buf), &got))) return FALSE;
    if (info->Type != REG_DWORD || info->DataLength != sizeof(ULONG)) return FALSE;
    *Value = *(PULONG)info->Data;
    return TRUE;
}

static VOID PutStep(_In_ PDEV_CTX Ctx, _In_ PCWSTR StName, _In_ NTSTATUS St,
                    _In_ PCWSTR ValName, _In_ ULONG Val)
{
    Put(Ctx, StName, (ULONG)St);
    Put(Ctx, ValName, Val);
}

/* ---------- open / initialize / close the SD bus interface -------------------- */
/* Per Microsoft docs: open in AddDevice, InitializeInterface() after opening, close with
 * InterfaceDereference() on query-remove / surprise-removal / remove, zero the struct afterwards. */

static VOID CloseBus(_In_ PDEV_CTX Ctx)
{
    if (Ctx->BusOpen) {
        if (Ctx->Bus.InterfaceDereference != NULL) {
            Ctx->Bus.InterfaceDereference(Ctx->Bus.Context);
        }
        RtlZeroMemory(&Ctx->Bus, sizeof(Ctx->Bus));
        Ctx->BusOpen = FALSE;
    }
}

static NTSTATUS OpenBus(_In_ PDEV_CTX Ctx)
{
    SDBUS_INTERFACE_PARAMETERS ip;

    if (Ctx->BusOpen) return STATUS_SUCCESS;

    RtlZeroMemory(&Ctx->Bus, sizeof(Ctx->Bus));
    Ctx->OpenSt = SdBusOpenInterface(Ctx->Pdo, &Ctx->Bus, sizeof(Ctx->Bus), SDBUS_INTERFACE_VERSION);
    if (!NT_SUCCESS(Ctx->OpenSt)) {
        Ctx->InitSt = STATUS_UNSUCCESSFUL;
        return Ctx->OpenSt;
    }
    Ctx->BusOpen = TRUE;

    RtlZeroMemory(&ip, sizeof(ip));
    ip.Size = sizeof(ip);
    ip.TargetObject = Ctx->Lower;
    ip.DeviceGeneratesInterrupts = FALSE;     /* probe only: no card interrupts */
    ip.CallbackAtDpcLevel = FALSE;
    ip.CallbackRoutine = NULL;
    ip.CallbackRoutineContext = NULL;

    if (Ctx->Bus.InitializeInterface == NULL) {
        Ctx->InitSt = STATUS_UNSUCCESSFUL;
    } else {
        Ctx->InitSt = Ctx->Bus.InitializeInterface(Ctx->Bus.Context, &ip);
    }
    if (!NT_SUCCESS(Ctx->InitSt)) {
        CloseBus(Ctx);
        return Ctx->InitSt;
    }
    return STATUS_SUCCESS;
}

/* ---------- sdbus helpers ---------------------------------------------------- */

static NTSTATUS GetProp(_In_ PDEV_CTX Ctx, _In_ SDBUS_PROPERTY Prop, _In_ PVOID Buf, _In_ ULONG Len)
{
    SDBUS_REQUEST_PACKET p;
    RtlZeroMemory(&p, sizeof(p));
    p.RequestFunction = SDRF_GET_PROPERTY;
    p.Parameters.GetSetProperty.Property = Prop;
    p.Parameters.GetSetProperty.Buffer   = Buf;
    p.Parameters.GetSetProperty.Length   = Len;
    return SdBusSubmitRequest(Ctx->Bus.Context, &p);
}

static NTSTATUS Cmd52(_In_ PDEV_CTX Ctx, _In_ UCHAR Fn, _In_ ULONG Addr,
                      _In_ BOOLEAN Write, _In_ UCHAR WData, _Out_ PUCHAR RData)
{
    SDBUS_REQUEST_PACKET p;
    SD_RW_DIRECT_ARGUMENT a;
    NTSTATUS st;

    *RData = 0;
    RtlZeroMemory(&p, sizeof(p));
    a.u.AsULONG = 0;
    a.u.bits.Function = Fn;
    a.u.bits.Address  = Addr;
    a.u.bits.WriteToDevice = Write ? 1 : 0;
    a.u.bits.Data = Write ? WData : 0;

    p.RequestFunction = SDRF_DEVICE_COMMAND;
    p.Parameters.DeviceCommand.CmdDesc  = Write ? g_Cmd52Write : g_Cmd52Read;
    p.Parameters.DeviceCommand.Argument = a.u.AsULONG;

    st = SdBusSubmitRequest(Ctx->Bus.Context, &p);
    if (NT_SUCCESS(st)) *RData = p.ResponseData.AsUCHAR[0];
    return st;
}

static NTSTATUS Cmd53Read32(_In_ PDEV_CTX Ctx, _In_ UCHAR Fn, _In_ ULONG Addr, _Out_ PULONG Out)
{
    SDBUS_REQUEST_PACKET p;
    SD_RW_EXTENDED_ARGUMENT a;
    NTSTATUS st;

    *Out = 0;
    *Ctx->XferBuf = 0xDEADBEEF;
    RtlZeroMemory(&p, sizeof(p));
    a.u.AsULONG = 0;
    a.u.bits.Function = Fn;
    a.u.bits.Address  = Addr;
    a.u.bits.OpCode   = 1;          /* incrementing address */
    a.u.bits.BlockMode = 0;         /* byte mode */
    a.u.bits.WriteToDevice = 0;
    a.u.bits.Count    = 4;

    p.RequestFunction = SDRF_DEVICE_COMMAND;
    p.Parameters.DeviceCommand.CmdDesc  = g_Cmd53Read;
    p.Parameters.DeviceCommand.Argument = a.u.AsULONG;
    p.Parameters.DeviceCommand.Mdl      = Ctx->XferMdl;
    p.Parameters.DeviceCommand.Length   = 4;

    st = SdBusSubmitRequest(Ctx->Bus.Context, &p);
    if (NT_SUCCESS(st)) *Out = *Ctx->XferBuf;
    return st;
}

static VOID Delay100ms(VOID)
{
    LARGE_INTEGER t;
    t.QuadPart = -10 * 1000 * 100;   /* 100 ms */
    KeDelayExecutionThread(KernelMode, FALSE, &t);
}

/* ---------- the probe -------------------------------------------------------- */

static VOID RunProbe(_In_ PDEV_CTX Ctx)
{
    NTSTATUS st;
    UCHAR b = 0;
    ULONG v32 = 0;
    USHORT v16 = 0;
    UCHAR v8 = 0;
    UCHAR fn;
    ULONG i;

    /* --- properties from sdbus --- */
    st = GetProp(Ctx, SDP_FUNCTION_NUMBER, &v8, sizeof(v8));
    PutStep(Ctx, L"P_Fn_St", st, L"P_Fn_Val", v8);
    Ctx->Fn = NT_SUCCESS(st) ? v8 : 1;
    fn = Ctx->Fn;

    v32 = 0;
    st = GetProp(Ctx, SDP_FUNCTION_TYPE, &v32, sizeof(v32));
    PutStep(Ctx, L"P_Type_St", st, L"P_Type_Val", v32);

    v16 = 0;
    st = GetProp(Ctx, SDP_BUS_DRIVER_VERSION, &v16, sizeof(v16));
    PutStep(Ctx, L"P_DrvVer_St", st, L"P_DrvVer_Val", v16);

    v8 = 0;
    st = GetProp(Ctx, SDP_BUS_WIDTH, &v8, sizeof(v8));
    PutStep(Ctx, L"P_Width_St", st, L"P_Width_Val", v8);

    v32 = 0;
    st = GetProp(Ctx, SDP_BUS_CLOCK, &v32, sizeof(v32));
    PutStep(Ctx, L"P_Clock_St", st, L"P_Clock_Val", v32);

    v16 = 0;
    st = GetProp(Ctx, SDP_HOST_BLOCK_LENGTH, &v16, sizeof(v16));
    PutStep(Ctx, L"P_HostBlk_St", st, L"P_HostBlk_Val", v16);

    v16 = 0;
    st = GetProp(Ctx, SDP_FUNCTION_BLOCK_LENGTH, &v16, sizeof(v16));
    PutStep(Ctx, L"P_FnBlk_St", st, L"P_FnBlk_Val", v16);

    v16 = 0;
    st = GetProp(Ctx, SDP_FN0_BLOCK_LENGTH, &v16, sizeof(v16));
    PutStep(Ctx, L"P_Fn0Blk_St", st, L"P_Fn0Blk_Val", v16);

    /* --- CCCR (function 0) --- */
    {
        static const struct { PCWSTR St; PCWSTR Val; ULONG Addr; } cccr[] = {
            { L"C00_St", L"C00_Val", 0x00 },  /* CCCR / SDIO revision   */
            { L"C01_St", L"C01_Val", 0x01 },  /* SD spec revision       */
            { L"C02_St", L"C02_Val", 0x02 },  /* IO enable              */
            { L"C03_St", L"C03_Val", 0x03 },  /* IO ready               */
            { L"C04_St", L"C04_Val", 0x04 },  /* int enable             */
            { L"C07_St", L"C07_Val", 0x07 },  /* bus interface control  */
            { L"C08_St", L"C08_Val", 0x08 },  /* card capabilities      */
            { L"C13_St", L"C13_Val", 0x13 },  /* bus speed select       */
        };
        for (i = 0; i < RTL_NUMBER_OF(cccr); i++) {
            b = 0;
            st = Cmd52(Ctx, 0, cccr[i].Addr, FALSE, 0, &b);
            PutStep(Ctx, cccr[i].St, st, cccr[i].Val, b);
        }
    }

    /* --- FBR of our function: standard function interface code --- */
    b = 0;
    st = Cmd52(Ctx, 0, 0x100UL * fn, FALSE, 0, &b);
    PutStep(Ctx, L"Fbr_St", st, L"Fbr_Val", b);

    /* --- enable our function (CCCR IOEx) and wait for IORx --- */
    b = 0;
    st = Cmd52(Ctx, 0, 0x02, FALSE, 0, &b);
    if (NT_SUCCESS(st)) {
        UCHAR en = (UCHAR)(b | (1u << fn));
        st = Cmd52(Ctx, 0, 0x02, TRUE, en, &b);
    }
    PutStep(Ctx, L"En_St", st, L"En_Val", b);

    {
        UCHAR rdy = 0;
        for (i = 0; i < 10; i++) {
            NTSTATUS s2 = Cmd52(Ctx, 0, 0x03, FALSE, 0, &rdy);
            if (NT_SUCCESS(s2) && (rdy & (1u << fn))) break;
            Delay100ms();
        }
        PutStep(Ctx, L"Rdy_St", STATUS_SUCCESS, L"Rdy_Val", rdy);
    }

    /* --- backplane window -> 0x18000000 (ChipCommon), then read the 32-bit chip id --- */
    st = Cmd52(Ctx, fn, 0x1000A, TRUE, (UCHAR)((0x18000000UL >> 8)  & 0x80), &b);
    PutStep(Ctx, L"WinLo_St", st, L"WinLo_Val", b);
    st = Cmd52(Ctx, fn, 0x1000B, TRUE, (UCHAR)((0x18000000UL >> 16) & 0xFF), &b);
    PutStep(Ctx, L"WinMid_St", st, L"WinMid_Val", b);
    st = Cmd52(Ctx, fn, 0x1000C, TRUE, (UCHAR)((0x18000000UL >> 24) & 0xFF), &b);
    PutStep(Ctx, L"WinHi_St", st, L"WinHi_Val", b);

    /* offset 0 inside the window, 32-bit access flag (bit 15) */
    st = Cmd53Read32(Ctx, fn, 0x8000, &v32);
    PutStep(Ctx, L"Sig_St", st, L"Sig_Val", v32);

    Put(Ctx, L"Probe_Done", 1);
    Put(Ctx, L"ProbeState", 2);
}

/* ---------- WDM plumbing ------------------------------------------------------ */

static VOID DoProbe(_In_ PDEV_CTX ctx)
{
    NTSTATUS st;
    ULONG state = 0;

    ctx->Key = NULL;
    st = IoOpenDeviceRegistryKey(ctx->Pdo, PLUGPLAY_REGKEY_DEVICE, KEY_SET_VALUE | KEY_QUERY_VALUE, &ctx->Key);
    if (!NT_SUCCESS(st)) { ctx->Key = NULL; return; }

    /* Self-disarming: 1 = a previous run started but did not finish -> skip (no boot loops). */
    if (GetU32(ctx, L"ProbeState", &state) && state == 1) {
        Put(ctx, L"Skipped_Prev_Incomplete", 1);
        goto done;
    }
    Put(ctx, L"ProbeState", 1);
    Put(ctx, L"Skipped_Prev_Incomplete", 0);
    Put(ctx, L"Ver", PROBE_VERSION);

    st = OpenBus(ctx);                       /* no-op when AddDevice already opened it */
    Put(ctx, L"Open_St", (ULONG)ctx->OpenSt);
    Put(ctx, L"Init_St", (ULONG)ctx->InitSt);
    if (!NT_SUCCESS(st)) { Put(ctx, L"ProbeState", 2); goto done; }

    ctx->XferBuf = (PULONG)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ULONG), PROBE_TAG);
    if (ctx->XferBuf != NULL) {
        ctx->XferMdl = IoAllocateMdl(ctx->XferBuf, sizeof(ULONG), FALSE, FALSE, NULL);
        if (ctx->XferMdl != NULL) MmBuildMdlForNonPagedPool(ctx->XferMdl);
    }
    if (ctx->XferBuf != NULL && ctx->XferMdl != NULL) {
        RunProbe(ctx);
    } else {
        Put(ctx, L"Probe_Done", 0xFFFFFFFF);
    }
    if (ctx->XferMdl != NULL) { IoFreeMdl(ctx->XferMdl); ctx->XferMdl = NULL; }
    if (ctx->XferBuf != NULL) { ExFreePoolWithTag(ctx->XferBuf, PROBE_TAG); ctx->XferBuf = NULL; }

done:
    if (ctx->Key != NULL) { ZwClose(ctx->Key); ctx->Key = NULL; }
}

VOID ProbeWorker(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
    PIO_WORKITEM wi = (PIO_WORKITEM)Context;
    PDEV_CTX ctx = (PDEV_CTX)DeviceObject->DeviceExtension;
    ULONG i;

    for (i = 0; i < 10 && !ctx->Removing; i++) Delay100ms();   /* let the start IRP finish */
    if (!ctx->Removing) DoProbe(ctx);

    IoFreeWorkItem(wi);
    KeSetEvent(&ctx->WorkDone, IO_NO_INCREMENT, FALSE);
    IoReleaseRemoveLock(&ctx->RemoveLock, ctx);
}

static VOID QueueProbe(_In_ PDEVICE_OBJECT Dev, _In_ PDEV_CTX ctx)
{
    PIO_WORKITEM wi;

    if (ctx->Removing) return;
    if (!NT_SUCCESS(IoAcquireRemoveLock(&ctx->RemoveLock, ctx))) return;
    wi = IoAllocateWorkItem(Dev);
    if (wi == NULL) { IoReleaseRemoveLock(&ctx->RemoveLock, ctx); return; }
    KeClearEvent(&ctx->WorkDone);
    IoQueueWorkItem(wi, ProbeWorker, DelayedWorkQueue, wi);
}

static VOID Quiesce(_In_ PDEV_CTX ctx)
{
    InterlockedExchange(&ctx->Removing, 1);
    KeWaitForSingleObject(&ctx->WorkDone, Executive, KernelMode, FALSE, NULL);
    CloseBus(ctx);
}

NTSTATUS StartCompletion(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp, _In_opt_ PVOID Context)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS DispatchPass(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PDEV_CTX ctx = (PDEV_CTX)DeviceObject->DeviceExtension;
    NTSTATUS st = IoAcquireRemoveLock(&ctx->RemoveLock, Irp);
    if (!NT_SUCCESS(st)) {
        Irp->IoStatus.Status = st;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return st;
    }
    IoSkipCurrentIrpStackLocation(Irp);
    st = IoCallDriver(ctx->Lower, Irp);
    IoReleaseRemoveLock(&ctx->RemoveLock, Irp);
    return st;
}

NTSTATUS DispatchPower(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PDEV_CTX ctx = (PDEV_CTX)DeviceObject->DeviceExtension;
    NTSTATUS st = IoAcquireRemoveLock(&ctx->RemoveLock, Irp);
    if (!NT_SUCCESS(st)) {
        PoStartNextPowerIrp(Irp);
        Irp->IoStatus.Status = st;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return st;
    }
    PoStartNextPowerIrp(Irp);
    IoSkipCurrentIrpStackLocation(Irp);
    st = PoCallDriver(ctx->Lower, Irp);
    IoReleaseRemoveLock(&ctx->RemoveLock, Irp);
    return st;
}

NTSTATUS DispatchPnp(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
    PDEV_CTX ctx = (PDEV_CTX)DeviceObject->DeviceExtension;
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS st = IoAcquireRemoveLock(&ctx->RemoveLock, Irp);

    if (!NT_SUCCESS(st)) {
        Irp->IoStatus.Status = st;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return st;
    }

    switch (sp->MinorFunction) {

    case IRP_MN_START_DEVICE: {
        KEVENT ev;
        KeInitializeEvent(&ev, NotificationEvent, FALSE);
        IoCopyCurrentIrpStackLocationToNext(Irp);
        IoSetCompletionRoutine(Irp, StartCompletion, &ev, TRUE, TRUE, TRUE);
        st = IoCallDriver(ctx->Lower, Irp);
        if (st == STATUS_PENDING) {
            KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
            st = Irp->IoStatus.Status;
        }
        if (NT_SUCCESS(st)) QueueProbe(DeviceObject, ctx);
        Irp->IoStatus.Status = st;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        IoReleaseRemoveLock(&ctx->RemoveLock, Irp);
        return st;
    }

    case IRP_MN_QUERY_REMOVE_DEVICE:
    case IRP_MN_SURPRISE_REMOVAL:
        Quiesce(ctx);
        break;

    case IRP_MN_CANCEL_REMOVE_DEVICE:
        InterlockedExchange(&ctx->Removing, 0);
        (VOID)OpenBus(ctx);
        break;

    case IRP_MN_REMOVE_DEVICE:
        Quiesce(ctx);
        IoSkipCurrentIrpStackLocation(Irp);
        st = IoCallDriver(ctx->Lower, Irp);
        IoReleaseRemoveLockAndWait(&ctx->RemoveLock, Irp);
        IoDetachDevice(ctx->Lower);
        IoDeleteDevice(DeviceObject);
        return st;

    default:
        break;
    }

    IoSkipCurrentIrpStackLocation(Irp);
    st = IoCallDriver(ctx->Lower, Irp);
    IoReleaseRemoveLock(&ctx->RemoveLock, Irp);
    return st;
}

NTSTATUS AddDevice(_In_ PDRIVER_OBJECT DriverObject, _In_ PDEVICE_OBJECT PhysicalDeviceObject)
{
    PDEVICE_OBJECT fdo = NULL;
    PDEV_CTX ctx;
    NTSTATUS st;

    st = IoCreateDevice(DriverObject, sizeof(DEV_CTX), NULL, FILE_DEVICE_UNKNOWN,
                        FILE_DEVICE_SECURE_OPEN, FALSE, &fdo);
    if (!NT_SUCCESS(st)) return st;

    ctx = (PDEV_CTX)fdo->DeviceExtension;
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Self = fdo;
    ctx->Pdo  = PhysicalDeviceObject;
    IoInitializeRemoveLock(&ctx->RemoveLock, PROBE_TAG, 0, 0);
    KeInitializeEvent(&ctx->WorkDone, NotificationEvent, TRUE);

    ctx->Lower = IoAttachDeviceToDeviceStack(fdo, PhysicalDeviceObject);
    if (ctx->Lower == NULL) {
        IoDeleteDevice(fdo);
        return STATUS_DEVICE_REMOVED;
    }

    fdo->Flags |= (ctx->Lower->Flags & (DO_BUFFERED_IO | DO_DIRECT_IO | DO_POWER_PAGABLE));
    fdo->DeviceType = ctx->Lower->DeviceType;
    fdo->Characteristics = ctx->Lower->Characteristics;

    (VOID)OpenBus(ctx);                       /* documented place; the probe retries if this fails */

    fdo->Flags &= ~DO_DEVICE_INITIALIZING;
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    ULONG i;
    UNREFERENCED_PARAMETER(RegistryPath);

    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) DriverObject->MajorFunction[i] = DispatchPass;
    DriverObject->MajorFunction[IRP_MJ_PNP]   = DispatchPnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = DispatchPower;
    DriverObject->DriverExtension->AddDevice = AddDevice;
    return STATUS_SUCCESS;
}
