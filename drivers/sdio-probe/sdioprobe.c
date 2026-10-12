/*
 * sdioprobe - minimal KMDF SDIO function driver (probe only).
 *
 * Binds to SD\VID_02d0&PID_a9a6&FN_1 (CYW43455 WiFi, backplane function) on the
 * Raspberry Pi 4/400. It talks to the sdbus driver (ntddsd.h) and records what it
 * finds in the device's "Device Parameters" registry key, so the result can be read
 * with PowerShell without a kernel debugger:
 *
 *   HKLM\SYSTEM\CurrentControlSet\Enum\SD\VID_02D0&PID_A9A6&FN_1\<inst>\Device Parameters
 *
 * Each step stores <name>_St (NTSTATUS) and <name>_Val. It never enables card
 * interrupts and never touches the WiFi firmware.
 *
 * Expected on a healthy chip (Linux brcmfmac reads the same): Sig_Val = 0x15294345.
 */
#include <ntddk.h>
#include <wdf.h>
#include <ntddsd.h>

#define PROBE_TAG 'bPdS'

typedef struct _DEV_CTX {
    WDFDEVICE                Device;
    SDBUS_INTERFACE_STANDARD Bus;
    BOOLEAN                  BusOpen;
    UCHAR                    Fn;
    PULONG                   XferBuf;      /* 4 bytes, non-paged, for CMD53 */
    PMDL                     XferMdl;
    WDFKEY                   Key;
} DEV_CTX, *PDEV_CTX;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEV_CTX, GetCtx)

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD       EvtDeviceAdd;
EVT_WDF_DEVICE_PREPARE_HARDWARE EvtPrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE EvtReleaseHardware;

static const SDCMD_DESCRIPTOR g_Cmd52Read  = { SDCMD_IO_RW_DIRECT,   SDCC_STANDARD, SDTD_READ,  SDTT_CMD_ONLY,      SDRT_5 };
static const SDCMD_DESCRIPTOR g_Cmd52Write = { SDCMD_IO_RW_DIRECT,   SDCC_STANDARD, SDTD_WRITE, SDTT_CMD_ONLY,      SDRT_5 };
static const SDCMD_DESCRIPTOR g_Cmd53Read  = { SDCMD_IO_RW_EXTENDED, SDCC_STANDARD, SDTD_READ,  SDTT_SINGLE_BLOCK,  SDRT_5 };

/* ---------- registry logging ------------------------------------------------ */

static VOID Put(_In_ PDEV_CTX Ctx, _In_ PCWSTR Name, _In_ ULONG Value)
{
    UNICODE_STRING n;
    if (Ctx->Key == NULL) return;
    RtlInitUnicodeString(&n, Name);
    (VOID)WdfRegistryAssignULong(Ctx->Key, &n, Value);
}

static VOID PutStep(_In_ PDEV_CTX Ctx, _In_ PCWSTR StName, _In_ NTSTATUS St,
                    _In_ PCWSTR ValName, _In_ ULONG Val)
{
    Put(Ctx, StName, (ULONG)St);
    Put(Ctx, ValName, Val);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "sdioprobe: %ws=0x%08x %ws=0x%08x\n",
               StName, (ULONG)St, ValName, Val);
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
}

/* ---------- WDF plumbing ------------------------------------------------------ */

NTSTATUS EvtPrepareHardware(_In_ WDFDEVICE Device, _In_ WDFCMRESLIST Raw, _In_ WDFCMRESLIST Trans)
{
    PDEV_CTX ctx = GetCtx(Device);
    NTSTATUS st;

    UNREFERENCED_PARAMETER(Raw);
    UNREFERENCED_PARAMETER(Trans);

    ctx->Key = NULL;
    st = WdfDeviceOpenRegistryKey(Device, PLUGPLAY_REGKEY_DEVICE, KEY_SET_VALUE | KEY_QUERY_VALUE,
                             WDF_NO_OBJECT_ATTRIBUTES, &ctx->Key);
    if (!NT_SUCCESS(st)) ctx->Key = NULL;

    ctx->XferBuf = (PULONG)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(ULONG), PROBE_TAG);
    if (ctx->XferBuf != NULL) {
        ctx->XferMdl = IoAllocateMdl(ctx->XferBuf, sizeof(ULONG), FALSE, FALSE, NULL);
        if (ctx->XferMdl != NULL) MmBuildMdlForNonPagedPool(ctx->XferMdl);
    }

    st = SdBusOpenInterface(WdfDeviceWdmGetPhysicalDevice(Device), &ctx->Bus,
                            sizeof(ctx->Bus), SDBUS_INTERFACE_VERSION);
    Put(ctx, L"Open_St", (ULONG)st);
    if (!NT_SUCCESS(st)) {
        ctx->BusOpen = FALSE;
        return STATUS_SUCCESS;   /* stay loaded; the registry says what happened */
    }
    ctx->BusOpen = TRUE;

    if (ctx->XferBuf != NULL && ctx->XferMdl != NULL) {
        RunProbe(ctx);
    } else {
        Put(ctx, L"Probe_Done", 0xFFFFFFFF);
    }
    return STATUS_SUCCESS;
}

NTSTATUS EvtReleaseHardware(_In_ WDFDEVICE Device, _In_ WDFCMRESLIST Trans)
{
    PDEV_CTX ctx = GetCtx(Device);
    UNREFERENCED_PARAMETER(Trans);

    if (ctx->BusOpen) {
        ctx->Bus.InterfaceDereference(ctx->Bus.Context);
        ctx->BusOpen = FALSE;
    }
    if (ctx->XferMdl != NULL) { IoFreeMdl(ctx->XferMdl); ctx->XferMdl = NULL; }
    if (ctx->XferBuf != NULL) { ExFreePoolWithTag(ctx->XferBuf, PROBE_TAG); ctx->XferBuf = NULL; }
    if (ctx->Key != NULL)     { WdfRegistryClose(ctx->Key); ctx->Key = NULL; }
    return STATUS_SUCCESS;
}

NTSTATUS EvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    WDF_PNPPOWER_EVENT_CALLBACKS pnp;
    WDF_OBJECT_ATTRIBUTES attrs;
    WDFDEVICE device;
    NTSTATUS st;

    UNREFERENCED_PARAMETER(Driver);

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnp);
    pnp.EvtDevicePrepareHardware = EvtPrepareHardware;
    pnp.EvtDeviceReleaseHardware = EvtReleaseHardware;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnp);

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attrs, DEV_CTX);
    st = WdfDeviceCreate(&DeviceInit, &attrs, &device);
    if (!NT_SUCCESS(st)) return st;

    GetCtx(device)->Device = device;
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG cfg;
    WDF_DRIVER_CONFIG_INIT(&cfg, EvtDeviceAdd);
    return WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &cfg, WDF_NO_HANDLE);
}
