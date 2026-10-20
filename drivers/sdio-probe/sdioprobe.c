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
#include <ntstrsafe.h>

#define PROBE_TAG 'bPdS'
#define PROBE_VERSION 11

typedef struct _AP_ENT {
    UCHAR  Bssid[6];
    UCHAR  SsidLen;
    UCHAR  Ssid[32];
    SHORT  Rssi;
    USHORT Chanspec;
} AP_ENT;

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
    BOOLEAN                  BlockOk;
    BOOLEAN                  WinValid;
    ULONG                    TxSeq;
    ULONG                    FrCount;
    ULONG                    MbCount;
    ULONG                    SdBase;
    PUCHAR                   RxBuf;        /* 2048 bytes: one received SDPCM frame */
    ULONG                    ReqId;
    BOOLEAN                  RepGot;
    ULONG                    RepLen;
    ULONG                    RepStatus;
    UCHAR                    Rep[512];
    ULONG                    NIntr;
    ULONG                    NFrames;
    ULONG                    NEvents;
    BOOLEAN                  ScanDone;
    ULONG                    ApCount;
    AP_ENT                   Ap[24];
    ULONG                    CurWin;
    PUCHAR                   Bounce;       /* 512-byte non-paged bounce buffer for CMD53 bulk transfers */
    PMDL                     BounceMdl;
    ULONG                    NCores;
    ULONG                    CoreId[16];
    ULONG                    CoreBase[16];
    ULONG                    CoreWrap[16];
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

static NTSTATUS SetProp(_In_ PDEV_CTX Ctx, _In_ SDBUS_PROPERTY Prop, _In_ PVOID Buf, _In_ ULONG Len)
{
    SDBUS_REQUEST_PACKET p;
    RtlZeroMemory(&p, sizeof(p));
    p.RequestFunction = SDRF_SET_PROPERTY;
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


/* ---------- M3a: backplane access, clock init, core enumeration (read-only) ---- */

#define F1_SBADDRLOW   0x1000A
#define F1_SBADDRMID   0x1000B
#define F1_SBADDRHIGH  0x1000C
#define F1_CHIPCLKCSR  0x1000E
#define F1_SDIOPULLUP  0x1000F
#define CLK_FORCE_ALP          0x01
#define CLK_ALP_AVAIL_REQ      0x08
#define CLK_FORCE_HW_CLKREQ_OFF 0x20
#define CLK_ALP_AVAIL          0x40
#define CLK_HT_AVAIL           0x80
#define SI_ENUM_BASE           0x18000000UL

static NTSTATUS BpSetWindow(_In_ PDEV_CTX c, _In_ ULONG addr)
{
    ULONG bar = addr & 0xFFFF8000UL;
    UCHAR b;
    NTSTATUS st;

    if (c->WinValid && c->CurWin == bar) return STATUS_SUCCESS;
    st = Cmd52(c, c->Fn, F1_SBADDRLOW,  TRUE, (UCHAR)((bar >> 8)  & 0x80), &b);
    if (!NT_SUCCESS(st)) return st;
    st = Cmd52(c, c->Fn, F1_SBADDRMID,  TRUE, (UCHAR)((bar >> 16) & 0xFF), &b);
    if (!NT_SUCCESS(st)) return st;
    st = Cmd52(c, c->Fn, F1_SBADDRHIGH, TRUE, (UCHAR)((bar >> 24) & 0xFF), &b);
    if (!NT_SUCCESS(st)) return st;
    c->CurWin = bar;
    c->WinValid = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS BpRead32(_In_ PDEV_CTX c, _In_ ULONG addr, _Out_ PULONG v)
{
    NTSTATUS st = BpSetWindow(c, addr);
    *v = 0;
    if (!NT_SUCCESS(st)) return st;
    return Cmd53Read32(c, c->Fn, (addr & 0x7FFF) | 0x8000, v);   /* bit 15 = 32-bit access */
}

static VOID PutIdx(_In_ PDEV_CTX c, _In_ ULONG i, _In_ PCWSTR suffix, _In_ ULONG val)
{
    WCHAR name[32];
    if (NT_SUCCESS(RtlStringCchPrintfW(name, RTL_NUMBER_OF(name), L"Core%u_%ws", i, suffix))) Put(c, name, val);
}

/* Port of brcmf_sdio_buscoreprep(): ask for ALP, wait for it, force ALP, drop pull-ups. */
static VOID ClockInit(_In_ PDEV_CTX c)
{
    NTSTATUS st;
    UCHAR b = 0, clk = 0;
    ULONG i;

    Put(c, L"Stage", 10);
    st = Cmd52(c, c->Fn, F1_CHIPCLKCSR, TRUE, CLK_FORCE_HW_CLKREQ_OFF | CLK_ALP_AVAIL_REQ, &b);
    PutStep(c, L"Clk_Wr_St", st, L"Clk_Wr_Val", CLK_FORCE_HW_CLKREQ_OFF | CLK_ALP_AVAIL_REQ);
    if (!NT_SUCCESS(st)) return;

    st = Cmd52(c, c->Fn, F1_CHIPCLKCSR, FALSE, 0, &clk);
    PutStep(c, L"Clk_Rd_St", st, L"Clk_Rd_Val", clk);

    for (i = 0; i < 1000; i++) {                       /* up to ~1 s, 1 ms steps */
        st = Cmd52(c, c->Fn, F1_CHIPCLKCSR, FALSE, 0, &clk);
        if (NT_SUCCESS(st) && (clk & (CLK_ALP_AVAIL | CLK_HT_AVAIL))) break;
        {   LARGE_INTEGER t; t.QuadPart = -10 * 1000; KeDelayExecutionThread(KernelMode, FALSE, &t); }
    }
    PutStep(c, L"Alp_St", st, L"Alp_Val", clk);
    if (!(clk & (CLK_ALP_AVAIL | CLK_HT_AVAIL))) return;

    st = Cmd52(c, c->Fn, F1_CHIPCLKCSR, TRUE, CLK_FORCE_HW_CLKREQ_OFF | CLK_FORCE_ALP, &b);
    PutStep(c, L"ForceAlp_St", st, L"ForceAlp_Val", CLK_FORCE_HW_CLKREQ_OFF | CLK_FORCE_ALP);
    {   LARGE_INTEGER t; t.QuadPart = -10 * 1000; KeDelayExecutionThread(KernelMode, FALSE, &t); }
    st = Cmd52(c, c->Fn, F1_SDIOPULLUP, TRUE, 0, &b);
    PutStep(c, L"Pullup_St", st, L"Pullup_Val", 0);
}

/* EROM walker, ported from brcmf_chip_dmp_get_desc / _get_regaddr / _erom_scan. */
static NTSTATUS EromGet(_In_ PDEV_CTX c, _Inout_ PULONG ea, _Out_ PULONG val, _Out_opt_ PUCHAR type)
{
    NTSTATUS st = BpRead32(c, *ea, val);
    *ea += 4;
    if (!NT_SUCCESS(st)) return st;
    if (type != NULL) {
        *type = (UCHAR)(*val & 0xF);
        if ((*type & ~0x8) == 0x5) *type = 0x5;          /* address descriptor (32 or 64-bit) */
    }
    return STATUS_SUCCESS;
}

static NTSTATUS EromRegAddr(_In_ PDEV_CTX c, _Inout_ PULONG ea, _Out_ PULONG regbase, _Out_ PULONG wrapbase, _Out_ PBOOLEAN ok)
{
    UCHAR desc = 0, wraptype, stype, sztype;
    ULONG val, tmp, szdesc, guard = 0;
    NTSTATUS st;

    *regbase = 0; *wrapbase = 0; *ok = FALSE;

    st = EromGet(c, ea, &val, &desc);
    if (!NT_SUCCESS(st)) return st;
    if (desc == 0x3)      { wraptype = 3; }                          /* master port -> MWRAP */
    else if (desc == 0x5) { *ea -= 4; wraptype = 2; }                /* address     -> SWRAP */
    else                  { *ea -= 4; return STATUS_SUCCESS; }       /* unexpected  -> not ok */

    do {
        do {
            st = EromGet(c, ea, &val, &desc);
            if (!NT_SUCCESS(st)) return st;
            if (desc == 0xF) { *ea -= 4; return STATUS_SUCCESS; }    /* unexpected table end */
            if (++guard > 512) return STATUS_SUCCESS;
        } while (desc != 0x5 && desc != 0x1);

        if (desc == 0x1) { *ea -= 4; *ok = TRUE; return STATUS_SUCCESS; }   /* next component reached */

        if (val & 0x8) { st = EromGet(c, ea, &tmp, NULL); if (!NT_SUCCESS(st)) return st; }
        sztype = (UCHAR)((val & 0x30) >> 4);
        if (sztype == 3) {
            st = EromGet(c, ea, &szdesc, NULL);
            if (!NT_SUCCESS(st)) return st;
            if (szdesc & 0x8) { st = EromGet(c, ea, &tmp, NULL); if (!NT_SUCCESS(st)) return st; }
        }
        if (sztype != 0 && sztype != 1) continue;          /* only 4K / 8K regions */

        stype = (UCHAR)((val & 0xC0) >> 6);
        if (*regbase == 0 && stype == 0)        *regbase  = val & 0xFFFFF000UL;
        if (*wrapbase == 0 && stype == wraptype) *wrapbase = val & 0xFFFFF000UL;
    } while (*regbase == 0 || *wrapbase == 0);

    *ok = TRUE;
    return STATUS_SUCCESS;
}

static VOID EromScan(_In_ PDEV_CTX c)
{
    ULONG ea = 0, val, id, nmw, nsw, rev, base, wrap, ncores = 0, guard = 0;
    UCHAR type = 0;
    BOOLEAN ok;
    NTSTATUS st;

    Put(c, L"Stage", 20);
    st = BpRead32(c, SI_ENUM_BASE + 0xFC, &ea);               /* chipcommon.eromptr */
    PutStep(c, L"Erom_St", st, L"Erom_Ptr", ea);
    if (!NT_SUCCESS(st) || ea == 0 || ea == 0xFFFFFFFF) return;

    Put(c, L"Stage", 21);
    while (type != 0xF && ++guard < 4096) {
        st = EromGet(c, &ea, &val, &type);
        if (!NT_SUCCESS(st)) break;
        if (!(val & 0x1)) continue;                            /* DMP_DESC_VALID */
        if (type != 0x1) continue;                             /* need a component descriptor */

        id = (val & 0x000FFF00UL) >> 8;
        st = EromGet(c, &ea, &val, &type);
        if (!NT_SUCCESS(st)) break;
        if ((val & 0xF) != 0x1) break;                         /* next must be a component too */

        nmw = (val & 0x0007C000UL) >> 14;
        nsw = (val & 0x00F80000UL) >> 19;
        rev = (val & 0xFF000000UL) >> 24;
        if (nmw + nsw == 0 && id != 0x827 && id != 0x840) continue;   /* only cores with ports (+PMU, GCI) */

        st = EromRegAddr(c, &ea, &base, &wrap, &ok);
        if (!NT_SUCCESS(st)) break;
        if (!ok) continue;

        if (ncores < 16) {
            c->CoreId[ncores] = id; c->CoreBase[ncores] = base; c->CoreWrap[ncores] = wrap;
            PutIdx(c, ncores, L"Id", id);
            PutIdx(c, ncores, L"Base", base);
            PutIdx(c, ncores, L"Wrap", wrap);
            PutIdx(c, ncores, L"Rev", rev);
        }
        ncores++;
    }
    c->NCores = (ncores < 16) ? ncores : 16;
    Put(c, L"Cores_N", ncores);
    Put(c, L"Erom_End", ea);
    Put(c, L"Stage", 29);
}



/* ---------- M3b: firmware + NVRAM download, ARM CR4 start (one-shot, BootFw=1) ---- */

#define BCMA_IOCTL        0x408
#define BCMA_RESET_CTL    0x800
#define BCMA_IOCTL_CLK    0x0001
#define BCMA_IOCTL_FGC    0x0002
#define CR4_IOCTL_CPUHALT 0x0020
#define D11_PHYRESET      0x0008
#define D11_PHYCLKEN      0x0004
#define CORE_D11          0x812
#define CORE_CR4          0x83E
#define CORE_SDIODEV      0x829
#define RAMBASE_4345      0x198000UL
#define RAM_CHUNK         64

static NTSTATUS Cmd53Bounce(_In_ PDEV_CTX c, _In_ UCHAR fn, _In_ ULONG addr, _In_ ULONG len, _In_ BOOLEAN write, _In_ BOOLEAN inc)
{
    static const SDCMD_DESCRIPTOR dRead  = { SDCMD_IO_RW_EXTENDED, SDCC_STANDARD, SDTD_READ,  SDTT_SINGLE_BLOCK, SDRT_5 };
    static const SDCMD_DESCRIPTOR dWrite = { SDCMD_IO_RW_EXTENDED, SDCC_STANDARD, SDTD_WRITE, SDTT_SINGLE_BLOCK, SDRT_5 };
    SDBUS_REQUEST_PACKET p;
    SD_RW_EXTENDED_ARGUMENT a;

    RtlZeroMemory(&p, sizeof(p));
    a.u.AsULONG = 0;
    a.u.bits.Function = fn;
    a.u.bits.Address  = addr;
    a.u.bits.OpCode   = inc ? 1 : 0;           /* 0 = fixed address (FIFO) */
    a.u.bits.BlockMode = 0;
    a.u.bits.WriteToDevice = write ? 1 : 0;
    a.u.bits.Count    = (len >= 512) ? 0 : len;
    p.RequestFunction = SDRF_DEVICE_COMMAND;
    p.Parameters.DeviceCommand.CmdDesc  = write ? dWrite : dRead;
    p.Parameters.DeviceCommand.Argument = a.u.AsULONG;
    p.Parameters.DeviceCommand.Mdl      = c->BounceMdl;
    p.Parameters.DeviceCommand.Length   = len;
    return SdBusSubmitRequest(c->Bus.Context, &p);
}

static NTSTATUS BpWrite32(_In_ PDEV_CTX c, _In_ ULONG addr, _In_ ULONG val)
{
    NTSTATUS st = BpSetWindow(c, addr);
    if (!NT_SUCCESS(st)) return st;
    *(PULONG)c->Bounce = val;
    return Cmd53Bounce(c, c->Fn, (addr & 0x7FFF) | 0x8000, 4, TRUE, TRUE);
}

static NTSTATUS RamWrite(_In_ PDEV_CTX c, _In_ ULONG addr, _In_reads_bytes_(len) const UCHAR *data, _In_ ULONG len)
{
    while (len != 0) {
        ULONG off = addr & 0x7FFF, n = 0x8000 - off;
        NTSTATUS st;
        if (n > len) n = len;
        if (n > RAM_CHUNK) n = RAM_CHUNK;
        st = BpSetWindow(c, addr);
        if (!NT_SUCCESS(st)) return st;
        RtlCopyMemory(c->Bounce, data, n);
        st = Cmd53Bounce(c, c->Fn, off, n, TRUE, TRUE);
        if (!NT_SUCCESS(st)) return st;
        addr += n; data += n; len -= n;
    }
    return STATUS_SUCCESS;
}

/* returns STATUS_SUCCESS and *Bad = 0xFFFFFFFF when identical, else *Bad = first mismatch offset */
static NTSTATUS RamVerify(_In_ PDEV_CTX c, _In_ ULONG addr, _In_reads_bytes_(len) const UCHAR *data, _In_ ULONG len, _Out_ PULONG Bad)
{
    ULONG done = 0;
    *Bad = 0xFFFFFFFF;
    while (done < len) {
        ULONG a = addr + done, off = a & 0x7FFF, n = 0x8000 - off;
        NTSTATUS st;
        if (n > len - done) n = len - done;
        if (n > RAM_CHUNK) n = RAM_CHUNK;
        st = BpSetWindow(c, a);
        if (!NT_SUCCESS(st)) return st;
        st = Cmd53Bounce(c, c->Fn, off, n, FALSE, TRUE);
        if (!NT_SUCCESS(st)) return st;
        if (RtlCompareMemory(c->Bounce, data + done, n) != n) {
            ULONG k = (ULONG)RtlCompareMemory(c->Bounce, data + done, n);
            *Bad = done + k;
            return STATUS_SUCCESS;
        }
        done += n;
    }
    return STATUS_SUCCESS;
}

static VOID CoreDisable(_In_ PDEV_CTX c, _In_ ULONG wrap, _In_ ULONG pre, _In_ ULONG reset)
{
    ULONG v = 0, i;
    (VOID)BpRead32(c, wrap + BCMA_RESET_CTL, &v);
    if ((v & 1) == 0) {
        (VOID)BpWrite32(c, wrap + BCMA_IOCTL, pre | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
        (VOID)BpRead32(c, wrap + BCMA_IOCTL, &v);
        (VOID)BpWrite32(c, wrap + BCMA_RESET_CTL, 1);
        KeStallExecutionProcessor(15);
        for (i = 0; i < 30; i++) {
            (VOID)BpRead32(c, wrap + BCMA_RESET_CTL, &v);
            if (v == 1) break;
            KeStallExecutionProcessor(10);
        }
    }
    (VOID)BpWrite32(c, wrap + BCMA_IOCTL, reset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
    (VOID)BpRead32(c, wrap + BCMA_IOCTL, &v);
}

static VOID CoreReset(_In_ PDEV_CTX c, _In_ ULONG wrap, _In_ ULONG pre, _In_ ULONG reset, _In_ ULONG post)
{
    ULONG v = 0, count = 0;
    CoreDisable(c, wrap, pre, reset);
    for (;;) {
        (VOID)BpRead32(c, wrap + BCMA_RESET_CTL, &v);
        if ((v & 1) == 0) break;
        (VOID)BpWrite32(c, wrap + BCMA_RESET_CTL, 0);
        if (++count > 50) break;
        KeStallExecutionProcessor(50);
    }
    (VOID)BpWrite32(c, wrap + BCMA_IOCTL, post | BCMA_IOCTL_CLK);
    (VOID)BpRead32(c, wrap + BCMA_IOCTL, &v);
}

static BOOLEAN FindCore(_In_ PDEV_CTX c, _In_ ULONG id, _In_ ULONG nth, _Out_ PULONG base, _Out_ PULONG wrap)
{
    ULONG i, seen = 0;
    for (i = 0; i < c->NCores; i++) {
        if (c->CoreId[i] == id) {
            if (seen == nth) { *base = c->CoreBase[i]; *wrap = c->CoreWrap[i]; return TRUE; }
            seen++;
        }
    }
    return FALSE;
}

static NTSTATUS ReadFileAll(_In_ PCWSTR path, _Outptr_ PUCHAR *out, _Out_ PULONG outLen)
{
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION fsi;
    HANDLE h = NULL;
    PUCHAR buf;
    ULONG size;
    NTSTATUS st;

    *out = NULL; *outLen = 0;
    RtlInitUnicodeString(&us, path);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwCreateFile(&h, GENERIC_READ | SYNCHRONIZE, &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
                      FILE_SHARE_READ, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(st)) return st;
    st = ZwQueryInformationFile(h, &iosb, &fsi, sizeof(fsi), FileStandardInformation);
    if (!NT_SUCCESS(st)) { ZwClose(h); return st; }
    if (fsi.EndOfFile.QuadPart <= 0 || fsi.EndOfFile.QuadPart > 0x400000) { ZwClose(h); return STATUS_FILE_INVALID; }
    size = (ULONG)fsi.EndOfFile.QuadPart;
    buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, size + 64, PROBE_TAG);
    if (buf == NULL) { ZwClose(h); return STATUS_INSUFFICIENT_RESOURCES; }
    st = ZwReadFile(h, NULL, NULL, NULL, &iosb, buf, size, NULL, NULL);
    ZwClose(h);
    if (!NT_SUCCESS(st)) { ExFreePoolWithTag(buf, PROBE_TAG); return st; }
    *out = buf; *outLen = size;
    return STATUS_SUCCESS;
}

static BOOLEAN IsNvChar(UCHAR ch) { return (ch >= 0x20 && ch < 0x7f && ch != '#'); }

/* simplified brcmf_fw_nvram_strip(): "key=value" lines -> NUL separated list, padded to 4, + length token */
static NTSTATUS BuildNvram(_In_reads_bytes_(inLen) const UCHAR *in, _In_ ULONG inLen, _Outptr_ PUCHAR *out, _Out_ PULONG outLen)
{
    PUCHAR o = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, inLen + 64, PROBE_TAG);
    ULONG pos = 0, n = 0, entry, token, words;
    BOOLEAN boardrev = FALSE;

    *out = NULL; *outLen = 0;
    if (o == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    while (pos < inLen) {
        UCHAR ch = in[pos];
        if (ch == ' ' || ch == '\r' || ch == '\t' || ch == '\n' || ch == 0) { pos++; continue; }
        if (ch == '#') { while (pos < inLen && in[pos] != '\n') pos++; continue; }
        if (!IsNvChar(ch)) { pos++; continue; }
        entry = pos;
        while (pos < inLen && in[pos] != '=') {
            if (!IsNvChar(in[pos]) || in[pos] == ' ') break;
            pos++;
        }
        if (pos >= inLen || in[pos] != '=') {                        /* invalid key: skip the line */
            while (pos < inLen && in[pos] != '\n') pos++;
            continue;
        }
        if (RtlCompareMemory(&in[entry], "RAW1", 4) == 4) {          /* ignored like Linux */
            while (pos < inLen && in[pos] != '\n') pos++;
            continue;
        }
        if (inLen - entry >= 8 && RtlCompareMemory(&in[entry], "boardrev", 8) == 8) boardrev = TRUE;
        pos++;                                                       /* skip '=' */
        while (pos < inLen && IsNvChar(in[pos])) pos++;
        RtlCopyMemory(&o[n], &in[entry], pos - entry);
        n += pos - entry;
        o[n++] = 0;
    }
    if (!boardrev) { static const char br[] = "boardrev=0xff"; RtlCopyMemory(&o[n], br, sizeof(br)); n += sizeof(br); }
    if (n == 0) { ExFreePoolWithTag(o, PROBE_TAG); return STATUS_FILE_INVALID; }

    {   ULONG padded = (n + 1 + 3) & ~3UL;
        while (n < padded) o[n++] = 0;
    }
    words = n / 4;
    token = (~words << 16) | (words & 0xFFFF);
    RtlCopyMemory(&o[n], &token, sizeof(token));
    n += sizeof(token);
    *out = o; *outLen = n;
    return STATUS_SUCCESS;
}


/* ---------- M4a: firmware shared struct + console log (read-only) ---------------- */

static NTSTATUS RamRead(_In_ PDEV_CTX c, _In_ ULONG addr, _Out_writes_bytes_(len) PUCHAR out, _In_ ULONG len)
{
    ULONG done = 0;
    while (done < len) {
        ULONG a = addr + done, off = a & 0x7FFF, n = 0x8000 - off;
        NTSTATUS st;
        if (n > len - done) n = len - done;
        if (n > RAM_CHUNK) n = RAM_CHUNK;
        st = BpSetWindow(c, a);
        if (!NT_SUCCESS(st)) return st;
        st = Cmd53Bounce(c, c->Fn, off, n, FALSE, TRUE);
        if (!NT_SUCCESS(st)) return st;
        RtlCopyMemory(out + done, c->Bounce, n);
        done += n;
    }
    return STATUS_SUCCESS;
}

/* store raw firmware text as a REG_SZ (printable ASCII + newlines only) */
static VOID PutStr(_In_ PDEV_CTX c, _In_ PCWSTR name, _In_reads_bytes_(len) const UCHAR *data, _In_ ULONG len)
{
    UNICODE_STRING nm;
    PWCHAR w;
    ULONG i, n = 0;

    if (c->Key == NULL) return;
    w = (PWCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, ((SIZE_T)len + 1) * sizeof(WCHAR), PROBE_TAG);
    if (w == NULL) return;
    for (i = 0; i < len; i++) {
        UCHAR ch = data[i];
        if (ch == '\n') w[n++] = L'\n';
        else if (ch >= 0x20 && ch < 0x7f) w[n++] = (WCHAR)ch;
    }
    w[n] = 0;
    RtlInitUnicodeString(&nm, name);
    (VOID)ZwSetValueKey(c->Key, &nm, 0, REG_SZ, w, (n + 1) * sizeof(WCHAR));
    (VOID)ZwFlushKey(c->Key);
    ExFreePoolWithTag(w, PROBE_TAG);
}

static BOOLEAN InRam(_In_ ULONG a) { return (a >= RAMBASE_4345 && a < RAMBASE_4345 + 0xC8000UL) ? TRUE : FALSE; }

static VOID DumpShared(_In_ PDEV_CTX c)
{
    ULONG sh = 0, flags, consoleAddr, bufAddr = 0, bufSize = 0, idx = 0;
    UCHAR hdr[64];
    PUCHAR buf = NULL, ordered = NULL;
    NTSTATUS st;

    Put(c, L"Stage", 40);
    st = BpRead32(c, RAMBASE_4345 + 0xC8000UL - 4, &sh);
    PutStep(c, L"Sh_Ptr_St", st, L"Sh_Addr", sh);
    if (!NT_SUCCESS(st) || sh == 0 || !InRam(sh) || ((~sh >> 16) & 0xFFFF) == (sh >> 16)) { Put(c, L"Sh_Valid", 0); return; }

    st = RamRead(c, sh, hdr, sizeof(hdr));
    PutStep(c, L"Sh_Rd_St", st, L"Sh_Valid", NT_SUCCESS(st) ? 1 : 0);
    if (!NT_SUCCESS(st)) return;

    flags = *(PULONG)&hdr[0];
    consoleAddr = *(PULONG)&hdr[20];
    Put(c, L"Sh_Flags", flags);                       /* low byte = shared version, 0x100 assert built, 0x200 assert, 0x400 trap */
    Put(c, L"Sh_Trap", *(PULONG)&hdr[4]);
    Put(c, L"Sh_AssertLine", *(PULONG)&hdr[16]);
    Put(c, L"Sh_Console", consoleAddr);
    PutStr(c, L"Sh_Tag", &hdr[28], 32);

    if (!InRam(consoleAddr)) return;
    st = RamRead(c, consoleAddr + 8, hdr, 12);          /* rte_console.log_le: buf, buf_size, idx */
    if (!NT_SUCCESS(st)) { Put(c, L"Con_St", (ULONG)st); return; }
    bufAddr = *(PULONG)&hdr[0]; bufSize = *(PULONG)&hdr[4]; idx = *(PULONG)&hdr[8];
    Put(c, L"Con_Buf", bufAddr); Put(c, L"Con_Size", bufSize); Put(c, L"Con_Idx", idx);
    if (bufSize == 0 || bufSize > 0x4000 || idx > bufSize || !InRam(bufAddr)) return;

    buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, (SIZE_T)bufSize * 2, PROBE_TAG);
    if (buf == NULL) return;
    ordered = buf + bufSize;
    st = RamRead(c, bufAddr, buf, bufSize);
    Put(c, L"Con_Rd_St", (ULONG)st);
    if (NT_SUCCESS(st)) {
        ULONG n = 0, i;
        if (idx < bufSize && buf[idx] != 0) {              /* ring has wrapped: oldest data starts at idx */
            for (i = idx; i < bufSize; i++) ordered[n++] = buf[i];
        }
        for (i = 0; i < idx; i++) ordered[n++] = buf[i];
        PutStr(c, L"Console", ordered, n);
    }
    ExFreePoolWithTag(buf, PROBE_TAG);
}

static VOID BootFirmware(_In_ PDEV_CTX c)
{
    PUCHAR fw = NULL, nv = NULL, nvraw = NULL;
    ULONG fwLen = 0, nvLen = 0, nvrawLen = 0;
    ULONG cr4Base = 0, cr4Wrap = 0, sdBase = 0, sdWrap = 0, d11Base = 0, d11Wrap = 0;
    ULONG corecap = 0, nab, nbb, idx, bx, blk, ramsize = 0, rambase = RAMBASE_4345, bad = 0, v = 0, rstvec;
    NTSTATUS st;
    UCHAR clk = 0, b;
    ULONG i;

    Put(c, L"Stage", 30);
    st = ReadFileAll(L"\\??\\C:\\rpiwin\\fw\\brcmfmac43456-sdio.bin", &fw, &fwLen);
    PutStep(c, L"Fw_Read_St", st, L"Fw_Len", fwLen);
    if (!NT_SUCCESS(st)) goto out;
    st = ReadFileAll(L"\\??\\C:\\rpiwin\\fw\\brcmfmac43456-sdio.txt", &nvraw, &nvrawLen);
    PutStep(c, L"Nv_Read_St", st, L"Nv_RawLen", nvrawLen);
    if (!NT_SUCCESS(st)) goto out;
    st = BuildNvram(nvraw, nvrawLen, &nv, &nvLen);
    PutStep(c, L"Nv_Build_St", st, L"Nv_Len", nvLen);
    if (!NT_SUCCESS(st)) goto out;

    if (!FindCore(c, CORE_CR4, 0, &cr4Base, &cr4Wrap) || !FindCore(c, CORE_SDIODEV, 0, &sdBase, &sdWrap)) {
        PutStep(c, L"Cores_St", STATUS_NOT_FOUND, L"Cores_Val", 0);
        goto out;
    }
    (VOID)FindCore(c, CORE_D11, 0, &d11Base, &d11Wrap);

    /* RAM size from the CR4 TCM banks (brcmf_chip_tcm_ramsize) */
    st = BpRead32(c, cr4Base + 0x04, &corecap);
    nab = corecap & 0xF; nbb = (corecap & 0xF0) >> 4;
    for (idx = 0; NT_SUCCESS(st) && idx < nab + nbb; idx++) {
        st = BpWrite32(c, cr4Base + 0x40, idx);
        if (!NT_SUCCESS(st)) break;
        st = BpRead32(c, cr4Base + 0x44, &bx);
        if (!NT_SUCCESS(st)) break;
        blk = 8192;
        if (bx & 0x200) blk >>= 3;
        ramsize += ((bx & 0x7F) + 1) * blk;
    }
    PutStep(c, L"Ram_St", st, L"Ram_Size", ramsize);
    Put(c, L"Ram_Cap", corecap);
    Put(c, L"Ram_Base", rambase);
    if (!NT_SUCCESS(st) || ramsize < 0x10000 || ramsize > 0x400000 || fwLen + nvLen > ramsize) goto out;

    /* set_passive: halt the ARM, disable D11 */
    Put(c, L"Stage", 31);
    (VOID)BpRead32(c, cr4Wrap + BCMA_IOCTL, &v);
    v &= CR4_IOCTL_CPUHALT;
    CoreReset(c, cr4Wrap, v, CR4_IOCTL_CPUHALT, CR4_IOCTL_CPUHALT);
    if (d11Wrap != 0) CoreDisable(c, d11Wrap, D11_PHYRESET | D11_PHYCLKEN, D11_PHYCLKEN);
    (VOID)BpRead32(c, cr4Wrap + BCMA_IOCTL, &v);
    Put(c, L"Cr4_Ioctl", v);

    /* firmware image at rambase */
    Put(c, L"Stage", 32);
    st = RamWrite(c, rambase, fw, fwLen);
    PutStep(c, L"Fw_Wr_St", st, L"Fw_Wr_Val", fwLen);
    if (!NT_SUCCESS(st)) goto out;
    Put(c, L"Stage", 33);
    st = RamVerify(c, rambase, fw, fwLen, &bad);
    PutStep(c, L"Fw_Vf_St", st, L"Fw_Vf_Bad", bad);
    if (!NT_SUCCESS(st) || bad != 0xFFFFFFFF) goto out;

    /* NVRAM at the end of RAM */
    Put(c, L"Stage", 34);
    st = RamWrite(c, rambase + ramsize - nvLen, nv, nvLen);
    PutStep(c, L"Nv_Wr_St", st, L"Nv_Wr_Addr", rambase + ramsize - nvLen);
    if (!NT_SUCCESS(st)) goto out;
    st = RamVerify(c, rambase + ramsize - nvLen, nv, nvLen, &bad);
    PutStep(c, L"Nv_Vf_St", st, L"Nv_Vf_Bad", bad);
    if (!NT_SUCCESS(st) || bad != 0xFFFFFFFF) goto out;

    /* set_active: clear SDIO core interrupts, write reset vector at 0, release the ARM */
    Put(c, L"Stage", 35);
    rstvec = *(PULONG)fw;
    Put(c, L"Rstvec", rstvec);
    (VOID)BpWrite32(c, sdBase + 0x20, 0xFFFFFFFF);
    if (rstvec != 0) {
        st = RamWrite(c, 0, (const UCHAR *)&rstvec, sizeof(rstvec));
        PutStep(c, L"Rst_Wr_St", st, L"Rst_Wr_Val", rstvec);
    }
    CoreReset(c, cr4Wrap, CR4_IOCTL_CPUHALT, 0, 0);
    (VOID)BpRead32(c, cr4Wrap + BCMA_IOCTL, &v);
    Put(c, L"Cr4_Ioctl_After", v);

    /* does the firmware come up? ask for HT clock and wait (it needs the ARM running) */
    Put(c, L"Stage", 36);
    st = Cmd52(c, c->Fn, F1_CHIPCLKCSR, TRUE, 0x10 /* HT_AVAIL_REQ */, &b);
    for (i = 0; i < 2000; i++) {
        st = Cmd52(c, c->Fn, F1_CHIPCLKCSR, FALSE, 0, &clk);
        if (NT_SUCCESS(st) && (clk & CLK_HT_AVAIL)) break;
        {   LARGE_INTEGER t; t.QuadPart = -10 * 1000; KeDelayExecutionThread(KernelMode, FALSE, &t); }
    }
    PutStep(c, L"Ht_St", st, L"Ht_Val", clk);
    Put(c, L"Ht_Ms", i);

    /* firmware publishes its shared-memory pointer in the last RAM word (replacing the NVRAM token) */
    Put(c, L"Stage", 37);
    st = BpRead32(c, rambase + ramsize - 4, &v);
    PutStep(c, L"Shared_St", st, L"Shared_Val", v);
    {   LARGE_INTEGER t; t.QuadPart = -10 * 1000 * 500; KeDelayExecutionThread(KernelMode, FALSE, &t); }   /* 500 ms for fw init */
    DumpShared(c);
    Put(c, L"Stage", 39);

out:
    if (nv != NULL)    ExFreePoolWithTag(nv, PROBE_TAG);
    if (nvraw != NULL) ExFreePoolWithTag(nvraw, PROBE_TAG);
    if (fw != NULL)    ExFreePoolWithTag(fw, PROBE_TAG);
}



/* ---------- M4b: enable F2, SDPCM/BCDC "ver" ioctl, polling (no interrupts) ------- */

#define SD_INTSTATUS        0x20
#define SD_HOSTINTMASK      0x24
#define SD_TOSBMAILBOXDATA  0x48
#define I_HMB_FRAME_IND     0x40
#define I_CHIPACTIVE        0x20000000UL
#define HOSTINTMASK_VAL     (0xF0UL | I_CHIPACTIVE)
#define F1_WATERMARK        0x10008
#define F1_SLEEPCSR         0x1001F
#define BRCMF_C_GET_VAR     262

static VOID PutHex(_In_ PDEV_CTX c, _In_ PCWSTR name, _In_reads_bytes_(len) const UCHAR *data, _In_ ULONG len)
{
    static const char hexd[] = "0123456789abcdef";
    UCHAR txt[1100];
    ULONG i, n = 0;
    if (len > 256) len = 256;
    for (i = 0; i < len; i++) {
        txt[n++] = (UCHAR)hexd[data[i] >> 4];
        txt[n++] = (UCHAR)hexd[data[i] & 0xF];
        if ((i & 15) == 15) txt[n++] = '\n'; else if ((i & 3) == 3) txt[n++] = ' ';
    }
    PutStr(c, name, txt, n);
}

static NTSTATUS F2Write(_In_ PDEV_CTX c, _In_reads_bytes_(len) const UCHAR *data, _In_ ULONG len)
{
    NTSTATUS st = BpSetWindow(c, SI_ENUM_BASE);              /* F2 FIFO lives at chipcommon base, 4-byte access flag */
    if (!NT_SUCCESS(st)) return st;
    RtlCopyMemory(c->Bounce, data, len);
    return Cmd53Bounce(c, 2, (SI_ENUM_BASE & 0x7FFF) | 0x8000, len, TRUE, TRUE);
}

static NTSTATUS F2Read(_In_ PDEV_CTX c, _Out_writes_bytes_(len) PUCHAR out, _In_ ULONG len)
{
    NTSTATUS st = BpSetWindow(c, SI_ENUM_BASE);
    if (!NT_SUCCESS(st)) return st;
    st = Cmd53Bounce(c, 2, (SI_ENUM_BASE & 0x7FFF) | 0x8000, len, FALSE, FALSE);
    if (NT_SUCCESS(st)) RtlCopyMemory(out, c->Bounce, len);
    return st;
}

#define SD_TOSBMAILBOX      0x40
#define SD_TOHOSTMAILBOXDATA 0x4C
#define SMB_INT_ACK         0x2
#define I_HMB_HOST_INT      0x80
#define BRCMF_C_UP          2
#define BRCMF_C_SET_VAR     263
#define BRCMF_E_ESCAN_RESULT 69
#define RX_BUF_SIZE         2048

static ULONG Be32(const UCHAR *p) { return ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3]; }
static ULONG Le32(const UCHAR *p) { return p[0] | ((ULONG)p[1] << 8) | ((ULONG)p[2] << 16) | ((ULONG)p[3] << 24); }
static USHORT Le16(const UCHAR *p) { return (USHORT)(p[0] | (p[1] << 8)); }

static VOID HandleEvent(_In_ PDEV_CTX c, _In_reads_bytes_(plen) const UCHAR *p, _In_ ULONG plen)
{
    ULONG type, status, dlen;
    const UCHAR *d;

    if (plen < 14 + 10 + 48) return;                               /* eth + brcm hdr + event msg */
    type = Be32(p + 28); status = Be32(p + 32); dlen = Be32(p + 44);
    d = p + 72;
    if (c->NEvents < 12) { WCHAR n[16]; if (NT_SUCCESS(RtlStringCchPrintfW(n, 16, L"Ev%u", c->NEvents))) Put(c, n, (type << 8) | (status & 0xFF)); }
    c->NEvents++;
    if (type != BRCMF_E_ESCAN_RESULT) return;
    if (status == 0) c->ScanDone = TRUE;                           /* BRCMF_E_STATUS_SUCCESS: scan finished */
    if (dlen < 12 || 72 + dlen > plen) return;
    {
        ULONG cnt = Le16(d + 10), i, off = 12;
        for (i = 0; i < cnt && i < 4; i++) {
            const UCHAR *bss = d + off;
            ULONG blen, k;
            AP_ENT *ap;
            if (off + 82 > dlen) break;
            blen = Le32(bss + 4);
            if (blen < 82 || off + blen > dlen) break;
            for (k = 0; k < c->ApCount; k++) if (RtlCompareMemory(c->Ap[k].Bssid, bss + 8, 6) == 6) break;
            if (k < RTL_NUMBER_OF(c->Ap)) {
                ap = &c->Ap[k];
                RtlCopyMemory(ap->Bssid, bss + 8, 6);
                ap->SsidLen = bss[18] > 32 ? 32 : bss[18];
                RtlCopyMemory(ap->Ssid, bss + 19, ap->SsidLen);
                ap->Chanspec = Le16(bss + 72);
                ap->Rssi = (SHORT)Le16(bss + 78);
                if (k == c->ApCount) c->ApCount++;
            }
            off += blen;
        }
    }
}

/* Port of the essential parts of brcmf_sdio_dpc(): clear intstatus, ack the mailbox, read + dispatch frames. */
static VOID ServiceInts(_In_ PDEV_CTX c)
{
    ULONG v = 0, clear, mb = 0, sdBase = c->SdBase;
    PUCHAR rx = c->RxBuf;
    NTSTATUS st = BpRead32(c, sdBase + SD_INTSTATUS, &v);
    if (!NT_SUCCESS(st)) return;
    clear = v & HOSTINTMASK_VAL;
    if (clear == 0) return;
    c->NIntr++;
    (VOID)BpWrite32(c, sdBase + SD_INTSTATUS, clear);                 /* write-1-to-clear */

    if (v & I_HMB_HOST_INT) {
        st = BpRead32(c, sdBase + SD_TOHOSTMAILBOXDATA, &mb);
        (VOID)BpWrite32(c, sdBase + SD_TOSBMAILBOX, SMB_INT_ACK);
        if (c->MbCount < 6) { WCHAR n[16]; if (NT_SUCCESS(RtlStringCchPrintfW(n, 16, L"Mb%u", c->MbCount))) Put(c, n, mb); }
        c->MbCount++;
    }
    if (v & I_HMB_FRAME_IND) {
        ULONG len, cs, sw, chan, off, done;
        st = F2Read(c, rx, 64);
        if (!NT_SUCCESS(st)) { Put(c, L"F2Rx_Err", (ULONG)st); return; }
        c->NFrames++;
        len = Le16(rx); cs = Le16(rx + 2); sw = Le32(rx + 4);
        chan = (sw >> 8) & 0xF; off = sw >> 24;
        if (((len ^ cs) & 0xFFFF) != 0xFFFF || len < 12 || len > RX_BUF_SIZE) { PutHex(c, L"Rx_BadHex", rx, 64); return; }
        done = 64;
        while (done < len) {                                          /* rest of the frame, <=512 bytes per CMD53 */
            ULONG n = len - done;
            if (n > 512) n = 512;
            n = (n + 3) & ~3UL;
            if (done + n > RX_BUF_SIZE) break;
            st = F2Read(c, rx + done, n);
            if (!NT_SUCCESS(st)) { Put(c, L"F2Rx2_Err", (ULONG)st); return; }
            done += n;
        }
        if (len == 12) return;                                        /* credit-only frame */
        if (chan == 0) {                                              /* control reply */
            if (off >= 12 && off + 16 <= len) {
                ULONG flags = Le32(rx + off + 8);
                if ((flags >> 16) == (c->ReqId & 0xFFFF)) {
                    ULONG n = len - off - 16;
                    if (n > sizeof(c->Rep)) n = sizeof(c->Rep);
                    c->RepStatus = Le32(rx + off + 12);
                    c->RepLen = n;
                    RtlCopyMemory(c->Rep, rx + off + 16, n);
                    c->RepGot = TRUE;
                }
            }
        } else if (chan == 1) {                                       /* firmware event: BCDC hdr(4) + 4*data_offset + eth frame */
            if (off + 4 <= len) {
                ULONG pl = off + 4 + (ULONG)rx[off + 3] * 4;
                if (pl < len) HandleEvent(c, rx + pl, len - pl);
            }
        }
    }
}

static VOID Delay1ms(VOID) { LARGE_INTEGER t; t.QuadPart = -10 * 1000; KeDelayExecutionThread(KernelMode, FALSE, &t); }

/* One control-channel request/response. SET: payload = name\0 + data. GET: payload = name\0 (zero padded to outlen). */
static NTSTATUS CtlCall(_In_ PDEV_CTX c, _In_ ULONG cmd, _In_ BOOLEAN set, _In_reads_bytes_opt_(plen) const UCHAR *payload, _In_ ULONG plen, _In_ ULONG outlen, _In_ ULONG timeoutMs)
{
    UCHAR frame[512];
    ULONG dlen = set ? plen : (outlen > plen ? outlen : plen);
    ULONG total = 28 + dlen, sendlen, ms;
    NTSTATUS st;

    if (total > 504) return STATUS_BUFFER_TOO_SMALL;
    sendlen = (total + 7) & ~7UL;
    RtlZeroMemory(frame, sendlen);
    c->ReqId = (c->ReqId + 1) & 0xFFFF;
    *(PUSHORT)&frame[0] = (USHORT)sendlen;                           /* hw length = padded length (what the firmware accepted) */
    *(PUSHORT)&frame[2] = (USHORT)~sendlen;
    *(PULONG)&frame[4]  = (c->TxSeq & 0xFF) | (0UL << 8) | (12UL << 24);
    *(PULONG)&frame[8]  = 0;
    *(PULONG)&frame[12] = cmd;
    *(PULONG)&frame[16] = dlen;
    *(PULONG)&frame[20] = (c->ReqId << 16) | (set ? 2UL : 0UL);
    *(PULONG)&frame[24] = 0;
    if (plen != 0 && payload != NULL) RtlCopyMemory(&frame[28], payload, plen);
    c->RepGot = FALSE; c->RepLen = 0; c->RepStatus = 0;
    st = F2Write(c, frame, sendlen);
    if (!NT_SUCCESS(st)) return st;
    c->TxSeq = (c->TxSeq + 1) & 0xFF;
    for (ms = 0; ms < timeoutMs && !c->RepGot; ms++) { ServiceInts(c); if (!c->RepGot) Delay1ms(); }
    if (!c->RepGot) return STATUS_TIMEOUT;
    return (c->RepStatus == 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

/* name\0 + data -> payload buffer; returns length */
static ULONG BuildVar(_Out_writes_bytes_(cap) PUCHAR out, _In_ ULONG cap, _In_ const char *name, _In_reads_bytes_opt_(dlen) const UCHAR *data, _In_ ULONG dlen)
{
    ULONG n = 0;
    while (name[n] != 0 && n + 1 < cap) { out[n] = (UCHAR)name[n]; n++; }
    out[n++] = 0;
    if (data != NULL && n + dlen <= cap) { RtlCopyMemory(out + n, data, dlen); n += dlen; }
    return n;
}

static NTSTATUS VarGet(_In_ PDEV_CTX c, _In_ const char *name, _In_ ULONG outlen)
{
    UCHAR pl[64];
    ULONG n = BuildVar(pl, sizeof(pl), name, NULL, 0);
    return CtlCall(c, 262 /* GET_VAR */, FALSE, pl, n, outlen, 2000);
}

static NTSTATUS VarSet(_In_ PDEV_CTX c, _In_ const char *name, _In_reads_bytes_(dlen) const UCHAR *data, _In_ ULONG dlen)
{
    UCHAR pl[500];
    ULONG n = BuildVar(pl, sizeof(pl), name, data, dlen);
    return CtlCall(c, BRCMF_C_SET_VAR, TRUE, pl, n, 0, 3000);
}

static VOID LoadClm(_In_ PDEV_CTX c)
{
    PUCHAR clm = NULL;
    ULONG clmLen = 0, pos = 0, chunks = 0;
    NTSTATUS st;
    UCHAR buf[12 + 384];

    Put(c, L"Stage", 62);
    st = ReadFileAll(L"\\??\\C:\\rpiwin\\fw\\brcmfmac43456-sdio.clm_blob", &clm, &clmLen);
    PutStep(c, L"Clm_Read_St", st, L"Clm_Len", clmLen);
    if (!NT_SUCCESS(st)) return;
    while (pos < clmLen) {
        ULONG n = clmLen - pos, flag = (1UL << 12);                  /* DLOAD_HANDLER_VER << 12 */
        if (n > 384) n = 384;
        if (pos == 0) flag |= 0x2;                                    /* DL_BEGIN */
        if (pos + n >= clmLen) flag |= 0x4;                           /* DL_END   */
        RtlZeroMemory(buf, 12);
        *(PUSHORT)&buf[0] = (USHORT)flag;
        *(PUSHORT)&buf[2] = 2;                                        /* DL_TYPE_CLM */
        *(PULONG)&buf[4]  = n;
        *(PULONG)&buf[8]  = 0;                                        /* crc */
        RtlCopyMemory(&buf[12], clm + pos, n);
        st = VarSet(c, "clmload", buf, 12 + n);
        if (!NT_SUCCESS(st)) { PutStep(c, L"Clm_Chunk_St", st, L"Clm_Chunk_At", pos); break; }
        pos += n; chunks++;
    }
    Put(c, L"Clm_Chunks", chunks);
    if (pos >= clmLen) {
        st = VarGet(c, "clmload_status", 4);
        PutStep(c, L"Clm_Status_St", st, L"Clm_Status", c->RepLen >= 4 ? Le32(c->Rep) : 0xFFFFFFFF);
    }
    ExFreePoolWithTag(clm, PROBE_TAG);
}

static VOID RunScan(_In_ PDEV_CTX c)
{
    UCHAR p[8 + 64 + 2];
    ULONG i, ms;
    NTSTATUS st;

    Put(c, L"Stage", 66);
    RtlZeroMemory(p, sizeof(p));
    *(PULONG)&p[0]  = 1;                                              /* BRCMF_ESCAN_REQ_VERSION */
    *(PUSHORT)&p[4] = 1;                                              /* WL_ESCAN_ACTION_START   */
    *(PUSHORT)&p[6] = 0x1234;                                         /* sync id */
    /* brcmf_scan_params_le @8: ssid{len=0,ssid[32]} (36) | bssid[6] | bss_type | scan_type | nprobes | active | passive | home | channel_num */
    for (i = 0; i < 6; i++) p[8 + 36 + i] = 0xFF;                     /* broadcast bssid */
    p[8 + 42] = 2;                                                    /* DOT11_BSSTYPE_ANY */
    p[8 + 43] = 0;                                                    /* BRCMF_SCANTYPE_ACTIVE */
    *(PULONG)&p[8 + 44] = 0xFFFFFFFF;                                 /* nprobes     (-1) */
    *(PULONG)&p[8 + 48] = 0xFFFFFFFF;                                 /* active_time (-1) */
    *(PULONG)&p[8 + 52] = 0xFFFFFFFF;                                 /* passive_time(-1) */
    *(PULONG)&p[8 + 56] = 0xFFFFFFFF;                                 /* home_time   (-1) */
    *(PULONG)&p[8 + 60] = 0;                                          /* channel_num */
    c->ScanDone = FALSE; c->ApCount = 0;
    st = VarSet(c, "escan", p, sizeof(p));
    PutStep(c, L"Escan_St", st, L"Escan_Status", c->RepStatus);
    if (!NT_SUCCESS(st)) return;
    for (ms = 0; ms < 12000 && !c->ScanDone; ms++) { ServiceInts(c); if (!c->ScanDone) Delay1ms(); }
    Put(c, L"Scan_Done", c->ScanDone ? 1 : 0);
    Put(c, L"Scan_Ms", ms);
    Put(c, L"Ap_N", c->ApCount);
    for (i = 0; i < c->ApCount && i < 16; i++) {
        WCHAR n[24];
        if (NT_SUCCESS(RtlStringCchPrintfW(n, 24, L"Ap%u_Ssid", i)))  PutStr(c, n, c->Ap[i].Ssid, c->Ap[i].SsidLen);
        if (NT_SUCCESS(RtlStringCchPrintfW(n, 24, L"Ap%u_Bssid", i))) PutHex(c, n, c->Ap[i].Bssid, 6);
        if (NT_SUCCESS(RtlStringCchPrintfW(n, 24, L"Ap%u_Rssi", i)))  Put(c, n, (ULONG)(LONG)c->Ap[i].Rssi);
        if (NT_SUCCESS(RtlStringCchPrintfW(n, 24, L"Ap%u_Chan", i)))  Put(c, n, c->Ap[i].Chanspec);
    }
}

static VOID Ioctl4b(_In_ PDEV_CTX c)
{
    NTSTATUS st;
    UCHAR b = 0, rdy = 0;
    ULONG sdWrap = 0, i, scan = 0;

    Put(c, L"Stage", 50);
    c->FrCount = 0; c->MbCount = 0; c->NIntr = 0; c->NFrames = 0; c->NEvents = 0; c->ReqId = 0x100;
    if (!FindCore(c, CORE_SDIODEV, 0, &c->SdBase, &sdWrap)) { Put(c, L"F2_Cores", 0); return; }

    (VOID)Cmd52(c, c->Fn, F1_SLEEPCSR, TRUE, 0x01, &b);               /* KSO */
    st = BpWrite32(c, c->SdBase + SD_TOSBMAILBOXDATA, 4UL << 16);    /* host protocol version 4 */
    PutStep(c, L"F2_Mbx_St", st, L"F2_Mbx_Val", 4UL << 16);

    st = Cmd52(c, 0, 0x02, FALSE, 0, &b);
    if (NT_SUCCESS(st)) st = Cmd52(c, 0, 0x02, TRUE, (UCHAR)(b | 0x04), &b);
    PutStep(c, L"F2_En_St", st, L"F2_En_Val", b);
    for (i = 0; i < 100; i++) {
        NTSTATUS s2 = Cmd52(c, 0, 0x03, FALSE, 0, &rdy);
        if (NT_SUCCESS(s2) && (rdy & 0x04)) break;
        Delay100ms();
    }
    PutStep(c, L"F2_Rdy_St", STATUS_SUCCESS, L"F2_Rdy_Val", rdy);
    if (!(rdy & 0x04)) return;

    (VOID)Cmd52(c, 0, 0x210, TRUE, 0x00, &b);                         /* F2 block size 512 */
    (VOID)Cmd52(c, 0, 0x211, TRUE, 0x02, &b);
    st = BpWrite32(c, c->SdBase + SD_HOSTINTMASK, HOSTINTMASK_VAL);
    PutStep(c, L"F2_Mask_St", st, L"F2_Mask_Val", HOSTINTMASK_VAL);
    st = Cmd52(c, c->Fn, F1_WATERMARK, TRUE, 0x08, &b);
    PutStep(c, L"F2_Wm_St", st, L"F2_Wm_Val", 0x08);

    Put(c, L"Stage", 51);                                              /* service what the firmware already posted */
    for (i = 0; i < 300; i++) { ServiceInts(c); Delay1ms(); }
    Put(c, L"Pre_Intr", c->NIntr); Put(c, L"Pre_Frames", c->NFrames);

    Put(c, L"Stage", 60);
    st = VarGet(c, "ver", 128);
    PutStep(c, L"Ver_St", st, L"Ver_Len", c->RepLen);
    if (c->RepLen != 0) PutStr(c, L"Ioctl_Ver", c->Rep, c->RepLen);
    if (!NT_SUCCESS(st)) { Put(c, L"Stage", 61); return; }

    if (GetU32(c, L"Scan", &scan) && scan == 1) {
        Put(c, L"Scan", 0);                                            /* one-shot */
        LoadClm(c);

        st = VarGet(c, "cur_etheraddr", 6);
        PutStep(c, L"Mac_St", st, L"Mac_Len", c->RepLen);
        if (c->RepLen >= 6) PutHex(c, L"Mac", c->Rep, 6);

        {   UCHAR mask[18];                                            /* event_msgs: only E_ESCAN_RESULT (69) */
            RtlZeroMemory(mask, sizeof(mask));
            mask[BRCMF_E_ESCAN_RESULT / 8] |= (UCHAR)(1u << (BRCMF_E_ESCAN_RESULT % 8));
            st = VarSet(c, "event_msgs", mask, sizeof(mask));
            PutStep(c, L"EvMask_St", st, L"EvMask_Status", c->RepStatus);
        }

        st = CtlCall(c, BRCMF_C_UP, TRUE, NULL, 0, 0, 3000);
        PutStep(c, L"Up_St", st, L"Up_Status", c->RepStatus);

        RunScan(c);
        Put(c, L"Ev_Total", c->NEvents);
    }

    Put(c, L"Intr_Total", c->NIntr); Put(c, L"Frames_Total", c->NFrames);
    { LARGE_INTEGER t; t.QuadPart = -10 * 1000 * 300; KeDelayExecutionThread(KernelMode, FALSE, &t); }
    DumpShared(c);
    Put(c, L"Stage", 59);
}

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

    /* --- function block size: Linux/brcmfmac sets 64 on F1 before any CMD53.
     *     v3 showed P_FnBlk = 0 and a divide-by-zero bugcheck (0x7E, 0xC0000094) on the first CMD53. --- */
    {
        USHORT want = 64, got = 0;
        NTSTATUS sset, sget;
        sset = SetProp(Ctx, SDP_FUNCTION_BLOCK_LENGTH, &want, sizeof(want));
        PutStep(Ctx, L"BlkSet_St", sset, L"BlkSet_Val", want);
        sget = GetProp(Ctx, SDP_FUNCTION_BLOCK_LENGTH, &got, sizeof(got));
        PutStep(Ctx, L"BlkRd_St", sget, L"BlkRd_Val", got);
        Ctx->BlockOk = (NT_SUCCESS(sget) && got != 0) ? TRUE : FALSE;
    }

    /* --- backplane window -> 0x18000000 (ChipCommon), then read the 32-bit chip id --- */
    st = Cmd52(Ctx, fn, 0x1000A, TRUE, (UCHAR)((0x18000000UL >> 8)  & 0x80), &b);
    PutStep(Ctx, L"WinLo_St", st, L"WinLo_Val", b);
    st = Cmd52(Ctx, fn, 0x1000B, TRUE, (UCHAR)((0x18000000UL >> 16) & 0xFF), &b);
    PutStep(Ctx, L"WinMid_St", st, L"WinMid_Val", b);
    st = Cmd52(Ctx, fn, 0x1000C, TRUE, (UCHAR)((0x18000000UL >> 24) & 0xFF), &b);
    PutStep(Ctx, L"WinHi_St", st, L"WinHi_Val", b);

    /* offset 0 inside the window, 32-bit access flag (bit 15) */
    if (!Ctx->BlockOk) {
        /* never issue CMD53 with a zero function block size (divide-by-zero crash seen in v3) */
        PutStep(Ctx, L"Sig_St", (NTSTATUS)0xDEAD0001, L"Sig_Val", 0);
    } else {
        st = Cmd53Read32(Ctx, fn, 0x8000, &v32);
        PutStep(Ctx, L"Sig_St", st, L"Sig_Val", v32);
        if (NT_SUCCESS(st) && v32 != 0 && v32 != 0xFFFFFFFF) {
            Ctx->WinValid = FALSE;              /* window was programmed outside BpSetWindow */
            {
                UCHAR clk0 = 0;
                (VOID)Cmd52(Ctx, fn, F1_CHIPCLKCSR, FALSE, 0, &clk0);
                Put(Ctx, L"Clk_At_Start", clk0);
                if (!(clk0 & CLK_HT_AVAIL)) ClockInit(Ctx);     /* M3a: only on a cold chip; never touch clocks of a running firmware */
            }
            EromScan(Ctx);                      /* M3a: list the SoC cores (read-only)        */
            {
                ULONG bootfw = 0;
                if (GetU32(Ctx, L"BootFw", &bootfw) && bootfw == 1) {
                    Put(Ctx, L"BootFw", 0);         /* one-shot: never repeats on reboot */
                    Put(Ctx, L"BootFw_Ran", 1);
                    BootFirmware(Ctx);
                }
                if (GetU32(Ctx, L"ReadConsole", &bootfw) && bootfw == 1) {
                    Put(Ctx, L"ReadConsole", 0);
                    DumpShared(Ctx);
                }
                if (GetU32(Ctx, L"Ioctl", &bootfw) && bootfw == 1) {
                    Put(Ctx, L"Ioctl", 0);              /* one-shot */
                    Ioctl4b(Ctx);
                }
            }
        }
    }

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
    ctx->RxBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, RX_BUF_SIZE, PROBE_TAG);
    ctx->Bounce = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 512, PROBE_TAG);
    if (ctx->Bounce != NULL) {
        ctx->BounceMdl = IoAllocateMdl(ctx->Bounce, 512, FALSE, FALSE, NULL);
        if (ctx->BounceMdl != NULL) MmBuildMdlForNonPagedPool(ctx->BounceMdl);
    }
    if (ctx->XferBuf != NULL && ctx->XferMdl != NULL && ctx->Bounce != NULL && ctx->BounceMdl != NULL && ctx->RxBuf != NULL) {
        RunProbe(ctx);
    } else {
        Put(ctx, L"Probe_Done", 0xFFFFFFFF);
    }
    if (ctx->RxBuf != NULL) { ExFreePoolWithTag(ctx->RxBuf, PROBE_TAG); ctx->RxBuf = NULL; }
    if (ctx->BounceMdl != NULL) { IoFreeMdl(ctx->BounceMdl); ctx->BounceMdl = NULL; }
    if (ctx->Bounce != NULL) { ExFreePoolWithTag(ctx->Bounce, PROBE_TAG); ctx->Bounce = NULL; }
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
