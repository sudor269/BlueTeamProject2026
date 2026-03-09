#pragma comment(lib, "fltmgr.lib")
#include <fltKernel.h>
#include <ntddstor.h>
#include <ntstrsafe.h>

#define TAG 'BSBU'
#define PORT_NAME L"\\UsbGuardPort"

PFLT_FILTER gFilter = NULL;
PFLT_PORT   gServerPort = NULL;
PFLT_PORT   gClientPort = NULL;

typedef struct _CTX {
    BOOLEAN IsUsb;
    BOOLEAN Allowed;
    UINT64  SerialHash;
    ULONG   PolicyVersion;
} CTX, * PCTX;

typedef struct _WHITELIST {
    UINT64* Items;
    ULONG   Count;
    ULONG   Version;
    EX_PUSH_LOCK Lock;
} WHITELIST;

typedef struct _POLICY_FLAGS {
    BOOLEAN AuditOnly;
    BOOLEAN DefaultAllowIfNoSerial;
} POLICY_FLAGS;

static WHITELIST gWl = { 0 };
static POLICY_FLAGS gPolicy = { FALSE, FALSE };

typedef enum _UG_CMD {
    UgCmdSetWhitelist = 1,
    UgCmdGetStatus = 2,
    UgCmdSetPolicy = 3
} UG_CMD;

#pragma pack(push, 1)

typedef struct _UG_MSG_HEADER {
    ULONG Command;
    ULONG Size;
} UG_MSG_HEADER;

typedef struct _UG_MSG_SET_WL {
    UG_MSG_HEADER Hdr;
    ULONG Version;
    ULONG Count;
} UG_MSG_SET_WL;

typedef struct _UG_MSG_SET_POLICY {
    UG_MSG_HEADER Hdr;
    UCHAR AuditOnly;
    UCHAR DefaultAllowIfNoSerial;
    UCHAR Reserved[2];
} UG_MSG_SET_POLICY;

typedef struct _UG_MSG_STATUS_REPLY {
    ULONG WlCount;
    ULONG WlVersion;
    UCHAR AuditOnly;
    UCHAR DefaultAllowIfNoSerial;
    UCHAR Reserved[2];
} UG_MSG_STATUS_REPLY;

#pragma pack(pop)

static VOID TrimSpaces(_Inout_ PWSTR s)
{
    size_t len;
    size_t start;
    size_t newLen;

    if (!s) return;

    len = wcslen(s);
    while (len > 0) {
        WCHAR c = s[len - 1];
        if (c == L' ' || c == L'\t' || c == L'\r' || c == L'\n') {
            s[len - 1] = L'\0';
            len--;
        }
        else {
            break;
        }
    }

    start = 0;
    while (s[start] == L' ' || s[start] == L'\t' || s[start] == L'\r' || s[start] == L'\n') {
        start++;
    }

    if (start > 0) {
        newLen = wcslen(s + start);
        memmove(s, s + start, (newLen + 1) * sizeof(WCHAR));
    }
}

static VOID NormalizeSerial(_Inout_ PWSTR s)
{
    PWSTR p;

    if (!s) return;

    TrimSpaces(s);

    for (p = s; *p; ++p) {
        if (*p == L'&') {
            *p = L'\0';
            break;
        }
    }

    TrimSpaces(s);

    for (p = s; *p; ++p) {
        if (*p >= L'a' && *p <= L'z') {
            *p = (WCHAR)(*p - (L'a' - L'A'));
        }
    }
}

static UINT64 HashSerial(_In_ PCWSTR s)
{
    const UINT64 FNV_OFFSET = 1469598103934665603ULL;
    const UINT64 FNV_PRIME = 1099511628211ULL;
    UINT64 h = FNV_OFFSET;
    const WCHAR* p;

    if (!s) return h;

    for (p = s; *p; ++p) {
        USHORT w = (USHORT)(*p);

        h ^= (UINT64)(w & 0xFF);
        h *= FNV_PRIME;

        h ^= (UINT64)((w >> 8) & 0xFF);
        h *= FNV_PRIME;
    }

    return h;
}

static VOID SortU64(_Inout_updates_(count) UINT64* arr, _In_ ULONG count)
{
    ULONG i;

    if (!arr || count < 2) return;

    for (i = 1; i < count; ++i) {
        UINT64 key = arr[i];
        LONG j = (LONG)i - 1;

        while (j >= 0 && arr[j] > key) {
            arr[j + 1] = arr[j];
            j--;
        }
        arr[j + 1] = key;
    }
}

static VOID SortAndDedupU64(_Inout_updates_(Count) UINT64* arr, _Inout_ PULONG Count)
{
    ULONG i, out;

    if (!arr || !Count || *Count == 0) return;

    SortU64(arr, *Count);

    out = 0;
    for (i = 0; i < *Count; ++i) {
        if (out == 0 || arr[i] != arr[out - 1]) {
            arr[out++] = arr[i];
        }
    }

    *Count = out;
}

static VOID WhitelistFree(VOID)
{
    ExAcquirePushLockExclusive(&gWl.Lock);

    if (gWl.Items) {
        ExFreePoolWithTag(gWl.Items, TAG);
        gWl.Items = NULL;
    }

    gWl.Count = 0;
    gWl.Version = 0;

    ExReleasePushLockExclusive(&gWl.Lock);
}

static NTSTATUS WhitelistReplace(_In_reads_(count) const UINT64* items, _In_ ULONG count, _In_ ULONG version)
{
    UINT64* newItems = NULL;
    ULONG newCount = count;

    if (count > 0) {
        SIZE_T bytes = ((SIZE_T)count) * sizeof(UINT64);

        newItems = (UINT64*)ExAllocatePool2(POOL_FLAG_PAGED, bytes, TAG);
        if (!newItems) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlCopyMemory(newItems, items, bytes);
        SortAndDedupU64(newItems, &newCount);
    }

    ExAcquirePushLockExclusive(&gWl.Lock);

    if (gWl.Items) {
        ExFreePoolWithTag(gWl.Items, TAG);
    }

    gWl.Items = newItems;
    gWl.Count = newCount;
    gWl.Version = version;

    ExReleasePushLockExclusive(&gWl.Lock);

    return STATUS_SUCCESS;
}

static BOOLEAN WhitelistContains(_In_ UINT64 h, _Out_opt_ PULONG pVersion)
{
    BOOLEAN found = FALSE;
    LONG lo, hi;

    ExAcquirePushLockShared(&gWl.Lock);

    if (pVersion) {
        *pVersion = gWl.Version;
    }

    lo = 0;
    hi = (LONG)gWl.Count - 1;

    while (lo <= hi) {
        LONG mid = lo + ((hi - lo) / 2);
        UINT64 v = gWl.Items[mid];

        if (v == h) {
            found = TRUE;
            break;
        }

        if (v < h) {
            lo = mid + 1;
        }
        else {
            hi = mid - 1;
        }
    }

    ExReleasePushLockShared(&gWl.Lock);
    return found;
}


static NTSTATUS SendIoctlSync(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ ULONG IoControlCode,
    _In_opt_ PVOID InBuf,
    _In_ ULONG InLen,
    _Out_writes_bytes_opt_(OutLen) PVOID OutBuf,
    _In_ ULONG OutLen,
    _Out_opt_ PULONG BytesReturned
)
{
    KEVENT ev;
    IO_STATUS_BLOCK iosb;
    PIRP irp;
    NTSTATUS st;

    if (BytesReturned) *BytesReturned = 0;

    KeInitializeEvent(&ev, NotificationEvent, FALSE);
    RtlZeroMemory(&iosb, sizeof(iosb));

    irp = IoBuildDeviceIoControlRequest(
        IoControlCode,
        DeviceObject,
        InBuf,
        InLen,
        OutBuf,
        OutLen,
        FALSE,
        &ev,
        &iosb
    );

    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    st = IoCallDriver(DeviceObject, irp);
    if (st == STATUS_PENDING) {
        KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
        st = iosb.Status;
    }

    if (BytesReturned) {
        *BytesReturned = (ULONG)iosb.Information;
    }

    return st;
}

static NTSTATUS QueryUsbAndSerial(
    _In_ PFLT_VOLUME Volume,
    _Out_ BOOLEAN* IsUsb,
    _Out_writes_(SerialCch) PWSTR SerialOut,
    _In_ ULONG SerialCch
)
{
    PDEVICE_OBJECT disk = NULL;
    NTSTATUS st;
    STORAGE_PROPERTY_QUERY q;
    UCHAR buf[1024];
    ULONG bytes = 0;

    if (IsUsb) *IsUsb = FALSE;
    if (SerialOut && SerialCch) SerialOut[0] = L'\0';

    st = FltGetDiskDeviceObject(Volume, &disk);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    RtlZeroMemory(&q, sizeof(q));
    q.PropertyId = StorageDeviceProperty;
    q.QueryType = PropertyStandardQuery;

    RtlZeroMemory(buf, sizeof(buf));

    st = SendIoctlSync(
        disk,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &q,
        sizeof(q),
        buf,
        sizeof(buf),
        &bytes
    );

    ObDereferenceObject(disk);

    if (!NT_SUCCESS(st)) {
        return st;
    }

    if (bytes < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return STATUS_INFO_LENGTH_MISMATCH;
    }

    {
        PSTORAGE_DEVICE_DESCRIPTOR d = (PSTORAGE_DEVICE_DESCRIPTOR)buf;

        if (IsUsb) {
            *IsUsb = (d->BusType == BusTypeUsb) ? TRUE : FALSE;
        }

        if (SerialOut && SerialCch && d->SerialNumberOffset && d->SerialNumberOffset < bytes) {
            PCSTR s = (PCSTR)(buf + d->SerialNumberOffset);
            ANSI_STRING a;
            UNICODE_STRING u;

            RtlInitAnsiString(&a, s);

            u.Buffer = SerialOut;
            u.Length = 0;
            u.MaximumLength = (USHORT)(SerialCch * sizeof(WCHAR));

            st = RtlAnsiStringToUnicodeString(&u, &a, FALSE);
            if (NT_SUCCESS(st)) {
                SerialOut[u.Length / sizeof(WCHAR)] = L'\0';
                NormalizeSerial(SerialOut);
            }
            else {
                SerialOut[0] = L'\0';
            }
        }
    }

    return STATUS_SUCCESS;
}


static NTSTATUS SetCtx(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ BOOLEAN isUsb,
    _In_ BOOLEAN allowed,
    _In_ UINT64 serialHash,
    _In_ ULONG policyVersion
)
{
    PCTX ctx = NULL;
    NTSTATUS st;

    st = FltAllocateContext(
        gFilter,
        FLT_INSTANCE_CONTEXT,
        sizeof(CTX),
        PagedPool,
        (PFLT_CONTEXT*)&ctx
    );

    if (!NT_SUCCESS(st)) {
        return st;
    }

    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->IsUsb = isUsb;
    ctx->Allowed = allowed;
    ctx->SerialHash = serialHash;
    ctx->PolicyVersion = policyVersion;

    st = FltSetInstanceContext(
        FltObjects->Instance,
        FLT_SET_CONTEXT_KEEP_IF_EXISTS,
        ctx,
        NULL
    );

    FltReleaseContext(ctx);
    return st;
}


static FLT_PREOP_CALLBACK_STATUS PreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
)
{
    PCTX ctx = NULL;
    NTSTATUS st;

    if (CompletionContext) *CompletionContext = NULL;

    if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    st = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT*)&ctx);
    if (!NT_SUCCESS(st) || !ctx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (ctx->IsUsb) {
        ULONG currentVersion = 0;
        BOOLEAN allowed = TRUE;

        ExAcquirePushLockShared(&gWl.Lock);
        currentVersion = gWl.Version;
        ExReleasePushLockShared(&gWl.Lock);

        if (ctx->PolicyVersion != currentVersion) {
            if (ctx->SerialHash != 0) {
                allowed = WhitelistContains(ctx->SerialHash, NULL);
            }
            else {
                allowed = gPolicy.DefaultAllowIfNoSerial ? TRUE : FALSE;
            }

            ctx->Allowed = allowed;
            ctx->PolicyVersion = currentVersion;
        }

        if (!ctx->Allowed) {
            if (gPolicy.AuditOnly) {
                FltReleaseContext(ctx);
                return FLT_PREOP_SUCCESS_NO_CALLBACK;
            }

            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            FltReleaseContext(ctx);
            return FLT_PREOP_COMPLETE;
        }
    }

    FltReleaseContext(ctx);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

static NTSTATUS InstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
    BOOLEAN isUsb = FALSE;
    WCHAR serial[128];
    NTSTATUS st;
    UINT64 h = 0;
    BOOLEAN allowed = TRUE;
    ULONG version = 0;

    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);

    RtlZeroMemory(serial, sizeof(serial));

    st = QueryUsbAndSerial(FltObjects->Volume, &isUsb, serial, ARRAYSIZE(serial));
    if (!NT_SUCCESS(st)) {
        isUsb = FALSE;
        serial[0] = L'\0';
    }

    if (isUsb) {
        if (serial[0] == L'\0') {
            allowed = gPolicy.DefaultAllowIfNoSerial ? TRUE : FALSE;
            ExAcquirePushLockShared(&gWl.Lock);
            version = gWl.Version;
            ExReleasePushLockShared(&gWl.Lock);
        }
        else {
            h = HashSerial(serial);
            allowed = WhitelistContains(h, &version);
        }
    }
    else {
        ExAcquirePushLockShared(&gWl.Lock);
        version = gWl.Version;
        ExReleasePushLockShared(&gWl.Lock);
    }

    return SetCtx(FltObjects, isUsb, allowed, h, version);
}

static NTSTATUS PortConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID* ConnectionPortCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    gClientPort = ClientPort;
    return STATUS_SUCCESS;
}

static VOID PortDisconnectNotify(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);

    if (gClientPort) {
        FltCloseClientPort(gFilter, &gClientPort);
        gClientPort = NULL;
    }
}

static NTSTATUS PortMessageNotify(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength
)
{
    UG_MSG_HEADER* hdr;

    UNREFERENCED_PARAMETER(PortCookie);

    if (ReturnOutputBufferLength) *ReturnOutputBufferLength = 0;

    if (!InputBuffer || InputBufferLength < sizeof(UG_MSG_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }

    hdr = (UG_MSG_HEADER*)InputBuffer;

    if (hdr->Size != InputBufferLength) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    switch ((UG_CMD)hdr->Command)
    {
    case UgCmdSetWhitelist:
    {
        UG_MSG_SET_WL* m;
        ULONG count;
        SIZE_T need;
        UINT64* hashes;

        if (InputBufferLength < sizeof(UG_MSG_SET_WL)) {
            return STATUS_INVALID_BUFFER_SIZE;
        }

        m = (UG_MSG_SET_WL*)InputBuffer;
        count = m->Count;
        need = sizeof(UG_MSG_SET_WL) + ((SIZE_T)count * sizeof(UINT64));

        if (need != InputBufferLength) {
            return STATUS_INVALID_BUFFER_SIZE;
        }

        hashes = (UINT64*)(m + 1);
        return WhitelistReplace(hashes, count, m->Version);
    }

    case UgCmdSetPolicy:
    {
        UG_MSG_SET_POLICY* m;

        if (InputBufferLength != sizeof(UG_MSG_SET_POLICY)) {
            return STATUS_INVALID_BUFFER_SIZE;
        }

        m = (UG_MSG_SET_POLICY*)InputBuffer;
        gPolicy.AuditOnly = (m->AuditOnly ? TRUE : FALSE);
        gPolicy.DefaultAllowIfNoSerial = (m->DefaultAllowIfNoSerial ? TRUE : FALSE);

        return STATUS_SUCCESS;
    }

    case UgCmdGetStatus:
    {
        UG_MSG_STATUS_REPLY rep;

        if (!OutputBuffer || OutputBufferLength < sizeof(UG_MSG_STATUS_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;
        }

        RtlZeroMemory(&rep, sizeof(rep));

        ExAcquirePushLockShared(&gWl.Lock);
        rep.WlCount = gWl.Count;
        rep.WlVersion = gWl.Version;
        ExReleasePushLockShared(&gWl.Lock);

        rep.AuditOnly = gPolicy.AuditOnly ? 1 : 0;
        rep.DefaultAllowIfNoSerial = gPolicy.DefaultAllowIfNoSerial ? 1 : 0;

        RtlCopyMemory(OutputBuffer, &rep, sizeof(rep));

        if (ReturnOutputBufferLength) {
            *ReturnOutputBufferLength = sizeof(rep);
        }

        return STATUS_SUCCESS;
    }

    default:
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS CreateCommunicationPort(VOID)
{
    NTSTATUS st;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;

    RtlInitUnicodeString(&portName, PORT_NAME);

    st = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sd
    );

    st = FltCreateCommunicationPort(
        gFilter,
        &gServerPort,
        &oa,
        NULL,
        PortConnectNotify,
        PortDisconnectNotify,
        PortMessageNotify,
        1
    );

    FltFreeSecurityDescriptor(sd);
    return st;
}


static NTSTATUS Unload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    if (gServerPort) {
        FltCloseCommunicationPort(gServerPort);
        gServerPort = NULL;
    }

    if (gClientPort) {
        FltCloseClientPort(gFilter, &gClientPort);
        gClientPort = NULL;
    }

    WhitelistFree();

    if (gFilter) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
    }

    return STATUS_SUCCESS;
}

static const FLT_CONTEXT_REGISTRATION CtxReg[] = {
    { FLT_INSTANCE_CONTEXT, 0, NULL, sizeof(CTX), TAG },
    { FLT_CONTEXT_END }
};

static const FLT_OPERATION_REGISTRATION Ops[] = {
    { IRP_MJ_CREATE, 0, PreCreate, NULL },
    { IRP_MJ_OPERATION_END }
};

static const FLT_REGISTRATION Reg = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    CtxReg,
    Ops,
    Unload,
    InstanceSetup,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS st;

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializePushLock(&gWl.Lock);

    st = FltRegisterFilter(DriverObject, &Reg, &gFilter);
    if (!NT_SUCCESS(st)) {
        return st;
    }

    st = CreateCommunicationPort();
    if (!NT_SUCCESS(st)) {
        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return st;
    }

    st = FltStartFiltering(gFilter);
    if (!NT_SUCCESS(st)) {
        if (gServerPort) {
            FltCloseCommunicationPort(gServerPort);
            gServerPort = NULL;
        }

        FltUnregisterFilter(gFilter);
        gFilter = NULL;
        return st;
    }

    return STATUS_SUCCESS;
}