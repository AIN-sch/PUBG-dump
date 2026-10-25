/* bebyspass.c - BattlEye handle-protection bypass via ObRegisterCallbacks altitude race
 *
 * Principle:
 *   ObRegisterCallbacks are invoked in altitude order, higher altitude first.
 *   BEDaisy registers ~363220 and strips handle access.
 *   We register at a LOWER altitude, so our pre-op runs AFTER its,
 *   and we restore DesiredAccess to full access.
 *
 * No kernel struct offsets are guessed. Only documented WDK APIs are used,
 * except PsGetProcessImageFileName which is declared explicitly below.
 */

#include <ntifs.h>
#include <ntddk.h>

/* Undocumented but exported by ntoskrnl. Not present in any WDK header,
 * so it must be declared here or the compiler assumes int return and
 * truncates the pointer to 32 bits on x64. */
NTSYSAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
    _In_ PEPROCESS Process
);

#define TARGET_IMAGE_PREFIX "TslGame"
#define CALLER_IMAGE_PREFIX "pubg"
#define OUR_ALTITUDE        L"1000"

#define FULL_ACCESS 0x1FFFFFL

static PVOID   g_ObRegistration = NULL;

/* Prefix compare against a 15-char ANSI image name, case-insensitive, no CRT. */
static BOOLEAN PrefixMatch(_In_opt_ PCHAR Name, _In_ PCSTR Prefix)
{
    SIZE_T i;
    if (Name == NULL || Prefix == NULL)
        return FALSE;

    for (i = 0; Prefix[i] != 0; ++i) {
        CHAR a = Name[i];
        CHAR b = Prefix[i];
        if (a == 0)
            return FALSE;
        if (a >= 'A' && a <= 'Z') a = (CHAR)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (CHAR)(b - 'A' + 'a');
        if (a != b)
            return FALSE;
    }
    return TRUE;
}

static PCHAR ImageNameOfObject(_In_ POB_PRE_OPERATION_INFORMATION Info)
{
    if (Info->ObjectType == *PsProcessType) {
        PEPROCESS Process = (PEPROCESS)Info->Object;
        if (Process == NULL)
            return NULL;
        return PsGetProcessImageFileName(Process);
    }

    if (Info->ObjectType == *PsThreadType) {
        PETHREAD Thread = (PETHREAD)Info->Object;
        PEPROCESS Process;
        if (Thread == NULL)
            return NULL;
        Process = IoThreadToProcess(Thread);
        if (Process == NULL)
            return NULL;
        return PsGetProcessImageFileName(Process);
    }

    return NULL;
}

static OB_PREOP_CALLBACK_STATUS PreOperation(
    _In_ PVOID RegistrationContext,
    _In_ POB_PRE_OPERATION_INFORMATION Info)
{
    PCHAR CallerName;
    PCHAR TargetName;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (Info == NULL || Info->Object == NULL || Info->ObjectType == NULL)
        return OB_PREOP_SUCCESS;

    /* Kernel-initiated opens are not interesting. */
    if (Info->KernelHandle != 0)
        return OB_PREOP_SUCCESS;

    if (Info->ObjectType != *PsProcessType && Info->ObjectType != *PsThreadType)
        return OB_PREOP_SUCCESS;

    /* Only assist our own usermode helper, never hand access to anyone else. */
    CallerName = PsGetProcessImageFileName(IoGetCurrentProcess());
    if (!PrefixMatch(CallerName, CALLER_IMAGE_PREFIX))
        return OB_PREOP_SUCCESS;

    TargetName = ImageNameOfObject(Info);
    if (!PrefixMatch(TargetName, TARGET_IMAGE_PREFIX))
        return OB_PREOP_SUCCESS;

    DbgPrint("[bebypass] grant full access: caller=%s target=%s\n",
             CallerName ? CallerName : "?", TargetName);

    Info->Parameters->CreateHandleInformation.DesiredAccess = FULL_ACCESS;

    return OB_PREOP_SUCCESS;
}

static VOID UnloadRoutine(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_ObRegistration != NULL) {
        ObUnRegisterCallbacks(g_ObRegistration);
        g_ObRegistration = NULL;
    }
    DbgPrint("[bebypass] unloaded\n");
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    OB_OPERATION_REGISTRATION Ops[2];
    OB_CALLBACK_REGISTRATION  Reg;
    UNICODE_STRING            Altitude;
    NTSTATUS                  Status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[bebypass] DriverEntry\n");

    DriverObject->DriverUnload = UnloadRoutine;

    RtlZeroMemory(Ops, sizeof(Ops));
    Ops[0].ObjectType   = PsProcessType;
    Ops[0].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    Ops[0].PreOperation = PreOperation;

    Ops[1].ObjectType   = PsThreadType;
    Ops[1].Operations   = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    Ops[1].PreOperation = PreOperation;

    RtlInitUnicodeString(&Altitude, OUR_ALTITUDE);

    RtlZeroMemory(&Reg, sizeof(Reg));
    Reg.Version                   = OB_FLT_REGISTRATION_VERSION;
    Reg.OperationRegistrationCount = 2;
    Reg.Altitude                  = Altitude;
    Reg.OperationRegistration     = Ops;

    Status = ObRegisterCallbacks(&Reg, &g_ObRegistration);
    if (!NT_SUCCESS(Status)) {
        DbgPrint("[bebypass] ObRegisterCallbacks failed 0x%08X\n", Status);
        return Status;
    }

    DbgPrint("[bebypass] registered at altitude %ws, status OK\n", OUR_ALTITUDE);
    return STATUS_SUCCESS;
}
