///<reference path='C:\Users\r0th3r\OneDrive\Code\index.d.ts'/>



function GetThreadFunctionFromThreadId(threadId=0, func=function(hThread){})
{
    const CloseHandle = new NativeFunction(
        Module.getExportByName('kernel32', 'CloseHandle'),
        'uint32', ['pointer']);
    const OpenThread = new NativeFunction(
        Module.getExportByName('kernel32', 'OpenThread'),
        'pointer', ['uint32', 'bool', 'uint32']);

    let threadAny;

    // const THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
    const THREAD_ALL_ACCESS = 0x001F03FF;

    let hThread = OpenThread(THREAD_ALL_ACCESS, 0, threadId);

    if (hThread.equals(NULL)) return threadAny;

    threadAny = func(hThread);

    if (!hThread.equals(NULL)) CloseHandle(hThread);

    return threadAny;
}
function GetThreadName(threadHandle=NULL)
{
    const NtQueryInformationThread = new NativeFunction(
        Module.getExportByName('ntdll', 'NtQueryInformationThread'),
        'uint32', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']);

    if (NULL === threadHandle) {
        const GetCurrentThread = new NativeFunction(
            Module.getExportByName('kernel32', 'GetCurrentThread'),
            'pointer', []);
        threadHandle = GetCurrentThread();
    }
    /*
        typedef struct _THREAD_NAME_INFORMATION
        {
            UNICODE_STRING ThreadName;
        } THREAD_NAME_INFORMATION, *PTHREAD_NAME_INFORMATION;
    */
    let threadNameInfo = Memory.alloc(16 + 128);
    const ntstatus = NtQueryInformationThread(
        threadHandle, 
        38 /* ThreadNameInformation */, 
        threadNameInfo, (16 + 128), NULL);

    return 0 == ntstatus ? 
    threadNameInfo.add(Process.pointerSize).readPointer().readUtf16String() : NULL;
}
function GetThreadStartAddress(threadHandle=NULL)
{
    const NtQueryInformationThread = new NativeFunction(
        Module.getExportByName('ntdll', 'NtQueryInformationThread'),
        'uint32', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']);

    if (NULL === threadHandle) {
        const GetCurrentThread = new NativeFunction(
            Module.getExportByName('kernel32', 'GetCurrentThread'),
            'pointer', []);
        threadHandle = GetCurrentThread();
    }

    let threadStartAddress = Memory.alloc(Process.pointerSize);
    const ntstatus = NtQueryInformationThread(
        threadHandle, 
        9 /* ThreadQuerySetWin32StartAddress */, 
        threadStartAddress, Process.pointerSize, NULL);
    return 0 == ntstatus ? threadStartAddress.readPointer() : NULL;
}



function GetLdrpInitialize()
{
    let LdrpInitialize = NULL;
    const LdrInitializeThunk = Module.getExportByName('ntdll', 'LdrInitializeThunk');

    let target = LdrInitializeThunk;
    for (;;) {
        const i = Instruction.parse(target);
        if (i.mnemonic === 'call') {
            LdrpInitialize = ptr(i.opStr);
            break;
        }
        target = i.next;
    }
    return new NativeFunction(LdrpInitialize, 'uint32', ['pointer', 'pointer']);
}


/* https://github.com/mq1n/DLLThreadInjectionDetector/blob/master/DLLInjectionDetector/ThreadCheck.cpp */
const LdrpInitialize = GetLdrpInitialize();
Interceptor.attach(LdrpInitialize, {
onEnter(args) {
        this.target = GetThreadStartAddress();
        /* WOW */
        this.arrbackup = new Uint8Array(this.target.readByteArray(1));
    },
    onLeave(retval) {
        if (0 != retval.toInt32()) return;

        if (this.target.readU8() != this.arrbackup[0] &&
            null == Process.findModuleByAddress(this.target))
        {
            this.target.writeByteArray(this.arrbackup);
        }
    }
});
