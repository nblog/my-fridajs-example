///<reference path='C:/Users/r0th3r/OneDrive/Code/index.d.ts'/>


function GetThreadFunctionFromThreadId(threadId=0, func=function(hThread=ptr(-2)){})
{
    const CloseHandle = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('CloseHandle'),
        'uint32', ['pointer']);
    const OpenThread = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('OpenThread'),
        'pointer', ['uint32', 'bool', 'uint32']);

    let threadAny;

    /* Minimal rights required by ExecInAnyThread():
     *   THREAD_SUSPEND_RESUME   (0x0002) - SuspendThread / ResumeThread
     *   THREAD_GET_CONTEXT      (0x0008) - GetThreadContext
     *   THREAD_SET_CONTEXT      (0x0010) - SetThreadContext
     *   THREAD_QUERY_INFORMATION(0x0040) - GetThreadId / NtQueryInformationThread
     */
    const thread_access = 0x0002 | 0x0008 | 0x0010 | 0x0040;
    let hThread = OpenThread(thread_access, 0, threadId);

    if (hThread.equals(NULL)) return threadAny;

    threadAny = func(hThread);

    if (!hThread.equals(NULL)) CloseHandle(hThread);

    return threadAny;
}
function GetCurrentThread()
{
    return new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('GetCurrentThread'),
        'pointer', [])();
}
function GetThreadName(threadHandle=NULL)
{
    const NtQueryInformationThread = new NativeFunction(
        Process.getModuleByName('ntdll').getExportByName('NtQueryInformationThread'),
        'uint32', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']);

    if (NULL === threadHandle)
        threadHandle = GetCurrentThread();
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
        Process.getModuleByName('ntdll').getExportByName('NtQueryInformationThread'),
        'uint32', ['pointer', 'uint32', 'pointer', 'uint32', 'pointer']);

    if (NULL === threadHandle)
        threadHandle = GetCurrentThread();

    let threadStartAddress = Memory.alloc(Process.pointerSize);
    const ntstatus = NtQueryInformationThread(
        threadHandle, 
        9 /* ThreadQuerySetWin32StartAddress */, 
        threadStartAddress, Process.pointerSize, NULL);
    return 0 == ntstatus ? threadStartAddress.readPointer() : NULL;
}
function ExecInAnyThread(threadHandle=NULL, func=function(parameter=NULL){}, parameter=NULL)
{
    const GetLastError = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('GetLastError'),
        'uint32', []);
    const GetThreadContext = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('GetThreadContext'),
        'uint32', ['pointer', 'pointer']);
    const SetThreadContext = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('SetThreadContext'),
        'uint32', ['pointer', 'pointer']);
    const SuspendThread = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('SuspendThread'),
        'uint32', ['pointer']);
    const ResumeThread = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('ResumeThread'),
        'uint32', ['pointer']);
    const CloseHandle = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('CloseHandle'),
        'uint32', ['pointer']);
    const CreateEventW = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('CreateEventW'),
        'pointer', ['pointer', 'bool', 'bool', 'pointer']);
    const ResetEvent = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('ResetEvent'),
        'bool', ['pointer']);
    const WaitForSingleObject = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('WaitForSingleObject'),
        'uint32', ['pointer', 'uint32']);
    const PostThreadMessageW = new NativeFunction(
        Process.getModuleByName('user32').getExportByName('PostThreadMessageW'),
        'bool', ['uint32', 'uint32', 'pointer', 'pointer']);

    /* attach thread */
    const threadId = new NativeFunction(
        Process.getModuleByName('kernel32').getExportByName('GetThreadId'),
        'uint32', ['pointer'])(threadHandle);

    let thumb = NULL;
    let routine = new NativeCallback(function(hEvent) {
        func(parameter);
        new NativeFunction(
            Process.getModuleByName('kernel32').getExportByName('SetEvent'),
            'bool', ['pointer'])(hEvent);
    }, 'void', ['pointer']);
    Process.enumerateThreads().forEach(function(thread) {
        if (thread.id != threadId) return;

        let hEvent = CreateEventW(NULL, 1, 0, Memory.allocUtf16String('fridajs-rpc-event'));
        ResetEvent(hEvent);

        thumb = Memory.alloc(Process.pageSize);
        Memory.patchCode(thumb, Process.pageSize, code => {
            const cw = new X86Writer(code, { pc: thumb });
            cw.putPushax();
            cw.putPushfx();
            cw.putCallAddressWithArguments(routine, [hEvent]);
            cw.putPopfx();
            cw.putPopax();
            cw.putJmpAddress(thread.context.pc);
        });

        let pContext = Memory.alloc(8 == Process.pointerSize ? 0x4d0 : 0x2cc);

        SuspendThread(threadHandle);

        /* ContextFlags */
        pContext.add(8 == Process.pointerSize ? 0x30 : 0).writeU32(0x10001 /* CONTEXT_CONTROL */);
        if (!GetThreadContext(threadHandle, pContext))
            throw new Error('GetThreadContext failed: ' + GetLastError());

        /* PC */
        pContext.add(8 == Process.pointerSize ? 0xf8 : 0xb8).writePointer(thumb);
        if (!SetThreadContext(threadHandle, pContext))
            throw new Error('SetThreadContext failed: ' + GetLastError());

        ResumeThread(threadHandle);

        /* hi */
        PostThreadMessageW(thread.id, 0x0000 /* WM_NULL */, NULL, NULL);

        WaitForSingleObject(hEvent, 30 * 1000 /* 30s */);

        if (hEvent != NULL) CloseHandle(hEvent);
    });
}
/*
GetThreadFunctionFromThreadId(Process.enumerateThreads()[0].id, function(hThread) {
    ExecInAnyThread(hThread, function(parameter) {
        console.log(`[+] Executed Thread Id: ${Process.getCurrentThreadId()} ${parameter}`);
    }, ptr(0x1337));
});
*/


// function patchThreadNotify2(m) 
// {
//     function GetLdrpCallInitRoutine()
//     {
//         return new NativeFunction(
//             Process.getModuleByName('ntdll.dll').base.add(/* SYMBOL RVA */),
//             'bool', ['pointer', 'pointer', 'uint32', 'pointer']);
//     }
//     const LdrpCallInitRoutine = GetLdrpCallInitRoutine();
//     Interceptor.replace(LdrpCallInitRoutine, new NativeCallback(function(
//         InitRoutine, DllHandle, Reason, Context) {
//             /* patch threadnotify */
//             if (Reason == 2 /* DLL_THREAD_ATTACH */ && DllHandle.equals(m.base)) return 0;

//             return LdrpCallInitRoutine(InitRoutine, DllHandle, Reason, Context);
//         }, 'bool', ['pointer', 'pointer', 'uint32', 'pointer'])
//     );
// } patchThreadNotify2(Process.enumerateModules()[0]);

function patchThreadNotify()
{
    function GetLdrpInitialize()
    {
        let LdrpInitialize = NULL;
        const LdrInitializeThunk = Process.getModuleByName('ntdll').getExportByName('LdrInitializeThunk');

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
            /* if (0 != retval.toInt32()) return; */

            if (this.target.readU8() != this.arrbackup[0] &&
                null == Process.findModuleByAddress(this.target))
            {
                this.target.writeByteArray(this.arrbackup);
            }
        }
    });
} patchThreadNotify();
