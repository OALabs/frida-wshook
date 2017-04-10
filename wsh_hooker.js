var ptrWSASocketW = Module.findExportByName("WS2_32.DLL", "WSASocketW");

// Enable Debugging
var DEBUG_FLAG = true;

// Allow Shell commands
var ALLOW_SHELL = false;

// Allow DNS Requests
var DISABLE_DNS = false;

// Allow WSASend
var DISABLE_WSASEND = true;

// Allow COM Object lookup
var DISABLE_COM_INIT = true;

recv('set_script_vars', function onMessage(setting) {

    debug("Setting Script Vars...")
    DEBUG_FLAG = setting['debug'];
    debug(" - DEBUG_FLAG: " +  DEBUG_FLAG);
    DISABLE_DNS = setting['disable_dns'];
    debug(" - DISABLE_DNS: " +  DISABLE_DNS);
    ALLOW_SHELL = setting['allow_shell'];
    debug(" - ALLOW_SHELL: " +  DISABLE_DNS);
    DISABLE_WSASEND = setting['disable_send'];
    debug(" - DISABLE_WSASEND: " +  DISABLE_WSASEND);
    DISABLE_COM_INIT = setting['disable_com'];
    debug(" - DISABLE_COM_INIT: " +  DISABLE_COM_INIT);

});

function debug(msg)
{
    if(DEBUG_FLAG == true){
        send({
            name: 'log',
            payload: msg
        });
        recv('ack', function () {}).wait();
    }
}

function log_instr(msg){
    send({
        name: 'instr',
        hookdata: msg
    });
}

ADDRESS_FAMILY = {
    0x0:"AF_UNSPEC",
    0x2:"AF_INET",
    0X6:"AF_IPX",
    0X16:"AF_APPLETALK",
    0X17:"AF_NETBIOS",
    0X23:"AF_INET6",
    0X26:"AF_IRDA",
    0X32:"AF_BTH"
};


//https://msdn.microsoft.com/en-us/library/windows/desktop/dd542643(v=vs.85).aspx

CO_E_CLASSSTRING = 0x800401F3;
REGDB_E_WRITEREGDB = 0x80040151;
S_OK = 0;


/*
HRESULT CLSIDFromProgID(
  _In_  LPCOLESTR lpszProgID,
  _Out_ LPCLSID   lpclsid
);
 */
var ptrCLSIDFromProgID = Module.findExportByName("Ole32.dll", "CLSIDFromProgID");
var CLSIDFromProgID = new NativeFunction(ptrCLSIDFromProgID, 'uint', ['pointer', 'pointer']);
Interceptor.replace(ptrCLSIDFromProgID, new NativeCallback(function (lpszProgID, lpclsid) {
     var retval = CO_E_CLASSSTRING;

     var prog_id = Memory.readUtf16String(lpszProgID);
     log_instr({'hook':'clsid','progid': prog_id});

     if(!DISABLE_COM_INIT){
         retval = CLSIDFromProgID(lpszProgID, lpclsid);
    }
    return retval;
 },'uint',['pointer', 'pointer'], 'stdcall'));

Interceptor.attach(ptrWSASocketW, {
    onEnter: function (args) {
        debug(" WSASocketW() Called");
        debug("   |-- Address Family: " + ADDRESS_FAMILY[parseInt(args[0],16)]+"["+ args[0]+"]");
    },
    onLeave: function (retval) {
        //console.log("Leave");
        if (retval.toInt32() > 0) {
            /* do something with this.fileDescriptor */
        }
    }
});

NAMESPACE = {
    0:"NS_ALL",
    12:"NS_DNS",
    13:"NS_NETBT",
    14:"NS_WINS",
    15:"NS_NLA",
    16:"NS_BTH",
    32:"NS_NTDS",
    37:"NS_EMAIL",
    38:"NS_PNRPNAME",
    39:"NS_PNRPCLOUD"
};

WSAHOST_NOT_FOUND = 11001;
/*
int WSAAPI GetAddrInfoEx(
  _In_opt_        PCTSTR                             pName,
  _In_opt_        PCTSTR                             pServiceName,
  _In_            DWORD                              dwNameSpace,
  _In_opt_        LPGUID                             lpNspId,
  _In_opt_  const ADDRINFOEX                         *pHints,
  _Out_           PADDRINFOEX                        *ppResult,
  _In_opt_        struct timeval                     *timeout,
  _In_opt_        LPOVERLAPPED                       lpOverlapped,
  _In_opt_        LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
  _Out_opt_       LPHANDLE                           lpNameHandle
);
 */
var ptrGetAddrInfoExW = Module.findExportByName("WS2_32.DLL", "GetAddrInfoExW");
var GetAddrInfoExW = new NativeFunction(ptrGetAddrInfoExW, 'int', ['pointer', 'pointer', 'uint', 'pointer','pointer','pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

Interceptor.replace(ptrGetAddrInfoExW, new NativeCallback(function (pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult,timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle) {
    //Set the default return to not found
    var retval = WSAHOST_NOT_FOUND;
    if(!DISABLE_DNS) retval = GetAddrInfoExW(pName, pServiceName, dwNameSpace, lpNspId, pHints, ppResult,timeout, lpOverlapped, lpCompletionRoutine, lpNameHandle);
      if(dwNameSpace = 0x12){
            var host =  Memory.readUtf16String(pName);
            log_instr({'hook':'dns','host': host});
        }
        else{
            debug(" AddrInfo Request: " + NAMESPACE[dwNameSpace] +"[" + dwNameSpace + "]");
        }
    return retval;


},'int', ['pointer', 'pointer', 'uint', 'pointer','pointer','pointer', 'pointer', 'pointer', 'pointer', 'pointer'], 'stdcall'));


/*
https://msdn.microsoft.com/en-us/library/windows/desktop/ms742203(v=vs.85).aspx
int WSASend(
  _In_  SOCKET                             s,
  _In_  LPWSABUF                           lpBuffers,
  _In_  DWORD                              dwBufferCount,
  _Out_ LPDWORD                            lpNumberOfBytesSent,
  _In_  DWORD                              dwFlags,
  _In_  LPWSAOVERLAPPED                    lpOverlapped,
  _In_  LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine

https://msdn.microsoft.com/en-us/library/windows/desktop/ms741542(v=vs.85).aspx

  typedef struct __WSABUF {
  u_long   len;
  char FAR *buf;
} WSABUF, *LPWSABUF;

);
 */

var buffer = 0;
var ptrWSASend = Module.findExportByName("WS2_32.DLL", "WSASend");
var WSASend = new NativeFunction(ptrWSASend, 'int', ['pointer', 'pointer', 'uint', 'pointer','uint','pointer', 'pointer']);
Interceptor.replace(ptrWSASend, new NativeCallback(function (s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine) {
    var retval = 10060;
    if(!DISABLE_WSASEND){
        retval = WSASend(s, lpBuffers, dwBufferCount,lpNumberOfBytesSent,dwFlags,lpOverlapped,lpCompletionRoutine);
    }
    else{
        // TODO: Force the socket closed
        // Passing an error as a return value makes cscript cry and try try again..
        // for now capture the lpbuffer value and if we've see it just nop out
        //
        //
        if(buffer == lpBuffers){
            return retval;
        }
        buffer = lpBuffers;
    }

    //TODO: Handle multiple wsabuff structures..for now we assume that there is only one.
    //      But these could be chained in an array of [WSABUF, WSABUF, WSABUF, WSABUF]
    //
    debug("----------------------");
    debug("   |-- Socket ("+s+")");
    debug("   |-- LPWSABUF ("+lpBuffers+")");
    debug("   |-- Buffers " + dwBufferCount)

    var buff_len = Memory.readInt(ptr(lpBuffers));

    debug("Buffer Length: " + buff_len);
    //var dptr = Memory.readInt(ptr(lpBuffers));
    var lpwbuf = lpBuffers;
    lpwbuf = (lpwbuf.toInt32() + 4);
    var dptr = Memory.readInt(ptr(lpwbuf));

    var request_data = Memory.readCString(ptr(dptr), buff_len);
    try {
        debug("-- Request Data --");
        debug(request_data);
        debug("-- Request Data End --");
        log_instr({"hook":'wsasend', "request": request_data, "buffers": dwBufferCount});
    }
    catch(err){}

    return retval

},'int',['pointer', 'pointer', 'uint', 'pointer','uint','pointer', 'pointer'], 'stdcall'));

var ptrWSAAddressToStringW = Module.findExportByName("WS2_32.DLL", "WSAAddressToStringW");
Interceptor.attach(ptrWSAAddressToStringW, {
    onEnter: function (args) {
        debug(" WSAAddressToStringW() Called");
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
            /* do something with this.fileDescriptor */
        }
    }
});


var ptrWSAStartup = Module.findExportByName("WS2_32.DLL", "WSAStartup");
Interceptor.attach(ptrWSAStartup, {
    onEnter: function (args) {
        debug(" WSAStartup() Called");
        debug("   |-- Requesting Version ("+ args[0]+")");
    },
    onLeave: function (retval) {
        if (retval.toInt32() > 0) {
            // nop
        }
    }
});

// https://msdn.microsoft.com/en-us/library/windows/desktop/bb762153(v=vs.85).aspx
SHOWCMD = {
    0:"SW_HIDE",
    1:"SW_SHOWNORMAL",
    2:"SW_SHOWMINIMIZED",
    3:"SW_SHOWMAXIMIZED",
    4:"SW_SHOWNOACTIVATE",
    5:"SW_SHOW",
    6:"SW_MINIMIZE",
    7:"SW_SHOWMINNOACTIVE",
    8:"SW_SHOWNA",
    9:"SW_RESTORE",
    10:"SW_SHOWDEFAULT"
};

var ptrShellExecute = Module.findExportByName("Shell32.dll", "ShellExecuteExW");
var ShellExecute = new NativeFunction(ptrShellExecute, 'int', ['pointer']);

Interceptor.replace(ptrShellExecute, new NativeCallback(function (executeinfo) {

        var retval = false;

        //To pass the shell instruction comment out this line..
        if(ALLOW_SHELL == true)retval = ShellExecute(executeinfo);

        var shellinfo_ptr = executeinfo;
        var structure_size = Memory.readUInt(shellinfo_ptr);
        var ptr_file = Memory.readPointer(shellinfo_ptr.add(16));
        var ptr_params = Memory.readPointer(shellinfo_ptr.add(20));
        var nshow = Memory.readInt(shellinfo_ptr.add(28));

        var lpfile = Memory.readUtf16String(ptr(ptr_file));
        var lpparams = Memory.readUtf16String(ptr(ptr_params));

        log_instr({"hook":'shell', "nshow": SHOWCMD[nshow], "cmd": lpfile, "params": lpparams});

        return retval;
    },'int',['pointer'], 'stdcall'));