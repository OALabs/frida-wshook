import frida
import argparse
import os
import time

class WSHooker(object):

    # Path to cscript
    _CSCRIPT_PATH_WOW64 = "C:\\Windows\SysWOW64\\"
    _CSCRIPT_PATH = "C:\\Windows\System32\\"
    _CSCRIPT_EXE = 'cscript.exe'

    def __init__(self):
        self.script = None

        if os.path.exists(WSHooker._CSCRIPT_PATH_WOW64):
            print ' [*] x64 detected..using SysWOW64'
            self.wsh_host = WSHooker._CSCRIPT_PATH_WOW64 + WSHooker._CSCRIPT_EXE
        else:
            print ' [*] Using System32'
            self.wsh_host = WSHooker._CSCRIPT_PATH + WSHooker._CSCRIPT_EXE

    def on_message(self, message, data):
        if message['type'] == 'send':
            msg_data = message['payload']

            if msg_data['name'] == 'log':
                try:
                    print '%s' % msg_data['payload']
                    self.script.post({'type': 'ack'})
                except Exception as e:
                    print e
            elif msg_data['name'] == 'instr':
                try:
                    hmsg = msg_data['hookdata']
                    if hmsg['hook'] == 'clsid':
                        print " CLSIDFromProgID Called"
                        print "  |-ProgId: %s" % hmsg['progid']
                    elif hmsg['hook'] == 'dns':
                        print " DNS Lookup"
                        print "  |-Host: %s" % hmsg['host']
                    elif hmsg['hook'] == 'shell':
                        print " ShellExecute Called"
                        print "  |-nShow: %s " % hmsg['nshow']
                        print "  |-Command: %s" % hmsg['cmd']
                        print "  |-Params: %s" % hmsg['params']
                    elif hmsg['hook'] == 'wsasend':
                        print " WSASend Called"
                        print "  |-Request Data Start"

                        rdata = hmsg['request'].split('\n')
                        for req in rdata:
                            print "    %s" % req
                        print "  |-Request Data End"
                    else:
                        print '%s ' % msg_data['hookdata']
                    print ''
                except TypeError as te:
                    print ' [!] Error parsing hook data!'
                    print ' [!] Error: %s' % te

    def eval_script(self,
                    target_script,
                    debug=False,
                    enable_shell=False,
                    disable_dns=False,
                    disable_send=False,
                    disable_com=False):

        # create the command args
        cmd = [self.wsh_host, target_script]

        # spawn the process
        pid = frida.spawn(cmd)
        session = frida.attach(pid)

        # attach to the session
        with open("wsh_hooker.js") as fp:
            script_js = fp.read()

        self.script = session.create_script(script_js, name="wsh_hooker.js")
        self.script.on('message', self.on_message)
        self.script.load()

        # Set Script variables
        print ' [*] Setting Script Vars...'
        self.script.post({"type": "set_script_vars",
                          "debug": debug,
                          "disable_dns": disable_dns,
                          "enable_shell": enable_shell,
                          "disable_send": disable_send,
                          "disable_com": disable_com})

        # Sleep for a second to ensure the vars are set..
        time.sleep(1)

        print ' [*] Hooking Process %s' % pid
        frida.resume(pid)

        # Keep process open
        raw_input(" [!] Running Script. Ctrl+Z to detach from instrumented program.\n\n")
        # print("[!] Ctrl+D on UNIX, Ctrl+Z on Windows/cmd.exe to detach from instrumented program.\n\n")
        # sys.stdin.read()

        # Kill it with fire
        frida.kill(pid)

def main():
    parser = argparse.ArgumentParser(description="frida-wshook.py your friendly WSH Hooker")
    parser.add_argument("script", help="Path to target .js/.vbs file")
    parser.add_argument('--debug', dest='debug', action='store_true', help="Output debug info")
    parser.add_argument('--disable_dns', dest='disable_dns', action='store_true', help="Disable DNS Requests")
    parser.add_argument('--disable_com_init', dest='disable_com_init', action='store_true', help="Disable COM Object Id Lookup")
    parser.add_argument('--enable_shell', dest='enable_shell', action='store_true', help="Enable Shell Commands")
    parser.add_argument('--disable_net', dest='disable_net', action='store_true', help="Disable Network Requests")

    args = parser.parse_args()

    wshooker = WSHooker()
    wshooker.eval_script(args.script,
                         args.debug,
                         args.enable_shell,
                         args.disable_dns,
                         args.disable_net,
                         args.disable_com_init)

if __name__ == '__main__':
    main()