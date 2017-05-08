# -*- coding: utf-8 -*-
import frida
import argparse
import os
import time

__author__ = "Sean Wilson  - @seanmw"
__version__ = "1.0.1"

####################################################################################################
# Changelog
#
# 5.7.2017
#  - Cleaned up how the script exits
#  - Added logging for when the script host has terminated or the injected script is destroyed
#
#
#
#
#
#
######################################################################################################


class WSHooker(object):

    # Path to cscript
    _CSCRIPT_PATH_WOW64 = "C:\\Windows\SysWOW64\\"
    _CSCRIPT_PATH = "C:\\Windows\System32\\"
    _CSCRIPT_EXE = 'cscript.exe'

    def __init__(self):
        self.script = None
        self._process_terminated = False

        if os.path.exists(WSHooker._CSCRIPT_PATH_WOW64):
            print ' [*] x64 detected..using SysWOW64'
            self.wsh_host = WSHooker._CSCRIPT_PATH_WOW64 + WSHooker._CSCRIPT_EXE
        else:
            print ' [*] Using System32'
            self.wsh_host = WSHooker._CSCRIPT_PATH + WSHooker._CSCRIPT_EXE

    def on_detach(self, message, data):
        print ' [!] CScript process has terminated!'
        print '     |- Process Id: %s' % message.pid
        print '     |- Message: %s' % data
        self._process_terminated = True
        print ' [!] Exiting...'

    def on_destroyed(self):
        print ' [!] Warning: Instrumentation script has been destroyed!'

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
        else:
            print ' [!] Error: %s' % message

    def eval_script(self,
                    target_script,
                    debug=False,
                    enable_shell=False,
                    disable_dns=False,
                    disable_send=False,
                    disable_com=False):

        # create the command args
        cmd = [self.wsh_host, target_script]

        # Spawn and attach to the process
        pid = frida.spawn(cmd)
        session = frida.attach(pid)

        # attach to the session
        with open("wsh_hooker.js") as fp:
            script_js = fp.read()

        self.script = session.create_script(script_js, name="wsh_hooker.js")
        #self.script.set_log_handler(self.log_handler)

        self.script.on('message', self.on_message)

        session.on('detached', self.on_detach)

        self.script.on('destroyed', self.on_destroyed)

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

        print ' Press ctrl-c to kill the process...'
        # Keep the process running...
        while True:
            try:
                time.sleep(0.5)
                if self._process_terminated:
                    break
            except KeyboardInterrupt:
                break

        if not self._process_terminated:
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

    if not args.script.endswith('vbs') and \
            not args.script.endswith('js'):
        print ' [!] Error: Invalid Script Extension! Extension must be .js or .vbs'
        return

    wshooker = WSHooker()
    wshooker.eval_script(args.script,
                         args.debug,
                         args.enable_shell,
                         args.disable_dns,
                         args.disable_net,
                         args.disable_com_init)

if __name__ == '__main__':
    main()