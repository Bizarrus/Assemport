import ida_idaapi
import ida_funcs
import ida_kernwin
import idautils
from Assemport import Assemport

class AssemportPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL | ida_idaapi.PLUGIN_MULTI
    comment = "Assemport exports all functions separately in an assembly file."
    help = "Assemport exports all functions separately in an assembly file. This enables further processing by external tools such as an AI."
    wanted_name = "Assemport"
    wanted_hotkey = "F12"

    def init(self):
        return Assemport()

def PLUGIN_ENTRY():
    return AssemportPlugin()