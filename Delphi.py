"""
  +------------------------------------------------------------------------+
  | IDA for Delphi – VCL event-constructor tracer (IDA 9.x)                |
  +------------------------------------------------------------------------+
    Copyright(c) 2025 - Coldzer0 <Coldzer0 [at] protonmail.ch> @Coldzer0x0
"""

import ida_dbg
import ida_ida
import ida_bytes
import ida_funcs
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_ua
import ida_name

# -------------------------------------------------------------------------
#  Helpers
# -------------------------------------------------------------------------
def find_ret(start_ea, max_scan = 0x40):
    """Return the EA of the first 0xC3 within max_scan bytes (or None)."""
    ea = start_ea
    for _ in range(max_scan):
        if ida_bytes.get_byte(ea) == 0xC3:
            return ea
        ea += 1
    return None


# -------------------------------------------------------------------------
#  Debug-hook class
# -------------------------------------------------------------------------
class VCLDbgHook(ida_dbg.DBG_Hooks):
    """
    Own debug hook class that implementd the callback functions
    Ref: https://github.com/idapython/src/blob/master/examples/debugger/dbghooks/automatic_steps.py
    """

    def __init__(self):
        ida_dbg.DBG_Hooks.__init__(self)  # important 
        self.constructor_ret = ida_idaapi.BADADDR
        self.entry_point = ida_idaapi.BADADDR
        self.INDEX = 0

    def log(self, msg):
        ida_kernwin.msg(">>> [+] %s \n" % msg)

    # ---- breakpoint callback --------------------------------------------
    def dbg_bpt(self, tid, ea):
        if ea == self.constructor_ret:  # VCL constructor
            
            ida_dbg.refresh_debugger_memory()

            if ida_ida.inf_is_64bit():  
                name_ptr = ida_dbg.get_reg_val("RDX")
                fn_ea = ida_dbg.get_reg_val("RAX")
            elif ida_ida.inf_is_32bit_exactly():  
                name_ptr = ida_dbg.get_reg_val("EDX")
                fn_ea = ida_dbg.get_reg_val("EAX")
            else:  
                self.log("Unsupported Arch")
                return 0

            event_name = ida_bytes.get_strlit_contents(
                name_ptr + 1, 
                ida_bytes.get_byte(name_ptr), # Str len
                ida_nalt.STRTYPE_C
            )
            if not event_name:
                event_name = "_DE_UNKOWN_%d" % self.INDEX 
                self.INDEX += 1
                self.log("Failed to read event name @ 0x%X - Using a temp name: %s" % (name_ptr, event_name))

            callback_name = f"_DE_{event_name}"

            ida_ua.create_insn(fn_ea)
            if not ida_funcs.get_func(fn_ea):
                ida_funcs.add_func(fn_ea)
            ida_name.set_name(fn_ea, callback_name, ida_name.SN_PUBLIC | ida_name.SN_FORCE)
            
            ida_dbg.add_bpt(fn_ea)  # keep tracing calls
            self.log("VCL Event '%-8s' → 0x%X" % (callback_name, fn_ea))
            ida_dbg.continue_process()
            
        elif ea == self.entry_point:  # just resume from entry BP
            ida_dbg.del_bpt(ea)
            ida_dbg.continue_process()
            
        return 0

    def dbg_run_to(self, pid, tid, ea):
        ida_dbg.continue_process()
        
    def dbg_process_exit(self, pid, tid, ea, code):
        self.log("Process exited (pid=%d tid=%d code=%d)" % (pid, tid, code))
        return 0


# -------------------------------------------------------------------------
#  Script entry point
# -------------------------------------------------------------------------
   
# detect bitness
is64 = ida_ida.inf_is_64bit() 
is32 = ida_ida.inf_is_32bit_exactly()

# compile pattern
patterns = ida_bytes.compiled_binpat_vec_t()
enc_idx = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)

if is64:
    pat = "80 ?? ?? 00 74 ?? E8 ?? ?? ?? ?? 48 8B ?? ?? 48 8D ??"
elif is32:
    pat = "80 E3 DF 75 ?? 49 75 ?? 8B 46 02 ?? ?? 5B C3"
else:
    ida_kernwin.warning("Unsupported file-format bitness\n")
    exit()

if ida_bytes.parse_binpat_str(patterns, 0, pat, 16, enc_idx):
    ida_kernwin.warning("Failed to compile binary pattern\n")
    exit()

match, _ = ida_bytes.bin_search(
    0,
    ida_ida.inf_get_max_ea(),
    patterns,
    ida_bytes.BIN_SEARCH_FORWARD
    | ida_bytes.BIN_SEARCH_NOBREAK
    | ida_bytes.BIN_SEARCH_NOSHOW,
)
if match == ida_idaapi.BADADDR:
    ida_kernwin.warning("Pattern not found\n")
    exit()

vlc_ctor_ret_ea = find_ret(match)
if vlc_ctor_ret_ea is None:
    ida_kernwin.warning("RET not found after pattern @ 0x%X\n" % match)
    exit()

# Remove an existing debug hook
ida_kernwin.msg("Check previous hook ...\n")
try:
    if debughook:
        ida_kernwin.msg("Removing previous hook ...\n")
        debughook.unhook()
        del debughook
    else:
        ida_kernwin.msg("No previous hook ...\n")
except:
    pass

# hook & breakpoints

ida_kernwin.msg("Installing debug hook & breakpoints ...\n")
debughook = VCLDbgHook()
debughook.constructor_ret = vlc_ctor_ret_ea
debughook.entry_point = ida_ida.inf_get_start_ip()

ida_dbg.add_bpt(debughook.constructor_ret)
ida_kernwin.msg("VCL Constructor BP @ 0x%X \n" % (debughook.constructor_ret))

if not debughook.hook():
    ida_kernwin.warning(">>> Hook is not installed <<<")
    exit()
    
# Run
if not ida_dbg.run_to(debughook.entry_point):
    ida_kernwin.warning("Impossible to prepare debugger requests. Is a debugger selected?\n")
