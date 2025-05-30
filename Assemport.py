import ida_idaapi
import ida_funcs
import ida_kernwin
import ida_pro
import ida_auto
import ida_loader
import ida_fpro
import ida_bytes
import ida_hexrays
import ida_range
import idautils
import os

class Assemport(ida_idaapi.plugmod_t):
    def __del__(self):
        ida_kernwin.hide_wait_box()
        print("[Assemport] Finished.")
    
    def run(self, arg):
        step_sleep = 0.5
        ida_kernwin.show_wait_box("Processing Export")

        # Get Working-Path
        path = os.path.dirname(ida_loader.get_path(ida_loader.PATH_TYPE_CMD))
        output = os.path.join(path, "Assemport")

        print(f"[Assemport] Path = {path}")
        print(f"[Assemport] Output = {output}")

        # Create Output-Directory
        try:
            os.mkdir(output)
        except FileExistsError:
            pass
        except PermissionError:
            print(f"[Assemport] Permission denied: Unable to create '{output}'.")
        except Exception as e:
            print(f"[Assemport] An error occurred: {e}")

        try:
            all_eas = list(idautils.Functions())
            neas = len(all_eas)

            # Iterate each function
            for i, ea in enumerate(all_eas):
                if ida_kernwin.user_cancelled():
                    break

                # Get Func
                func = ida_funcs.get_func(ea)

                if func is None:
                    print("[Assemport] Not a Function, Skipping 0x%x" % ea)
                    continue

                # Get Name
                func_name = ida_funcs.get_func_name(ea)

                # Get Info
                range = ida_range.rangeset_t()
                if ida_funcs.get_func_ranges(range, func) == ida_idaapi.BADADDR:
                    print("[Assemport] Bad Range, Skipping 0x%x" % ea)
                    continue

                start = range.begin().start_ea
                end = range.begin().end_ea

                # Save Content
                file = ida_fpro.qfile_t()

                if file.open(os.path.join(output, "%s.asm" % func_name), "wt"):
                    try:
                        ida_loader.gen_file(ida_loader.OFILE_ASM, file.get_fp(), start, end, 0)
                    finally:
                        file.close()

                print(f"[Assemport] Handle function {func_name} on Address 0x{ea:x}")
                print(func);
                ida_kernwin.replace_wait_box("Processing Export...\n\n\t%d / %d\t" % (i + 1, neas))
                
        finally:
            ida_kernwin.hide_wait_box()