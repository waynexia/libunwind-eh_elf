/********** Libunwind -- eh_elf flavour **********
 * This is the eh_elf version of libunwind, made for academic purposes.
 *
 * Théophile Bastian <theophile.bastian@ens.fr> <contact+github@tobast.fr>
 *************************************************
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ************************************************/

#include "eh_elf.h"
#include "context_struct.h"
#include "libunwind.h"
#include "memory_map.h"
#include "remote.h"

int eh_elf_init_local() {
    return mmap_init_local();
}

int eh_elf_init_pid(pid_t pid) {
    Debug(3, "Init with pid\n");
    return mmap_init_pid(pid);
}

int eh_elf_init_mmap(unw_mmap_entry_t* entries, size_t count) {
    Debug(3, "Init with mmap\n");
    return mmap_init_mmap(entries, count);
}

void eh_elf_clear() {
    mmap_clear();
}

static struct {
    unw_addr_space_t addr_space;
    unw_accessors_t *accessors;
    void* arg;
} _fetch_state;

static uintptr_t fetchw_here(uintptr_t addr) {
    uintptr_t out;
    fetchw(_fetch_state.addr_space,
           _fetch_state.accessors,
           &addr,
           &out,
           _fetch_state.arg);
    return out;
}

dwarf_loc_t of_eh_elf_loc(uintptr_t eh_elf_loc) {
    if(eh_elf_loc + 1 == 0) // Undefined
        return DWARF_NULL_LOC;
    return DWARF_LOC(eh_elf_loc, DWARF_LOC_TYPE_VAL);
}

int eh_elf_step_cursor(struct cursor *cursor) {
    uintptr_t ip = cursor->dwarf.ip;

    // Check for the end of the call chain
    if(DWARF_IS_NULL_LOC(cursor->dwarf.loc[UNW_TDEP_IP]))
        return 0;
    if(!DWARF_IS_NULL_LOC(cursor->dwarf.loc[UNW_TDEP_BP])) {
        uintptr_t bp;
        dwarf_get(&cursor->dwarf,
                cursor->dwarf.loc[UNW_TDEP_BP], &bp);
        if(bp == 0)
            return 0;
    }

    // Retrieve memory map entry
    mmap_entry_t* mmap_entry = mmap_get_entry(ip);
    if(mmap_entry == NULL)
        return -1;

    Debug(5, "In memory map entry %lx-%lx (%s) - off %lx, ip %lx%s\n",
            mmap_entry->beg_ip,
            mmap_entry->end_ip,
            mmap_entry->object_name,
            mmap_entry->offset,
            ip - mmap_entry->offset,
            mmap_entry->eh_elf == NULL ? " [MISSING EH_ELF]" : "");

    // Retrieve a pointer to the eh_elf function
    _fde_func_with_deref_t fde_func =
        (_fde_func_with_deref_t) (dlsym(mmap_entry->eh_elf, "_eh_elf"));
    if(fde_func == NULL)
        return -2;

    // Setup an eh_elf context
    unwind_context_t eh_elf_context;
    eh_elf_context.rip = ip;
    dwarf_get(&cursor->dwarf,
            cursor->dwarf.loc[UNW_TDEP_SP], &eh_elf_context.rsp);
    dwarf_get(&cursor->dwarf,
            cursor->dwarf.loc[UNW_TDEP_BP], &eh_elf_context.rbp);

    // Set _fetch_state before passing fetchw_here
    _fetch_state.addr_space = cursor->dwarf.as;
    _fetch_state.accessors = &cursor->dwarf.as->acc;
    _fetch_state.arg = &cursor->dwarf.as_arg;

    Debug(4, "Unwinding in mmap entry %s at position 0x%lx\n",
            mmap_entry->object_name,
            ip - mmap_entry->offset);

    // Call fde_func
    eh_elf_context = fde_func(
            eh_elf_context,
            ip - mmap_entry->offset,
            fetchw_here);

    // Push back the data into libunwind's structures
    for (int i = 0; i < DWARF_NUM_PRESERVED_REGS; ++i)
        cursor->dwarf.loc[i] = DWARF_NULL_LOC;

    cursor->dwarf.loc[UNW_TDEP_BP] = of_eh_elf_loc(eh_elf_context.rbp);
    cursor->dwarf.loc[UNW_TDEP_SP] = of_eh_elf_loc(eh_elf_context.rsp);
    cursor->dwarf.loc[UNW_TDEP_IP] = of_eh_elf_loc(eh_elf_context.rip);
    cursor->dwarf.use_prev_instr = 1;

    cursor->frame_info.frame_type = UNW_X86_64_FRAME_GUESSED;
    cursor->frame_info.cfa_reg_rsp = 0;
    cursor->frame_info.cfa_reg_offset = 16;
    cursor->frame_info.rbp_cfa_offset = -16;
    cursor->dwarf.cfa += 16;
    cursor->dwarf.ip = eh_elf_context.rip;

    return 1;
}
