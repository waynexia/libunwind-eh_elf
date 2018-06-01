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
    return mmap_init_pid(pid);
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

int eh_elf_step_cursor(struct cursor *cursor) {
    uintptr_t ip = cursor->dwarf.ip;

    // Retrieve memory map entry
    mmap_entry_t* mmap_entry = mmap_get_entry(ip);
    if(mmap_entry == NULL)
        return -1;

    // Retrieve a pointer to the eh_elf function
    _fde_func_with_deref_t fde_func =
        (_fde_func_t) (dlsym(mmap_entry->eh_elf, "_eh_elf"));
    if(fde_func == NULL)
        return -2;

    // Setup an eh_elf context
    unwind_context_t eh_elf_context;
    eh_elf_context.rip = ip;
    eh_elf_context.rsp = cursor->dwarf.loc[UNW_TDEP_SP].val;
    eh_elf_context.rbp = cursor->dwarf.loc[UNW_TDEP_BP].val;

    // Set _fetch_state before passing fetchw_here
    _fetch_state.addr_space = cursor->dwarf.as;
    _fetch_state.accessors = &cursor->dwarf.as->acc;

    // Call fde_func
    eh_elf_context = fde_func(
            eh_elf_context,
            ip - mmap_entry->offset,
            fetchw_here);

    // Check for the end of the call chain
    if(eh_elf_context.rbp == 0 || eh_elf_context.rip + 1 == 0)
        return 0;

    // Push back the data into libunwind's structures
    for (int i = 0; i < DWARF_NUM_PRESERVED_REGS; ++i)
        cursor->dwarf.loc[i] = DWARF_NULL_LOC;

    cursor->dwarf.loc[UNW_TDEP_BP].val = eh_elf_context.rbp;
    cursor->dwarf.loc[UNW_TDEP_SP].val = eh_elf_context.rsp;
    cursor->dwarf.loc[UNW_TDEP_IP].val = eh_elf_context.rip;
    cursor->dwarf.use_prev_instr = 1;

    cursor->frame_info.frame_type = UNW_X86_64_FRAME_GUESSED;
    cursor->frame_info.cfa_reg_rsp = 0;
    cursor->frame_info.cfa_reg_offset = 16;
    cursor->frame_info.rbp_cfa_offset = -16;
    cursor->dwarf.cfa += 16;

    return 1;
}
