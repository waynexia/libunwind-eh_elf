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
    struct cursor* cursor;
    int last_rc;
    uintptr_t cur_rsp;
} _fetch_state;

static uintptr_t fetchw_here(uintptr_t addr) {
    uintptr_t out;
    int rv = _fetch_state.cursor->dwarf.as->acc.access_mem(
            _fetch_state.cursor->dwarf.as,
            addr,
            &out,
            0,
            _fetch_state.cursor->dwarf.as_arg);

    if(rv != 0) {
        /*
            Recover from slightly out-of-sync DWARF
            ====

            When we're unwinding the first frame of a chain, and we start from,
            eg. a `pop %rbx` at the end of the function, the DWARF can be out
            of sync and still state that eg. `%rbx` is saved at something that
            simplifies to `%rsp-8`. Which might not be accessibe through the
            `access_mem` abstraction, eg. if we're running perf and it didn't
            capture the stack below `%rsp`
        */
        if(_fetch_state.cur_rsp - addr < 128) {
            Debug(3, "dwarf_get warning: tried to access %lX (%lX below rsp)\n",
                    addr, _fetch_state.cur_rsp - addr);
            return 0; // hope that nothing bad will happen.
        }
        Debug(1, "dwarf_get error %d (addr %lX, sp %lX)\n",
                rv, addr, _fetch_state.cur_rsp);
        _fetch_state.last_rc = rv;
    }

    return out;
}

dwarf_loc_t of_eh_elf_loc(uintptr_t eh_elf_loc, uint8_t flags, int flag_id) {
    if((flags & (1 << flag_id)) == 0)
        return DWARF_NULL_LOC;
    return DWARF_LOC(eh_elf_loc, DWARF_LOC_TYPE_VAL);
}

/** Sets `dest_reg` to `of_eh_elf_loc` if the provided register is not null.
 * Else, leave the `dest_reg` as-is. */
int set_dwarf_loc_ifdef(
        dwarf_loc_t* dest_reg, uintptr_t eh_elf_loc,
        uint8_t flags, int flag_id)
{
    if((flags & (1 << flag_id)) != 0) {
        *dest_reg = of_eh_elf_loc(eh_elf_loc, flags, flag_id);
        return 1;
    }
    return 0;
}

int eh_elf_step_cursor(struct cursor *cursor) {
    uintptr_t ip = cursor->dwarf.ip;
    {
        uintptr_t dbp;
        dwarf_get(&cursor->dwarf, cursor->dwarf.loc[UNW_TDEP_BP], &dbp);
        Debug (4, "AT ENTER bp=%016lx%s sp=%016lx ip=%016lx\n", dbp,
                DWARF_IS_NULL_LOC(cursor->dwarf.loc[UNW_TDEP_BP])?" [NULL]":"",
                cursor->dwarf.cfa, cursor->dwarf.ip);
    }

    // Retrieve memory map entry
    mmap_entry_t* mmap_entry = mmap_get_entry(ip);
    if(mmap_entry == NULL) {
        Debug(3, "No such mmap entry :(\n");
        return -1;
    }

    Debug(5, "In memory map entry %lx-%lx (%s) - off %lx, ip %lx%s\n",
            mmap_entry->beg_ip,
            mmap_entry->end_ip,
            mmap_entry->object_name,
            mmap_entry->offset,
            ip - mmap_entry->offset,
            mmap_entry->eh_elf == NULL ? " [MISSING EH_ELF]" : "");

    // Setup an eh_elf context
    unwind_context_t eh_elf_context;
    eh_elf_context.rip = ip;
    eh_elf_context.rsp = cursor->dwarf.cfa;
    dwarf_get(&cursor->dwarf,
            cursor->dwarf.loc[UNW_TDEP_BP], &eh_elf_context.rbp);
    dwarf_get(&cursor->dwarf,
            cursor->dwarf.loc[UNW_X86_64_RBX], &eh_elf_context.rbx);

    // Set _fetch_state before passing fetchw_here
    _fetch_state.cursor = cursor;
    _fetch_state.last_rc = 0;
    _fetch_state.cur_rsp = cursor->dwarf.cfa;

    Debug(4, "Unwinding in mmap entry %s at position 0x%lx (sp=%016lx, bp=%016lx)\n",
            mmap_entry->object_name,
            ip - mmap_entry->offset,
            eh_elf_context.rsp,
            eh_elf_context.rbp
            );

    eh_elf_context.flags = 0;
    // Call fde_func
    eh_elf_context = mmap_entry->fde_func(
            eh_elf_context,
            ip - mmap_entry->offset,
            fetchw_here);

    if(_fetch_state.last_rc != 0) {
        // access_mem error
        return -4;
    }

    if(((eh_elf_context.flags & (1 << UNWF_ERROR))) != 0) {
        // Error, somehow
        Debug(3, "eh_elf unwinding FAILED (fl=%02x), IP=0x%016lx\n",
                eh_elf_context.flags, ip);
        return -3;
    }

    if(((eh_elf_context.flags & (1 << UNWF_RIP))
                && eh_elf_context.rip < 10)
            || ((eh_elf_context.flags & (1 << UNWF_RSP))
                && eh_elf_context.rsp < 10))
    {
        Debug(4, "EH_ELF err. -5: rip=%lX, rsp=%lX (ip = %lX) Flags: %x (%d)\n",
                eh_elf_context.rip, eh_elf_context.rsp, ip,
                eh_elf_context.flags, eh_elf_context.flags & (1<<UNWF_RIP));
        return -5;
    }

    Debug(3, "EH_ELF: bp=%016lx sp=%016lx ip=%016lx\n",
            eh_elf_context.rbp,
            eh_elf_context.rsp,
            eh_elf_context.rip);
    Debug(3, "MMAP: %s %lx\n",
            mmap_entry->object_name,
            ip - mmap_entry->offset);

    // Push back the data into libunwind's structures

    cursor->dwarf.loc[UNW_TDEP_IP] = of_eh_elf_loc(
            eh_elf_context.rip, eh_elf_context.flags, UNWF_RIP);
    set_dwarf_loc_ifdef(
            &cursor->dwarf.loc[UNW_TDEP_BP],
            eh_elf_context.rbp,
            eh_elf_context.flags,
            UNWF_RBP);
    set_dwarf_loc_ifdef(
            &cursor->dwarf.loc[UNW_TDEP_SP],
            eh_elf_context.rsp,
            eh_elf_context.flags,
            UNWF_RSP);
    set_dwarf_loc_ifdef(
            &cursor->dwarf.loc[UNW_X86_64_RBX],
            eh_elf_context.rbx,
            eh_elf_context.flags,
            UNWF_RBX);
    cursor->dwarf.use_prev_instr = 0;

    cursor->frame_info.frame_type = UNW_X86_64_FRAME_GUESSED;
    cursor->frame_info.cfa_reg_rsp = 0;
    cursor->frame_info.cfa_reg_offset = 16;
    cursor->frame_info.rbp_cfa_offset = -16;
    cursor->dwarf.cfa = eh_elf_context.rsp;
    cursor->dwarf.ip = eh_elf_context.rip;

    // Check for the end of the call chain
    if(DWARF_IS_NULL_LOC(cursor->dwarf.loc[UNW_TDEP_IP])) {
        Debug(5, "End of call chain by null RA\n");
        return 0;
    }

    /* FIXME ignore RBP part for now
    if(!DWARF_IS_NULL_LOC(cursor->dwarf.loc[UNW_TDEP_BP])) {
        uintptr_t bp;
        dwarf_get(&cursor->dwarf,
                cursor->dwarf.loc[UNW_TDEP_BP], &bp);
        if(bp == 0) {
            Debug(5, "End of call chain by null base pointer\n");
            return 0;
        }
    }
    // */

    return 1;
}
