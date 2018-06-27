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

#pragma once

#include <sys/types.h>
#include <stdint.h>
#include <dlfcn.h>

#include "libunwind.h"
#include "context_struct.h"

/// A type representing a dlopen handle
typedef void* dl_obj_t;

/// A linked list of dl_obj_t
typedef struct dl_obj_list {
   char* object_name;       ///< Name of the object mapped here
   dl_obj_t eh_elf;         ///< Corresponding eh_elf file, dlopen'd
   _fde_func_with_deref_t fde_func; ///< Fde deref function, directly
   struct dl_obj_list* next;     ///< Next item in the list
} dl_obj_list_t;

/// A structure containing the informations gathererd about a line in the
/// memory map
typedef struct {
   int id;            ///< ID of this entry, for fast access
   uintptr_t offset;  ///< Total offset: ip + offset = ip in original ELF file
   char* object_name; ///< Name of the object mapped here
   uintptr_t beg_ip, end_ip; ///< Start and end IP of this object in memory
   dl_obj_t eh_elf;   ///< Corresponding eh_elf file, dlopen'd
   _fde_func_with_deref_t fde_func; ///< Fde deref function, directly
} mmap_entry_t;

/// Dealloc all allocated memory and reset internal state
void mmap_clear();

/** Init the memory map for the local process
 * @returns 0 upon success, or a negative value upon failure.
 **/
int mmap_init_local();

/** Init the memory map for a remote process with the given pid
 * @returns 0 upon success, or a negative value upon failure.
 **/
int mmap_init_pid(pid_t pid);

/** Init the memory map from a provided memory map
 * @returns 0 upon success, or a negative value upon failure.
 **/
int mmap_init_mmap(unw_mmap_entry_t* entries, size_t count);

/** Get the `mmap_entry_t` corresponding to the given IP
 * @return a pointer to the corresponding memory map entry, or NULL upon
 * failure.
 **/
mmap_entry_t* mmap_get_entry(uintptr_t ip);
