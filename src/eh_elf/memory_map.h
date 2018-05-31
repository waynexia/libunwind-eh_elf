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

/// A type representing a dlopen handle
typedef void* dl_obj_t;

/// A structure containing the informations gathererd about a line in the
/// memory map
typedef struct {
   int id;            ///< ID of this entry, for fast access
   uintptr_t offset;  ///< Total offset: ip + offset = ip in original ELF file
   char* object_name; ///< Name of the object mapped here
   uintptr_t beg_ip, end_ip; ///< Start and end IP of this object in memory
   dl_obj_t eh_elf;   ///< Corresponding eh_elf file, dlopen'd
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

/// Get the `mmap_entry_t` corresponding to the given IP
int mmap_get_entry(uintptr_t ip, mmap_entry_t* entry);
