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
#include "libunwind_i.h"

/** Initialize everything for local memory analysis
 * @return 0 on success, or a negative value upon failure
 **/
int eh_elf_init_local();

/** Initialize everything for the remote analysis of the process of given PID
 * @return 0 on success, or a negative value upon failure
 **/
int eh_elf_init_pid(pid_t pid);

/// Cleanup everything that was allocated by eh_elf_init_*
void eh_elf_clear();

/** Step the cursor using eh_elf mechanisms.
 *
 * @return a positive value upon success, 0 if the frame before this unwinding
 * was the last one, or a negative value upon failure.
 **/
int eh_elf_step_cursor(struct cursor *cursor);
