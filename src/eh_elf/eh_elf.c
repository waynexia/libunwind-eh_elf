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

int eh_elf_init_local() {
    return mmap_init_local();
}

int eh_elf_init_pid(pid_t pid) {
    return mmap_init_pid(pid);
}

void eh_elf_clear() {
    mmap_clear();
}

int eh_elf_step_cursor(struct cursor *cursor) {
    // TODO implement
    return 0;
}
