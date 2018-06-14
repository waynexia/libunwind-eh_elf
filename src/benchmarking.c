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

#include <time.h>
#include <stdint.h>
#include <stdio.h>

typedef struct timespec chrono_t;

static const long NSEC_MAX = 1000 * 1000 * 1000;
static chrono_t _timer_accu = {
    .tv_sec = 0,
    .tv_nsec = 0
};
static size_t _call_count = 0;

static void normalize_timer(chrono_t* timer) {
    if(timer->tv_nsec >= NSEC_MAX) {
        timer->tv_sec++;
        timer->tv_nsec -= NSEC_MAX;
    }
    else if(timer->tv_nsec < 0) {
        timer->tv_sec--;
        timer->tv_nsec += NSEC_MAX;
    }
}

static void timer_add(chrono_t* out, chrono_t t1, chrono_t t2) {
    out->tv_sec = t1.tv_sec + t2.tv_sec;
    out->tv_nsec = t1.tv_nsec + t2.tv_nsec;
    normalize_timer(out);
}

static void timer_diff(chrono_t* out, chrono_t t1, chrono_t t2) {
    out->tv_sec = t2.tv_sec - t1.tv_sec;
    out->tv_nsec = t2.tv_nsec - t1.tv_nsec;
    normalize_timer(out);
}

chrono_t chrono_start() {
    chrono_t out;
    clock_gettime(CLOCK_REALTIME, &out);
    return out;
}

void chrono_end(chrono_t start) {
    chrono_t diff;
    ++_call_count;
    timer_diff(&diff, start, chrono_start());
    timer_add(&_timer_accu, _timer_accu, diff);
}

chrono_t chrono_report() {
    return _timer_accu;
}

void chrono_report_disp() {
    fprintf(stderr,
            "=============== BENCH ===============\n"
            "Total unwind time: %ld s %ld ns, %lu calls\n",
            _timer_accu.tv_sec,
            _timer_accu.tv_nsec,
            _call_count);
}
