#include "memory_map.h"
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "libunwind_i.h"

static mmap_entry_t* _memory_map = NULL;
static size_t _memory_map_size = 0;
static int _mmap_init_done = 0;

/// Init the memory map with a given /proc/XX/ argument
int mmap_init_procdir(const char* procdir);

/// Reorder the entries in `entries` by increasing (non-overlapping)
/// memory region
static int mmap_order_entries(mmap_entry_t* entries, size_t count);

/// `dlopen`s the corresponding eh_elf for each entry in `entries`.
static int mmap_dlopen_eh_elfs(mmap_entry_t* entries, size_t count);


static int compare_mmap_entry(const void* _e1, const void* _e2) {
    // We can't return e1->beg_ip - e2->beg_ip because of int overflows
    const mmap_entry_t *e1 = _e1,
                       *e2 = _e2;
    if(e1->beg_ip < e2->beg_ip)
        return -1;
    if(e1->beg_ip > e2->beg_ip)
        return 1;
    return 0;
}

int mmap_init_local() {
    return mmap_init_procdir("/proc/self/");
}


int mmap_init_pid(pid_t pid) {
    char procdir[64];
    sprintf(procdir, "/proc/%d/", pid);
    return mmap_init_procdir(procdir);
}

int mmap_init_procdir(const char* procdir) {
    // This function reads /proc/pid/maps and deduces the memory map

    mmap_clear();

    // Open the mmap file
    char map_path[128];
    sprintf(map_path, "%s/maps", procdir);
    FILE* map_handle = fopen(map_path, "r");
    if(map_handle == NULL)
        return -1;

    // Get line count
    int nb_entries = 0;
    int lastch;
    while((lastch = fgetc(map_handle)) != EOF) {
        if(lastch == '\n') {
            nb_entries++;
        }
    }
    rewind(map_handle);
    _memory_map = (mmap_entry_t*) calloc(nb_entries, sizeof(mmap_entry_t));
    _memory_map_size = nb_entries;

    // Read all lines
    uintptr_t ip_beg, ip_end, offset, inode;
    char is_x;
    char path[256];
    int cur_entry = 0;
    int pos_before_path;
    char* line = malloc(512 * sizeof(char));
    size_t line_size = 512;
    while(getline(&line, &line_size, map_handle) >= 0)
    {
        sscanf(line,
                "%lX-%lX %*c%*c%c%*c %lX %*[0-9a-fA-F:] %ld %n",
                &ip_beg, &ip_end, &is_x, &offset, &inode, &pos_before_path);
        sscanf(line + pos_before_path, "%s", path);
        if(cur_entry >= nb_entries) {
            mmap_clear();
            return -2; // Bad entry count, somehow
        }

        if(inode == 0) // Special region, out of our scope
            continue;
        if(is_x != 'x') // Not executable, out of our scope
            continue;

        _memory_map[cur_entry].id = cur_entry;
        _memory_map[cur_entry].offset = ip_beg - offset;
        _memory_map[cur_entry].beg_ip = ip_beg;
        _memory_map[cur_entry].end_ip = ip_end;
        _memory_map[cur_entry].object_name =
            (char*) malloc(sizeof(char) * (strlen(path) + 1));
        strcpy(_memory_map[cur_entry].object_name, path);

        cur_entry++;
    }
    free(line);

    // Shrink _memory_map to only use up the number of relevant entries
    assert(_memory_map_size >= (size_t)cur_entry);
    _memory_map_size = cur_entry; // Because of skipped entries
    _memory_map = (mmap_entry_t*)
        realloc(_memory_map, _memory_map_size * sizeof(mmap_entry_t));

    // Ensure the entries are sorted by ascending ip range
    if(mmap_order_entries(_memory_map, _memory_map_size) < 0)
        return -3;

    // dlopen corresponding eh_elf objects
    if(mmap_dlopen_eh_elfs(_memory_map, _memory_map_size) < 0)
        return -4;

    _mmap_init_done = 1;

    return 0;
}

int mmap_init_mmap(unw_mmap_entry_t* entries, size_t count) {
    Debug(3, "Start reading mmap (entries=%016lx)\n", (uintptr_t)entries);
    Debug(3, "%lu entries\n", count);

    mmap_clear();

    _memory_map = (mmap_entry_t*) calloc(count, sizeof(mmap_entry_t));
    _memory_map_size = count;

    int mmap_pos = 0;
    for(int pos=0; pos < (int)count; ++pos) {
        if(entries[pos].object_name[0] == '[') {
            // Special entry (stack,vdso, …)
            continue;
        }

        Debug(3, "> MMAP %016lx-%016lx %s\n",
                entries[pos].beg_ip,
                entries[pos].end_ip,
                entries[pos].object_name);

        _memory_map[mmap_pos].id = pos;
        _memory_map[mmap_pos].offset = entries[pos].offset;
        _memory_map[mmap_pos].beg_ip = entries[pos].beg_ip;
        _memory_map[mmap_pos].end_ip = entries[pos].end_ip;
        _memory_map[mmap_pos].object_name =
            malloc(strlen(entries[pos].object_name) + 1);
        strcpy(_memory_map[mmap_pos].object_name, entries[pos].object_name);

        ++mmap_pos;
    }

    // Shrink memory map
    _memory_map_size = mmap_pos;
    _memory_map = (mmap_entry_t*)
        realloc(_memory_map, _memory_map_size * sizeof(mmap_entry_t));

    if(mmap_order_entries(_memory_map, _memory_map_size) < 0)
        return -3;
    if(mmap_dlopen_eh_elfs(_memory_map, _memory_map_size) < 0)
        return -4;

    _mmap_init_done = 1;
    Debug(3, "Init complete\n");
    return 0;
}

/// Ensure entries in the memory map are ordered by ascending beg_ip
static int mmap_order_entries(mmap_entry_t* entries, size_t count) {
    qsort(entries, count, sizeof(mmap_entry_t),
            compare_mmap_entry);
    for(size_t pos = 0; pos < count; ++pos)
        entries[pos].id = pos;
    return 0;
}

/// `dlopen` the needed eh_elf objects.
static int mmap_dlopen_eh_elfs(mmap_entry_t* entries, size_t count) {
    for(size_t id = 0; id < count; ++id) {
        char eh_elf_path[256];
        char* obj_basename = basename(entries[id].object_name);
        sprintf(eh_elf_path, "%s.eh_elf.so", obj_basename);
        entries[id].eh_elf = dlopen(eh_elf_path, RTLD_LAZY);
        if(entries[id].eh_elf == NULL)
            return -1;
    }
    return 0;
}

void mmap_clear() {
    _mmap_init_done = 0;

    if(_memory_map != NULL) {
        for(size_t pos=0; pos < _memory_map_size; ++pos) {
            free(_memory_map[pos].object_name);
            dlclose(_memory_map[pos].eh_elf);
        }
        free(_memory_map);
    }
}

static int bsearch_compar_mmap_entry(const void* vkey, const void* vmmap_elt) {
    uintptr_t key = *(uintptr_t*)vkey;
    const mmap_entry_t* mmap_elt = (const mmap_entry_t*) vmmap_elt;

    if(mmap_elt->beg_ip <= key && key < mmap_elt->end_ip)
        return 0;
    if(key < mmap_elt->beg_ip)
        return -1;
    return 1;
}

mmap_entry_t* mmap_get_entry(uintptr_t ip) {
    // Perform a binary search to find the requested ip

    Debug(3, "Getting mmap entry %016lx\n", ip);
    if(!_mmap_init_done) {
        Debug(1, "Mmap access before init! Aborting\n");
        return NULL;
    }
    return bsearch(
            (void*)&ip,
            (void*)_memory_map,
            _memory_map_size,
            sizeof(mmap_entry_t),
            bsearch_compar_mmap_entry);
}
