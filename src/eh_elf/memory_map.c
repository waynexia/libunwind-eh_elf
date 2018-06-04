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


static int compare_mmap_entry(const void* e1, const void* e2) {
    return ((mmap_entry_t*)e1)->beg_ip - ((mmap_entry_t*)e2)->beg_ip;
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
        _memory_map[cur_entry].offset = offset;
        _memory_map[cur_entry].beg_ip = ip_beg;
        _memory_map[cur_entry].end_ip = ip_end;
        _memory_map[cur_entry].object_name =
            (char*) malloc(sizeof(char) * (strlen(path) + 1));
        strcpy(_memory_map[cur_entry].object_name, path);

        cur_entry++;
    }
    free(line);

    // Shrink _memory_map to only use up the number of relevant entries
    assert(_memory_map_size >= cur_entry);
    _memory_map_size = cur_entry; // Because of skipped entries
    _memory_map = (mmap_entry_t*)
        realloc(_memory_map, _memory_map_size * sizeof(mmap_entry_t));

    // Ensure the entries are sorted by ascending ip range
    qsort(_memory_map, _memory_map_size, sizeof(mmap_entry_t),
            compare_mmap_entry);

    // dlopen corresponding eh_elf objects
    for(size_t id = 0; id < _memory_map_size; ++id) {
        char eh_elf_path[256];
        char* obj_basename = basename(_memory_map[id].object_name);
        sprintf(eh_elf_path, "%s.eh_elf.so", obj_basename);
        _memory_map[id].eh_elf = dlopen(eh_elf_path, RTLD_LAZY);
    }

    _mmap_init_done = 1;

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

    if(!_mmap_init_done)
        return NULL;

    return bsearch(
            (void*)&ip,
            (void*)_memory_map,
            _memory_map_size,
            sizeof(mmap_entry_t),
            bsearch_compar_mmap_entry);
}
