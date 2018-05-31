#include "memory_map.h"
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static mmap_entry_t* _memory_map = NULL;
static size_t _memory_map_size = 0;

/// Init the memory map with a given /proc/XX/ argument
int mmap_init_procdir(const char* procdir);


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
        if(lastch == '\n')
            nb_entries++;
    }
    rewind(map_handle);
    _memory_map = (mmap_entry_t*) calloc(nb_entries, sizeof(mmap_entry_t));
    _memory_map_size = nb_entries;

    // Read all lines
    uintptr_t ip_beg, ip_end, offset, inode;
    char is_x;
    char path[256];
    int cur_entry = 0;
    while(fscanf(map_handle,
                "%lX-%lX %*c%*c%c%*c %lX %*[0-9a-fA-F:] %ld %s",
                &ip_beg, &ip_end, &is_x, &offset, &inode, path) != EOF)
    {
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

    // Shrink _memory_map to only use up the number of relevant entries
    assert(_memory_map_size >= cur_entry);
    _memory_map_size = cur_entry; // Because of skipped entries
    _memory_map = (mmap_entry_t*)
        realloc(_memory_map, _memory_map_size * sizeof(mmap_entry_t));

    // dlopen corresponding eh_elf objects
    for(size_t id = 0; id < _memory_map_size; ++id) {
        char eh_elf_path[256];
        char* obj_basename = basename(_memory_map[id].object_name);
        sprintf(eh_elf_path, "%s.eh_elf.so", obj_basename);
        _memory_map[id].eh_elf = dlopen(eh_elf_path, RTLD_LAZY);
    }

    return 0;
}

void mmap_clear() {
    if(_memory_map != NULL) {
        for(size_t pos=0; pos < _memory_map_size; ++pos) {
            free(_memory_map[pos].object_name);
            dlclose(_memory_map[pos].eh_elf);
        }
        free(_memory_map);
    }
}
