#ifndef VAR_FILTER_H
#define VAR_FILTER_H

#include <stdbool.h>
#include <dirent.h>

typedef enum {
    MATCH_EXACT,
    MATCH_PREFIX,
    MATCH_SUFFIX,
    MATCH_CONTAINS,
    MATCH_REGEX
} MatchType;

typedef struct {
    MatchType type;
    const char *pattern;
} FilterRule;

typedef struct {
    const char *path;
    bool default_deny;
    FilterRule *whitelist;
    int whitelist_count;
    FilterRule *blacklist;
    int blacklist_count;
} DirRule;

void set_jailbreak_hidden_for_pid(pid_t pid, bool hidden);
bool is_jailbreak_hidden_for_current_process(void);
bool is_jailbreak_hidden_for_pid(pid_t pid);
bool should_hide_file(const char *dir_path, const char *name);
bool is_jailbreak_path(const char *path);
void init_var_filter(void);
void cleanup_var_filter(void);

typedef struct {
    DIR *real_dir;
    char dir_path[1024];
    struct dirent *buffer;
    pid_t owner_pid;
} FilteredDIR;

FilteredDIR *filtered_opendir(const char *name);
struct dirent *filtered_readdir(FilteredDIR *dirp);
int filtered_closedir(FilteredDIR *dirp);

#endif