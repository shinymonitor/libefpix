#ifndef _CONSTRUCT_H
#define _CONSTRUCT_H

//================================================================
//SECTION: Config
//================================================================

#define CONSTRUCT_DEF static inline

//================================================================
//SECTION: Includes
//================================================================

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/stat.h> 

//================================================================
//SECTION: Platform
//================================================================

#ifdef _WIN32
	#include <direct.h>
	#define CONSTRUCT_NL "\r\n"
	#define CONSTRUCT_PS "\\"
    #define CONSTRUCT_PS_CHR '\\'
    #define CONSTRUCT_CS "&&"
    #define CONSTRUCT_MKDIR_CMD "if not exist \"%s\" mkdir \"%s\""
    #define CONSTRUCT_CP_CMD "copy /Y \"%s\" \"%s\""
    #define CONSTRUCT_CP_R_CMD "echo d | xcopy /Y /E /I \"%s\\\" \"%s\\\""
    #define CONSTRUCT_MV_CMD "move /Y \"%s\" \"%s\""
	#define CONSTRUCT_RM_CMD "del /Q \"%s\""
	#define CONSTRUCT_RMDIR_CMD "rmdir /S /Q \"%s\""
    #define CONSTRUCT_FETCH_CMD "powershell -Command \"Invoke-WebRequest -Uri '%s' -OutFile '%s'\""
#else
	#define CONSTRUCT_NL "\n"
	#define CONSTRUCT_PS "/"
    #define CONSTRUCT_PS_CHR '/'
    #define CONSTRUCT_CS ";"
    #define CONSTRUCT_MKDIR_CMD "mkdir -p \"%s\""
    #define CONSTRUCT_CP_CMD "cp \"%s\" \"%s\""
    #define CONSTRUCT_CP_R_CMD "cp -r \"%s/.\" \"%s\""
    #define CONSTRUCT_MV_CMD "mv \"%s\" \"%s\""
	#define CONSTRUCT_RM_CMD "rm \"%s\""
	#define CONSTRUCT_RMDIR_CMD "rm -rf \"%s\""
	#define CONSTRUCT_FETCH_CMD "wget -q --show-progress \"%s\" -O \"%s\""
#endif

//================================================================
//SECTION: assert, realloc, free
//================================================================

#ifndef CONSTRUCT_ASSERT
#include <assert.h>
#define CONSTRUCT_ASSERT assert
#endif
#ifndef CONSTRUCT_REALLOC
#include <stdlib.h>
#define CONSTRUCT_REALLOC realloc
#endif
#ifndef CONSTRUCT_FREE
#include <stdlib.h>
#define CONSTRUCT_FREE free
#endif

//================================================================
//SECTION: Dynamic Arrays
//================================================================

#ifndef CONSTRUCT_DA_INIT_CAP
#define CONSTRUCT_DA_INIT_CAP 256
#endif
#define CONSTRUCT_da_define(item_t, da_t) typedef struct {item_t* items; size_t count, capacity;} da_t
#define CONSTRUCT_da_reserve(da, expected_capacity) do { \
    if ((expected_capacity) > (da)->capacity) { \
        if ((da)->capacity == 0) (da)->capacity = CONSTRUCT_DA_INIT_CAP; \
        while ((expected_capacity) > (da)->capacity) (da)->capacity *= 2; \
        (da)->items = CONSTRUCT_REALLOC((da)->items, (da)->capacity * sizeof(*(da)->items)); CONSTRUCT_ASSERT((da)->items != NULL && "DA RESERVE FAILED"); \
    } \
    else if ((expected_capacity) < (da)->capacity/2 && (da)->capacity > CONSTRUCT_DA_INIT_CAP) { \
        do {(da)->capacity /= 2;} while ((da)->capacity > CONSTRUCT_DA_INIT_CAP && (expected_capacity) <= (da)->capacity/2); \
        (da)->items = CONSTRUCT_REALLOC((da)->items, (da)->capacity * sizeof(*(da)->items)); CONSTRUCT_ASSERT((da)->items != NULL && "DA RESERVE FAILED"); \
    } \
} while (0)
#define CONSTRUCT_da_append(da, item) do {CONSTRUCT_da_reserve((da), (da)->count + 1); (da)->items[(da)->count++] = (item);} while (0)
#define CONSTRUCT_da_append_many(da, new_items, new_items_count) do {CONSTRUCT_da_reserve((da), (da)->count + (new_items_count)); memcpy((da)->items + (da)->count, (new_items), (new_items_count)*sizeof(*(da)->items)); (da)->count += (new_items_count);} while (0)
#define CONSTRUCT_da_resize(da, new_size) do {CONSTRUCT_da_reserve((da), new_size); (da)->count = (new_size);} while (0)

#define CONSTRUCT_da_remove_unordered(da, i) do {size_t j = (i); CONSTRUCT_ASSERT(j < (da)->count); (da)->items[j] = (da)->items[--(da)->count];} while(0)
#define CONSTRUCT_da_foreach(Type, it, da) for (Type* it = (da)->items; it < (da)->items + (da)->count; ++it)
#define CONSTRUCT_da_reset(da) (da)->count=0
#define CONSTRUCT_da_free(da) do {(da)->count=0; (da)->capacity=0; CONSTRUCT_FREE((da)->items); (da)->items = NULL;} while(0)

//================================================================
//String Builder
//================================================================

CONSTRUCT_da_define(char, CONSTRUCT_StringBuilder);

#define CONSTRUCT_sb_append_chr(sb, chr) CONSTRUCT_da_append(sb, chr)
#define CONSTRUCT_sb_append_buf(sb, buf, size) CONSTRUCT_da_append_many(sb, buf, size)
#define CONSTRUCT_sb_append_str(sb, str)  do {const char* s = (str); size_t n = strlen(s); CONSTRUCT_da_append_many(sb, s, n);} while (0)
#define CONSTRUCT_sb_append_null(sb) CONSTRUCT_da_append(sb, '\0')

#define CONSTRUCT_sb_str(sb) (sb)->items
#define CONSTRUCT_sb_len(sb) (sb)->count
#define CONSTRUCT_sb_get(sb, index) (CONSTRUCT_ASSERT((sb)->count>index), (sb)->items[index])
#define CONSTRUCT_sb_last(sb) (sb)->items[(CONSTRUCT_ASSERT((sb)->count > 0), (sb)->count-1)]
#define CONSTRUCT_sb_foreach(it, da) CONSTRUCT_da_foreach(char, it, da)
#define CONSTRUCT_sb_reset(sb) CONSTRUCT_da_reset((sb))
#define CONSTRUCT_sb_free(sb) CONSTRUCT_da_free((sb))

#define CONSTRUCT_SB_Fmt "%.*s"
#define CONSTRUCT_SB_Arg(sb) (int)(sb)->count, (sb)->items

//================================================================
//Temp functions
//================================================================

CONSTRUCT_da_define(char, CONSTRUCT_Temp);

static CONSTRUCT_Temp CONSTRUCT_global_temp = {0};

CONSTRUCT_DEF char* CONSTRUCT_temp_sprintf(const char* format, ...) {
    va_list args;
    va_start(args, format);
    size_t n = vsnprintf(NULL, 0, format, args);
    va_end(args);
    CONSTRUCT_da_resize(&CONSTRUCT_global_temp, n+1);
    va_start(args, format);
    vsnprintf(CONSTRUCT_global_temp.items, n + 1, format, args);
    va_end(args);
    return CONSTRUCT_global_temp.items;
}
CONSTRUCT_DEF char* CONSTRUCT_temp_strdup(char* str){
    size_t n = strlen(str);
    CONSTRUCT_da_resize(&CONSTRUCT_global_temp, n+1);
    memcpy(CONSTRUCT_global_temp.items, str, n);
    CONSTRUCT_global_temp.items[n] = '\0';
    return CONSTRUCT_global_temp.items;
}
CONSTRUCT_DEF char* CONSTRUCT_temp_strndup(char* str, size_t n){
    CONSTRUCT_da_resize(&CONSTRUCT_global_temp, n+1);
    memcpy(CONSTRUCT_global_temp.items, str, n);
    CONSTRUCT_global_temp.items[n] = '\0';
    return CONSTRUCT_global_temp.items;
}
CONSTRUCT_DEF void CONSTRUCT_temp_reset(void) {CONSTRUCT_da_reset(&CONSTRUCT_global_temp);}
CONSTRUCT_DEF void CONSTRUCT_temp_free(void) {CONSTRUCT_da_free(&CONSTRUCT_global_temp);}

CONSTRUCT_DEF char* CONSTRUCT_utemp_sprintf(CONSTRUCT_Temp* temp, const char* format, ...) {
    va_list args;
    va_start(args, format);
    size_t n = vsnprintf(NULL, 0, format, args);
    va_end(args);
    CONSTRUCT_da_resize(temp, n+1);
    va_start(args, format);
    vsnprintf(temp->items, n + 1, format, args);
    va_end(args);
    return temp->items;
}
CONSTRUCT_DEF char* CONSTRUCT_utemp_strdup(CONSTRUCT_Temp* temp, char* str){
    size_t n = strlen(str);
    CONSTRUCT_da_resize(temp, n+1);
    memcpy(temp->items, str, n);
    temp->items[n] = '\0';
    return temp->items;
}
CONSTRUCT_DEF char* CONSTRUCT_utemp_strndup(CONSTRUCT_Temp* temp, char* str, size_t n){
    CONSTRUCT_da_resize(temp, n+1);
    memcpy(temp->items, str, n);
    temp->items[n] = '\0';
    return temp->items;
}
CONSTRUCT_DEF void CONSTRUCT_utemp_reset(CONSTRUCT_Temp* temp) {CONSTRUCT_da_reset(temp);}
CONSTRUCT_DEF void CONSTRUCT_utemp_free(CONSTRUCT_Temp* temp) {CONSTRUCT_da_free(temp);}

//================================================================
//SECTION: Logging
//================================================================

typedef enum {CONSTRUCT_INFO, CONSTRUCT_WARNING, CONSTRUCT_ERROR} CONSTRUCT_LogType;

CONSTRUCT_DEF void CONSTRUCT_print_log(CONSTRUCT_LogType level, const char* fmt, ...) {
    switch (level) {
        case CONSTRUCT_INFO: 
            printf("[INFO] "); 
            break;
        case CONSTRUCT_WARNING: 
            #ifndef _WIN32
                printf("\x1B[33m");
            #endif
            printf("[WARNING] "); 
            break;
        case CONSTRUCT_ERROR:
            #ifndef _WIN32 
                printf("\x1B[31;1;4m");
            #endif
            printf("[ERROR] "); 
            break;
    }
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    #ifndef _WIN32
        printf("\x1B[0m");
    #endif
    printf(CONSTRUCT_NL);
}
CONSTRUCT_DEF void CONSTRUCT_fprint_log(const char* file_path, CONSTRUCT_LogType level, const char* fmt, ...) {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    FILE* file=fopen(file_path, "a");
    if (file == NULL) return;
    fprintf(file, "[%d/%02d/%02d@%02d:%02d:%02d] ", t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);
    switch (level) {
        case CONSTRUCT_INFO: fprintf(file, "[INFO] "); break;
        case CONSTRUCT_WARNING: fprintf(file, "[WARNING] "); break;
        case CONSTRUCT_ERROR: fprintf(file, "[ERROR] "); break;
    }
    va_list args;
    va_start(args, fmt);
    vfprintf(file, fmt, args);
    if (level == CONSTRUCT_ERROR) fflush(file);
    va_end(args);
    fprintf(file, CONSTRUCT_NL);
    fclose(file);
}

//================================================================
//SECTION: File Handling
//================================================================

CONSTRUCT_DEF bool CONSTRUCT_file_exists(char* file_path){FILE* file; if ((file = fopen(file_path, "r"))) {fclose(file); return true;} return false;}
CONSTRUCT_DEF time_t CONSTRUCT_get_mtime(char* file_path) {struct stat st; if (stat(file_path, &st) == -1) return 0; return st.st_mtime;}
CONSTRUCT_DEF bool CONSTRUCT_is_newer(char* new_path, char* old_path){
	time_t new_mtime = CONSTRUCT_get_mtime(new_path);
	time_t old_mtime = CONSTRUCT_get_mtime(old_path);
	if (new_mtime == 0 || old_mtime == 0) return true;
	return new_mtime > old_mtime;
}
CONSTRUCT_DEF const char* CONSTRUCT_path_basename(const char* path){const char* p = strrchr(path, CONSTRUCT_PS_CHR); return p ? p + 1 : path;}
typedef struct {uint8_t* bytes; size_t bytes_count;} CONSTRUCT_FileBytes;
CONSTRUCT_DEF bool CONSTRUCT_read_entire_file(const char* file_path, CONSTRUCT_FileBytes* file_bytes) {
    FILE* file_handle = fopen(file_path, "rb");
    if (file_handle == NULL) return false;
    if(fseek(file_handle, 0, SEEK_END)!=0) {fclose(file_handle); return false;}
    int64_t file_size = ftell(file_handle);
    if (file_size < 0) {fclose(file_handle); return false;}
    if (file_size == 0) {file_bytes->bytes_count = 0; fclose(file_handle); return true;}
    if(fseek(file_handle, 0, SEEK_SET)!=0) {fclose(file_handle); return false;}
    file_bytes->bytes=(uint8_t*)realloc(file_bytes->bytes, (size_t)file_size);
    if(!file_bytes->bytes) {fclose(file_handle); return false;}
    file_bytes->bytes_count = fread(file_bytes->bytes, 1, (size_t)file_size, file_handle);
    bool ok = !ferror(file_handle);
    fclose(file_handle);
    return ok;
}
CONSTRUCT_DEF bool CONSTRUCT_write_entire_file(const char* file_path, const void* data, size_t size) {
    FILE* file = fopen(file_path, "wb");
    if (file == NULL) return false;
    size_t bytes_written = fwrite(data, 1, size, file);
    fclose(file);
    return bytes_written == size;
}

CONSTRUCT_DEF bool CONSTRUCT_mkdir_if_not_exists(const char* path){
    #ifdef _WIN32
        return (!system(CONSTRUCT_temp_sprintf(CONSTRUCT_MKDIR_CMD, path, path)));
    #else
        return (!system(CONSTRUCT_temp_sprintf(CONSTRUCT_MKDIR_CMD, path)));
    #endif
}
CONSTRUCT_DEF bool CONSTRUCT_copy_file(const char* src_path, const char* dst_path){return (!system(CONSTRUCT_temp_sprintf(CONSTRUCT_CP_CMD, src_path, dst_path)));}
CONSTRUCT_DEF bool CONSTRUCT_copy_directory_recursively(const char* src_path, const char* dst_path) {return (!system(CONSTRUCT_temp_sprintf(CONSTRUCT_CP_R_CMD, src_path, dst_path)));}
CONSTRUCT_DEF bool CONSTRUCT_move_file(const char* src_path, const char* dst_path) {return (!system(CONSTRUCT_temp_sprintf(CONSTRUCT_MV_CMD, src_path, dst_path)));}
CONSTRUCT_DEF bool CONSTRUCT_delete_file(const char* path) {return (!system(CONSTRUCT_temp_sprintf(CONSTRUCT_RM_CMD, path)));}
CONSTRUCT_DEF bool CONSTRUCT_delete_directory(const char* path) {return (!system(CONSTRUCT_temp_sprintf(CONSTRUCT_RMDIR_CMD, path)));}
CONSTRUCT_DEF bool CONSTRUCT_fetch_file(const char* path, const char* url) {return (!system(CONSTRUCT_temp_sprintf(CONSTRUCT_FETCH_CMD, url, path)));}

#define CONSTRUCT_mkdir_if_not_exists_l(path) do {if(CONSTRUCT_mkdir_if_not_exists(path)) CONSTRUCT_print_log(CONSTRUCT_INFO, "CREATED DIRECTORY %s", path); else CONSTRUCT_print_log(CONSTRUCT_ERROR, "COULDNT CREATE DIRECTORY %s", path);} while(0)
#define CONSTRUCT_copy_file_l(src_path, dst_path) do {if(CONSTRUCT_copy_file(src_path, dst_path)) CONSTRUCT_print_log(CONSTRUCT_INFO, "COPIED FILE %s TO %s", src_path, dst_path); else CONSTRUCT_print_log(CONSTRUCT_ERROR, "COULDNT COPY FILE %s TO %s", src_path, dst_path);} while(0)
#define CONSTRUCT_copy_directory_recursively_l(src_path, dst_path) do {if(CONSTRUCT_copy_directory_recursively(src_path, dst_path)) CONSTRUCT_print_log(CONSTRUCT_INFO, "RECURSIVELY COPIED DIRECTORY %s TO %s", src_path, dst_path); else CONSTRUCT_print_log(CONSTRUCT_ERROR, "COULDNT RECURSIVELY COPY DIRECTORY %s TO %s", src_path, dst_path);} while(0)
#define CONSTRUCT_move_file_l(src_path, dst_path) do {if(CONSTRUCT_move_file(src_path, dst_path)) CONSTRUCT_print_log(CONSTRUCT_INFO, "MOVED FILE %s TO %s", src_path, dst_path); else CONSTRUCT_print_log(CONSTRUCT_ERROR, "COULDNT MOVE FILE %s TO %s", src_path, dst_path);} while(0)
#define CONSTRUCT_delete_file_l(path) do {if(CONSTRUCT_delete_file(path)) CONSTRUCT_print_log(CONSTRUCT_INFO, "DELETED FILE %s", path); else CONSTRUCT_print_log(CONSTRUCT_ERROR, "COULDNT DELETE FILE %s", path);} while(0)
#define CONSTRUCT_delete_directory_l(path) do {if(CONSTRUCT_delete_directory(path)) CONSTRUCT_print_log(CONSTRUCT_INFO, "DELETED DIRECTORY %s", path); else CONSTRUCT_print_log(CONSTRUCT_ERROR, "COULDNT DELETE DIRECTORY %s", path);} while(0)
#define CONSTRUCT_fetch_file_l(path, url) do {if(CONSTRUCT_fetch_file(path, url)) CONSTRUCT_print_log(CONSTRUCT_INFO, "FETCHED FILE %s TO %s", path, url); else CONSTRUCT_print_log(CONSTRUCT_ERROR, "COULDNT FETCH FILE %s TO %s", path, url);} while(0)
#define CONSTRUCT_read_entire_file_l(path, dab) do {if(CONSTRUCT_read_entire_file(path, dab)) CONSTRUCT_print_log(CONSTRUCT_INFO, "READ FILE %s", path); else CONSTRUCT_print_log(CONSTRUCT_ERROR, "COULDNT READ FILE %s", path);} while(0)
#define CONSTRUCT_write_entire_file_l(path, data, size) do {if(CONSTRUCT_write_entire_file(path, data, size)) CONSTRUCT_print_log(CONSTRUCT_INFO, "WROTE FILE %s", path); else CONSTRUCT_print_log(CONSTRUCT_ERROR, "COULDNT WRITE FILE %s", path);} while(0)

//================================================================
//SECTION: String View
//================================================================

typedef struct {const char* str; size_t len;} CONSTRUCT_StringView;

CONSTRUCT_DEF CONSTRUCT_StringView CONSTRUCT_sv_chop_by_delim(CONSTRUCT_StringView* sv, char delim) {
    bool nd = false;
    CONSTRUCT_StringView result = {0};
    for (size_t i = 0; i < sv->len; ++i) {
        if (nd == false && sv->str[i] != delim) {result.str = sv->str + i; nd = true;}
        else if (nd == true && sv->str[i] == delim && sv->str[i - 1] != '\\') {result.len = i - (result.str - sv->str); sv->str += i + 1; sv->len -= i + 1; return result;}
    }
    if (nd) {
        result.len = sv->len - (result.str - sv->str);
        sv->str += sv->len; sv->len = 0;
        return result;
    }
    return (CONSTRUCT_StringView){NULL, 0};
}
CONSTRUCT_DEF void CONSTRUCT_sv_trim_left(CONSTRUCT_StringView* sv, size_t n){if (n > sv->len) n = sv->len; sv->str += n; sv->len -= n;}
CONSTRUCT_DEF void CONSTRUCT_sv_trim_right(CONSTRUCT_StringView* sv, size_t n){if (n > sv->len) n = sv->len; sv->len -= n;}
CONSTRUCT_DEF void CONSTRUCT_sv_strip_left(CONSTRUCT_StringView* sv) {while (sv->len > 0 && isspace(sv->str[0])) {sv->str++; sv->len--;}}
CONSTRUCT_DEF void CONSTRUCT_sv_strip_right(CONSTRUCT_StringView* sv) {while (sv->len > 0 && isspace(sv->str[sv->len - 1])) --sv->len;}
CONSTRUCT_DEF void CONSTRUCT_sv_strip(CONSTRUCT_StringView* sv) {CONSTRUCT_sv_strip_left(sv); CONSTRUCT_sv_strip_right(sv);}

CONSTRUCT_DEF bool CONSTRUCT_sv_equal(CONSTRUCT_StringView* a, CONSTRUCT_StringView* b) {
    size_t len_a = a->len;
    size_t len_b = b->len;
    if (len_a != len_b) return false;
    return memcmp(a->str, b->str, len_a) == 0;
}
CONSTRUCT_DEF bool CONSTRUCT_sv_ends_with(CONSTRUCT_StringView* sv, char* cstr) {
    size_t cstr_len = strlen(cstr);
    if (cstr_len > sv->len) return false;
    return memcmp(sv->str + sv->len - cstr_len, cstr, cstr_len) == 0;
}
CONSTRUCT_DEF bool CONSTRUCT_sv_starts_with(CONSTRUCT_StringView* sv, char* cstr) {
    size_t cstr_len = strlen(cstr);
    if (cstr_len > sv->len) return false;
    return memcmp(sv->str, cstr, cstr_len) == 0;
}
CONSTRUCT_DEF void CONSTRUCT_sv_to_cstr(CONSTRUCT_StringView* sv, char* cstr){
    size_t sv_len = sv->len;
    memcpy(cstr, sv->str, sv_len);
    cstr[sv_len]='\0';
}
CONSTRUCT_DEF CONSTRUCT_StringView CONSTRUCT_sv_from_cstr(const char* cstr) {return (CONSTRUCT_StringView){cstr, strlen(cstr)};}
CONSTRUCT_DEF CONSTRUCT_StringView CONSTRUCT_sv_from_parts(const char* cstr, size_t len) {return (CONSTRUCT_StringView){cstr, len};}

#define CONSTRUCT_sv_len(sv) ((sv).len)
#define CONSTRUCT_SV_Fmt "%.*s"
#define CONSTRUCT_SV_Arg(sv) (int)CONSTRUCT_sv_len(sv), (sv).str

//================================================================
//SECTION: Misc
//================================================================

#define CONSTRUCT_STRINGIFY(x) #x
#define CONSTRUCT_TOSTRING(x) CONSTRUCT_STRINGIFY(x)

#define CONSTRUCT_UNUSED(...) (void)(__VA_ARGS__)
#define CONSTRUCT_TODO(message) do {printf("%s:%d: TODO: %s\n", __FILE__, __LINE__, message); abort();} while(0)

#define CONSTRUCT_PANIC(message) do {printf("%s:%d: PANIC: %s\n", __FILE__, __LINE__, message); abort();} while(0)
#define CONSTRUCT_UNREACHABLE() do {printf("%s:%d: UNREACHABLE\n", __FILE__, __LINE__); abort();} while(0)

#define CONSTRUCT_pop_first(xs, xs_sz) (assert((xs_sz) > 0), (xs_sz)--, *(xs)++)
#define CONSTRUCT_return_defer(value) do { result = (value); goto defer; } while(0)

#ifdef CONSTRUCT_CLOCK
    static clock_t CONSTRUCT_c1, CONSTRUCT_c2;
#endif
#ifdef CONSTRUCT_TIMER
    static time_t CONSTRUCT_t1, CONSTRUCT_t2;
#endif
#define CONSTRUCT_CLOCK_START CONSTRUCT_c1=clock()
#define CONSTRUCT_CLOCK_END CONSTRUCT_c2=clock()
#define CONSTRUCT_CLOCK_SEC ((float)(CONSTRUCT_c2 - CONSTRUCT_c1))/CLOCKS_PER_SEC
#define CONSTRUCT_TIMER_START CONSTRUCT_t1=time(NULL)
#define CONSTRUCT_TIMER_END CONSTRUCT_t2=time(NULL)
#define CONSTRUCT_TIMER_SEC (CONSTRUCT_t2 - CONSTRUCT_t1)

#define CONSTRUCT_AL(Type, ...) (Type[]){__VA_ARGS__}, (sizeof((Type[]){__VA_ARGS__})/sizeof(Type))
#define CONSTRUCT_SA(...) CONSTRUCT_AL(char*, __VA_ARGS__)

#define CONSTRUCT_expect_tt(exp) if(!(exp)) return 1
#define CONSTRUCT_expect_ft(exp) if((exp)) return 1
#define CONSTRUCT_expect_pt(exp) if((exp)<0) return 1
#define CONSTRUCT_expect_tf(exp) if(!(exp)) return 0
#define CONSTRUCT_expect_ff(exp) if((exp)) return 0
#define CONSTRUCT_expect_pf(exp) if((exp)<0) return 0

#define CONSTRUCT_d_expect_tt(exp) if(!(exp)) CONSTRUCT_return_defer(1)
#define CONSTRUCT_d_expect_ft(exp) if((exp)) CONSTRUCT_return_defer(1)
#define CONSTRUCT_d_expect_pt(exp) if((exp)<0) CONSTRUCT_return_defer(1)
#define CONSTRUCT_d_expect_tf(exp) if(!(exp)) CONSTRUCT_return_defer(0)
#define CONSTRUCT_d_expect_ff(exp) if((exp)) CONSTRUCT_return_defer(0)
#define CONSTRUCT_d_expect_pf(exp) if((exp)<0) CONSTRUCT_return_defer(0)

#define CONSTRUCT_u_expect_t(exp) if(!(exp)) CONSTRUCT_UNREACHABLE()
#define CONSTRUCT_u_expect_f(exp) if((exp)) CONSTRUCT_UNREACHABLE()
#define CONSTRUCT_u_expect_p(exp) if((exp)<0) CONSTRUCT_UNREACHABLE()

//================================================================
//SECTION: Commands
//================================================================

CONSTRUCT_da_define(char*, CONSTRUCT_Command);

#define CONSTRUCT_command_append(command, ...) CONSTRUCT_da_append_many(command, ((const char*[]){__VA_ARGS__}), (sizeof((const char*[]){__VA_ARGS__})/sizeof(const char*)))
#define CONSTRUCT_command_append_separator(command) CONSTRUCT_command_append(command, CONSTRUCT_CS)
#define CONSTRUCT_command_extend(command, other_command) CONSTRUCT_da_append_many(command, (other_command)->items, (other_command)->count)
#define CONSTRUCT_command_free(command) CONSTRUCT_da_free(command)

CONSTRUCT_DEF void CONSTRUCT_command_render(CONSTRUCT_Command* command, CONSTRUCT_StringBuilder* render){
    CONSTRUCT_sb_reset(render);
    for (size_t i = 0; i < command->count; ++i) {
        const char* arg = command->items[i];
        if (arg == NULL) break;
        if (i > 0) CONSTRUCT_sb_append_chr(render, ' ');
        CONSTRUCT_sb_append_str(render, arg);
    }
    CONSTRUCT_sb_append_null(render);
}
CONSTRUCT_DEF bool CONSTRUCT_command_run(CONSTRUCT_Command* command) {
    CONSTRUCT_StringBuilder command_sb = {0};
    CONSTRUCT_command_render(command, &command_sb);
    bool result = !system(command_sb.items);
    CONSTRUCT_sb_free(&command_sb);
    return result;
}
CONSTRUCT_DEF void CONSTRUCT_print_command(CONSTRUCT_Command* command) {
    CONSTRUCT_StringBuilder command_sb = {0};
    CONSTRUCT_command_render(command, &command_sb);
    printf("%s\n", command_sb.items);
    CONSTRUCT_sb_free(&command_sb);
}

//================================================================
//SECTION: CONSTRUCT build system
//================================================================

typedef struct {char** targets; size_t targets_count; char** dependencies; size_t dependencies_count; CONSTRUCT_Command command;} CONSTRUCT_ConstructRule;

CONSTRUCT_da_define(CONSTRUCT_ConstructRule, CONSTRUCT_ConstructRules);
CONSTRUCT_da_define(bool, CONSTRUCT_Bools);

CONSTRUCT_DEF bool CONSTRUCT_run_construct(CONSTRUCT_ConstructRules* construct_rules, bool verbose) {
    bool result = true;
    CONSTRUCT_Bools to_run  = {0};
    CONSTRUCT_Bools prev_run = {0};
    CONSTRUCT_da_resize(&to_run,   construct_rules->count);
    CONSTRUCT_da_resize(&prev_run, construct_rules->count);
    for (size_t i = 0; i < construct_rules->count; ++i) prev_run.items[i] = false;
    while (true) {
        size_t run_count = 0;
        for (size_t i = 0; i < construct_rules->count; ++i) {
            CONSTRUCT_ConstructRule* rule = &construct_rules->items[i];
            bool dep_ready = true;
            bool needs_run = false;
            for (size_t k = 0; k < rule->dependencies_count; ++k) if (!CONSTRUCT_file_exists(rule->dependencies[k])) {dep_ready = false; break;}
            if (dep_ready) {
                if (rule->targets_count == 0) needs_run = true;
                else {
                    for (size_t j = 0; j < rule->targets_count && !needs_run; ++j) {
                        if (!CONSTRUCT_file_exists(rule->targets[j])) needs_run = true;
                        else for (size_t k = 0; k < rule->dependencies_count && !needs_run; ++k) if (CONSTRUCT_is_newer(rule->dependencies[k], rule->targets[j])) needs_run = true;
                    }
                }
            }
            to_run.items[i] = needs_run;
            if (needs_run) run_count++;
        }
        if (run_count == 0) break;
        bool stalled = true;
        for (size_t i = 0; i < construct_rules->count; ++i) if (to_run.items[i] != prev_run.items[i]) { stalled = false; break; }
        if (stalled) {
            CONSTRUCT_print_log(CONSTRUCT_ERROR, "Build stalled: one or more commands are not producing their declared targets");
            CONSTRUCT_return_defer(false);
        }
        for (size_t i = 0; i < construct_rules->count; ++i) prev_run.items[i] = to_run.items[i];
        for (size_t i = 0; i < construct_rules->count; ++i) {
            if (!to_run.items[i]) continue;
            if (verbose) CONSTRUCT_print_command(&construct_rules->items[i].command);
            if (!CONSTRUCT_command_run(&construct_rules->items[i].command)) CONSTRUCT_return_defer(false);
            to_run.items[i] = false;
        }
    }
defer:
    CONSTRUCT_da_free(&to_run);
    CONSTRUCT_da_free(&prev_run);
    return result;
}

#ifndef CONSTRUCT_STRIP_PREFIX_GUARD_
#define CONSTRUCT_STRIP_PREFIX_GUARD_
    #ifndef CONSTRUCT_DONT_STRIP_PREFIX
        #define da_define CONSTRUCT_da_define
        #define da_reserve CONSTRUCT_da_reserve
        #define da_append CONSTRUCT_da_append
        #define da_append_many CONSTRUCT_da_append_many
        #define da_resize CONSTRUCT_da_resize
        #define da_remove_unordered CONSTRUCT_da_remove_unordered
        #define da_foreach CONSTRUCT_da_foreach
        #define da_reset CONSTRUCT_da_reset
        #define da_free CONSTRUCT_da_free
        #define StringBuilder CONSTRUCT_StringBuilder
        #define sb_append_chr CONSTRUCT_sb_append_chr
        #define sb_append_buf CONSTRUCT_sb_append_buf
        #define sb_append_str CONSTRUCT_sb_append_str
        #define sb_append_null CONSTRUCT_sb_append_null
        #define sb_str CONSTRUCT_sb_str
        #define sb_len CONSTRUCT_sb_len
        #define sb_get CONSTRUCT_sb_get
        #define sb_reset CONSTRUCT_sb_reset
        #define sb_free CONSTRUCT_sb_free
        #define sb_last CONSTRUCT_sb_last
        #define sb_foreach CONSTRUCT_sb_foreach
        #define SB_Fmt CONSTRUCT_SB_Fmt
        #define SB_Arg CONSTRUCT_SB_Arg
        #define Temp CONSTRUCT_Temp
        #define temp_sprintf CONSTRUCT_temp_sprintf
        #define temp_strdup CONSTRUCT_temp_strdup
        #define temp_strndup CONSTRUCT_temp_strndup
        #define temp_reset CONSTRUCT_temp_reset
        #define temp_free CONSTRUCT_temp_free
        #define utemp_sprintf CONSTRUCT_utemp_sprintf
        #define utemp_strdup CONSTRUCT_utemp_strdup
        #define utemp_strndup CONSTRUCT_utemp_strndup
        #define utemp_reset CONSTRUCT_utemp_reset
        #define utemp_free CONSTRUCT_utemp_free
        #define INFO CONSTRUCT_INFO
        #define WARNING CONSTRUCT_WARNING
        #define ERROR CONSTRUCT_ERROR
        #define LogType CONSTRUCT_LogType
        #define print_log CONSTRUCT_print_log
        #define fprint_log CONSTRUCT_fprint_log
        #define NL CONSTRUCT_NL 
        #define PS CONSTRUCT_PS 
        #define file_exists CONSTRUCT_file_exists
        #define get_mtime CONSTRUCT_get_mtime
        #define is_newer CONSTRUCT_is_newer
        #define path_basename CONSTRUCT_path_basename
        #define mkdir_if_not_exists CONSTRUCT_mkdir_if_not_exists
        #define copy_file CONSTRUCT_copy_file
        #define copy_directory_recursively CONSTRUCT_copy_directory_recursively
        #define move_file CONSTRUCT_move_file
        #define delete_file CONSTRUCT_delete_file
        #define delete_directory CONSTRUCT_delete_directory
        #define fetch_file CONSTRUCT_fetch_file
        #define FileBytes CONSTRUCT_FileBytes
        #define read_entire_file CONSTRUCT_read_entire_file
        #define write_entire_file CONSTRUCT_write_entire_file
        #define mkdir_if_not_exists_l CONSTRUCT_mkdir_if_not_exists_l
        #define copy_file_l CONSTRUCT_copy_file_l
        #define copy_directory_recursively_l CONSTRUCT_copy_directory_recursively_l
        #define move_file_l CONSTRUCT_move_file_l
        #define delete_file_l CONSTRUCT_delete_file_l
        #define delete_directory_l CONSTRUCT_delete_directory_l
        #define fetch_file_l CONSTRUCT_fetch_file_l
        #define read_entire_file_l CONSTRUCT_read_entire_file_l
        #define write_entire_file_l CONSTRUCT_write_entire_file_l
        #define StringView CONSTRUCT_StringView
        #define sv_chop_by_delim CONSTRUCT_sv_chop_by_delim
        #define sv_trim_left CONSTRUCT_sv_trim_left
        #define sv_trim_right CONSTRUCT_sv_trim_right
        #define sv_strip_left CONSTRUCT_sv_strip_left
        #define sv_strip_right CONSTRUCT_sv_strip_right
        #define sv_strip CONSTRUCT_sv_strip
        #define sv_equal CONSTRUCT_sv_equal
        #define sv_ends_with CONSTRUCT_sv_ends_with
        #define sv_starts_with CONSTRUCT_sv_starts_with
        #define sv_to_cstr CONSTRUCT_sv_to_cstr
        #define sv_from_cstr CONSTRUCT_sv_from_cstr
        #define sv_from_parts CONSTRUCT_sv_from_parts
        #define sv_len CONSTRUCT_sv_len
        #define SV_Fmt CONSTRUCT_SV_Fmt
        #define SV_Arg CONSTRUCT_SV_Arg
        #define ASSERT CONSTRUCT_ASSERT
        #define REALLOC CONSTRUCT_REALLOC
        #define FREE CONSTRUCT_FREE
        #define STRINGIFY CONSTRUCT_STRINGIFY
        #define TOSTRING CONSTRUCT_TOSTRING
        #define UNUSED CONSTRUCT_UNUSED
        #define TODO CONSTRUCT_TODO
        #define PANIC CONSTRUCT_PANIC
        #define UNREACHABLE CONSTRUCT_UNREACHABLE
        #define pop_first CONSTRUCT_pop_first
        #define return_defer CONSTRUCT_return_defer
        #define CLOCK_START CONSTRUCT_CLOCK_START
        #define CLOCK_END CONSTRUCT_CLOCK_END
        #define CLOCK_SEC CONSTRUCT_CLOCK_SEC
        #define TIMER_START CONSTRUCT_TIMER_START
        #define TIMER_END CONSTRUCT_TIMER_END
        #define TIMER_SEC CONSTRUCT_TIMER_SEC
        #define AL CONSTRUCT_AL
        #define SA CONSTRUCT_SA
        #define expect_tt CONSTRUCT_expect_tt
        #define expect_ft CONSTRUCT_expect_ft
        #define expect_pt CONSTRUCT_expect_pt
        #define expect_tf CONSTRUCT_expect_tf
        #define expect_ff CONSTRUCT_expect_ff
        #define expect_pf CONSTRUCT_expect_pf
        #define d_expect_tt CONSTRUCT_d_expect_tt
        #define d_expect_ft CONSTRUCT_d_expect_ft
        #define d_expect_pt CONSTRUCT_d_expect_pt
        #define d_expect_tf CONSTRUCT_d_expect_tf
        #define d_expect_ff CONSTRUCT_d_expect_ff
        #define d_expect_pf CONSTRUCT_d_expect_pf
        #define u_expect_t CONSTRUCT_u_expect_t
        #define u_expect_f CONSTRUCT_u_expect_f
        #define u_expect_p CONSTRUCT_u_expect_p
        #define Command CONSTRUCT_Command
        #define CommandOptions CONSTRUCT_CommandOptions
        #define command_append CONSTRUCT_command_append
        #define command_extend CONSTRUCT_command_extend
        #define command_free CONSTRUCT_command_free
        #define command_render CONSTRUCT_command_render
        #define command_run CONSTRUCT_command_run
        #define ConstructRule CONSTRUCT_ConstructRule
        #define ConstructRules CONSTRUCT_ConstructRules
        #define Bools CONSTRUCT_Bools
        #define run_construct CONSTRUCT_run_construct
    #endif
#endif // CONSTRUCT_STRIP_PREFIX_GUARD_

#endif // _CONSTRUCT_H