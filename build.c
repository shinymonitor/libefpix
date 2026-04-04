#include "build.h"
#define CC "gcc"
#define CFLAGS "-Wall -Wextra -Werror -pedantic -O3"
#define LINKS "-lsodium"

int main(){
    ConstructRules rules = {0};

    ConstructRule rule = {SA("build/example"), SA("src/example.c", "src/libefpix.h"), 0};
    command_append(&rule.command, CC, "src/example.c", "-o", "build/example", LINKS, CFLAGS);
    da_append(&rules, rule);

    if (!run_construct(&rules, true)) {print_log(ERROR, "Build failed"); return 1;}
    print_log(INFO, "Build finished");
    return 0;
}
