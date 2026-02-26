#include "build.h"
#define CC "gcc"
#define CFLAGS "-Wall -Wextra -Werror -pedantic -O3"

int main(){
    if (!file_exists("lib/monocypher.h")) fetch_file_l("lib/monocypher.h", "https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/monocypher.h");
    if (!file_exists("lib/monocypher.c")) fetch_file_l("lib/monocypher.c", "https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/monocypher.c");
    if (!file_exists("lib/monocypher-ed25519.h")) fetch_file_l("lib/monocypher-ed25519.h", "https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/optional/monocypher-ed25519.h");
    if (!file_exists("lib/monocypher-ed25519.c")) fetch_file_l("lib/monocypher-ed25519.c", "https://raw.githubusercontent.com/LoupVaillant/Monocypher/refs/heads/master/src/optional/monocypher-ed25519.c");
    
    ConstructRules rules = {0};

    ConstructRule rule = {SA("build/example"), SA("src/example.c", "src/libefpix.h", "src/libefpix_config.h"), 0};
    command_append(&rule.command, CC, "src/example.c lib/monocypher.c lib/monocypher-ed25519.c", "-o", "build/example", CFLAGS);
    da_append(&rules, rule);

    if (!run_construct(&rules, true)) {print_log(ERROR, "Build failed"); return 1;}
    print_log(INFO, "Build finished");
    return 0;
}
