/*
 * Minimal binding-free Unicorn 2.1.4 macOS ARM64 SIGILL reproducer.
 *
 * Build against a Unicorn installation, then run each operation separately:
 *   clang -I$UC/include unicorn_x87_sigill.c $UC/lib/libunicorn.2.dylib \
 *     -Wl,-rpath,$UC/lib -o unicorn_x87_sigill
 *   ./unicorn_x87_sigill mem-map
 *   ./unicorn_x87_sigill x87-register
 *   ./unicorn_x87_sigill x87-execute
 *
 * Under a policy that denies sysctlbyname("hw.cachelinesize"), all three reach
 * Unicorn qemu/util/cacheinfo.c:init_cache_info and SIGILL on `mrs CTR_EL0`.
 * uc_open alone succeeds. No Python/Rust binding or REKit state is involved.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>

static int checked(uc_err error, const char *operation) {
    if (error != UC_ERR_OK) {
        fprintf(stderr, "%s: %s\n", operation, uc_strerror(error));
        return 0;
    }
    printf("completed=%s\n", operation);
    fflush(stdout);
    return 1;
}

int main(int argc, char **argv) {
    uc_engine *uc = NULL;
    uint64_t value = 0x037f;
    const uint8_t fld1[] = {0xd9, 0xe8};
    const char *operation = argc > 1 ? argv[1] : "open";
    if (!checked(uc_open(UC_ARCH_X86, UC_MODE_32, &uc), "uc_open")) return 2;
    if (!strcmp(operation, "mem-map")) {
        if (!checked(uc_mem_map(uc, 0x1000000, 0x1000, UC_PROT_ALL), "uc_mem_map")) return 2;
    } else if (!strcmp(operation, "x87-register")) {
        if (!checked(uc_reg_write(uc, UC_X86_REG_FPCW, &value), "uc_reg_write(FPCW)")) return 2;
    } else if (!strcmp(operation, "x87-execute")) {
        if (!checked(uc_mem_map(uc, 0x1000000, 0x1000, UC_PROT_ALL), "uc_mem_map")) return 2;
        if (!checked(uc_mem_write(uc, 0x1000000, fld1, sizeof(fld1)), "uc_mem_write")) return 2;
        if (!checked(uc_emu_start(uc, 0x1000000, 0x1000002, 0, 1), "uc_emu_start(FLD1)")) return 2;
    }
    return checked(uc_close(uc), "uc_close") ? 0 : 2;
}
