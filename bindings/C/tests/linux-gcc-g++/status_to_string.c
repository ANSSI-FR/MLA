#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#ifdef __cplusplus
#include "mla.hpp"
#define MLA_STATUS_C(x) MLAStatus::x
#define AS_U64(x) static_cast<uint64_t>(x)
#else
#include "mla.h"
#define MLA_STATUS_C(x) x
#define AS_U64(x) (uint64_t)(x)
#endif

// ABI-level spot checks: the symbol is exported from the real staticlib, the
// cbindgen enumerator values agree with the Rust discriminants, and returned
// strings are readable from C. Exhaustive name coverage is enforced on the
// Rust side (status_name + round-trip tests); do not grow a full table here.
typedef struct { MLAStatus code; const char *name; } StatusName;

int main(void)
{
    const StatusName probes[] = {
        { MLA_STATUS_C(MLA_STATUS_SUCCESS), "Success" },
        { MLA_STATUS_C(MLA_STATUS_WRONG_MAGIC), "WrongMagic" },
        { MLA_STATUS_C(MLA_STATUS_CONFIG_ERROR_PRIVATE_KEY_NOT_SET), "ConfigErrorPrivateKeyNotSet" },
        { MLA_STATUS_C(MLA_STATUS_MLA_KEY_PARSER_ERROR), "MlaKeyParserError" },
    };
    size_t i;
    for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++)
    {
        const char *name = mla_status_to_string(AS_U64(probes[i].code));
        if (name == NULL || strcmp(name, probes[i].name) != 0)
        {
            fprintf(stderr, "FAIL: status 0x%08" PRIx64 " -> \"%s\" (expected \"%s\")\n",
                    (uint64_t)probes[i].code, name ? name : "(null)", probes[i].name);
            return 1;
        }
    }
    // Unknown codes (including retired compatibility slots) must not crash
    // and must map to "Unknown"
    const uint64_t unknown[] = { 0x000C0000, 0x00F10000, 0xDEAD0000 };
    for (i = 0; i < sizeof(unknown) / sizeof(unknown[0]); i++)
    {
        if (strcmp(mla_status_to_string(unknown[i]), "Unknown") != 0)
        {
            fprintf(stderr, "FAIL: unknown status 0x%08" PRIx64 " did not map to \"Unknown\"\n",
                    unknown[i]);
            return 1;
        }
    }
    printf("All status names OK\n");
    return 0;
}
