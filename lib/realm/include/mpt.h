
#include <arch.h>
#include <attestation_token.h>
#include <gic.h>
#include <memory_alloc.h>
#include <pauth.h>
#include <pmu.h>
#include <ripas.h>
#include <simd.h>
#include <sizes.h>
#include <smc-rmi.h>
#include <utils_def.h>

struct granule;

struct host_mem {
        unsigned long guest_rd_pa;
        unsigned long ipa_start;
	unsigned long map_size;
};
struct guest_mem {
        unsigned long host_rd_pa;
        unsigned long ipa_start;
	unsigned long map_size;
};

struct mpt {
	unsigned long test;
	struct host_mem host_memory;
	struct guest_mem guest_memory;
};

COMPILER_ASSERT(sizeof(struct mpt) <= GRANULE_SIZE);


