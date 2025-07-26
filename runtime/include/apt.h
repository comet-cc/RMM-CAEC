
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

struct master_mem {
        unsigned long slave_rd_pa;
        unsigned long ipa_start;
	unsigned long map_size;
};
struct slave_mem {
        unsigned long master_rd_pa;
        unsigned long ipa_start;
	unsigned long map_size;
};

struct apt {
	unsigned long csdata_ipa_begin;
	unsigned long csdata_ipa_end;
	unsigned long test;
	struct master_mem master_memory;
	struct slave_mem slave_memory;
};

COMPILER_ASSERT(sizeof(struct apt) <= GRANULE_SIZE);


