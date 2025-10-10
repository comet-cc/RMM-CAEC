
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
//#define MAX_MEM_REGIONS 40

struct master_mem {
    uint8_t slave_ID;
	unsigned long slave_rd_pa;
    unsigned long ipa_start;
	unsigned long map_size;
	//uint8_t flags;
	bool enable;
};

struct slave_mem {
    uint8_t master_ID;
	unsigned long master_rd_pa;
    unsigned long ipa_start;
	unsigned long map_size;
	//uint8_t flags;
	bool enable;
};

//csdata_ipa variables define the boundries in which the data is shared (combination of slave and master)

struct apt {
	unsigned long csdata_ipa_begin;
	unsigned long csdata_ipa_end;
	struct master_mem master_memory;
	struct slave_mem slave_memory;
};

COMPILER_ASSERT(sizeof(struct apt) <= GRANULE_SIZE);


