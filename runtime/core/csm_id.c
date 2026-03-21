#include <stdbool.h>
#include <stdint.h>

#include <csm_id.h>
#include <spinlock.h>

#define CONFIG_MAX_CSM_REGION_IDS 64

struct csm_region_id_entry {
	uint64_t owner_rd_pa;
	uint8_t region_id;
	bool in_use;
};

static struct csm_region_id_entry g_csm_region_ids[CONFIG_MAX_CSM_REGION_IDS];
static spinlock_t g_csm_region_id_lock;
static uint8_t g_csm_region_id_counter = 1U;

static int csm_region_id_find_free_slot(void)
{
	for (int i = 0; i < CONFIG_MAX_CSM_REGION_IDS; ++i) {
		if (!g_csm_region_ids[i].in_use) {
			return i;
		}
	}

	return -1;
}

static bool csm_region_id_collides(uint8_t region_id)
{
	for (int i = 0; i < CONFIG_MAX_CSM_REGION_IDS; ++i) {
		if (g_csm_region_ids[i].in_use &&
		    g_csm_region_ids[i].region_id == region_id) {
			return true;
		}
	}

	return false;
}

bool csm_region_id_assign(uint64_t owner_rd_pa, uint8_t *out_region_id)
{
	bool ok = false;
	uint8_t candidate;
	int slot;
	int tries = 0;

	spinlock_acquire(&g_csm_region_id_lock);

	slot = csm_region_id_find_free_slot();
	if (slot < 0) {
		goto out_unlock;
	}

	do {
		candidate = g_csm_region_id_counter++;
		if (candidate == 0U) {
			candidate = g_csm_region_id_counter++;
		}
		tries++;
		if (tries > CONFIG_MAX_CSM_REGION_IDS) {
			goto out_unlock;
		}
	} while (csm_region_id_collides(candidate));

	g_csm_region_ids[slot].owner_rd_pa = owner_rd_pa;
	g_csm_region_ids[slot].region_id = candidate;
	g_csm_region_ids[slot].in_use = true;

	if (out_region_id != NULL) {
		*out_region_id = candidate;
	}
	ok = true;

out_unlock:
	spinlock_release(&g_csm_region_id_lock);
	return ok;
}

bool csm_region_id_remove(uint8_t region_id)
{
	bool ok = false;

	spinlock_acquire(&g_csm_region_id_lock);

	for (int i = 0; i < CONFIG_MAX_CSM_REGION_IDS; ++i) {
		if (g_csm_region_ids[i].in_use &&
		    g_csm_region_ids[i].region_id == region_id) {
			g_csm_region_ids[i].owner_rd_pa = 0UL;
			g_csm_region_ids[i].region_id = 0U;
			g_csm_region_ids[i].in_use = false;
			ok = true;
			break;
		}
	}

	spinlock_release(&g_csm_region_id_lock);
	return ok;
}
