/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <arch.h>
#include <arch_features.h>
#include <attestation.h>
#include <buffer.h>
#include <debug.h>
#include <gic.h>
#include <granule.h>
#include <measurement.h>
#include <memory_alloc.h>
#include <psci.h>
#include <realm.h>
#include <rec.h>
#include <smc-handler.h>
#include <smc-rmi.h>
#include <smc.h>
#include <spinlock.h>
#include <stddef.h>
#include <string.h>
#include <apt.h>
#include <apt_helpers.h>
#include <realm_tag.h>
#include <csm_id.h>


#define ADD_OK_UL(a, b, out_end) \
    (((b) <= (ULONG_MAX - (a))) ? (*(out_end) = (a) + (b), true) : false)

/* [lo, hi) half-open interval containment */
#define WITHIN(lo, hi, s, e) ((s) >= (lo) && (e) <= (hi))

/* Disjoint half-open intervals: [s1,e1) and [s2,e2) */
#define DISJOINT(s1, e1, s2, e2) ((e1) <= (s2) || (e2) <= (s1))


unsigned long smc_apt_create(unsigned long rd_addr,
			     unsigned long apt_addr)
{
	struct granule *g_rd;
    struct granule *g_apt;
    struct apt *apt;
    struct rd *rd;
    unsigned long ret;

    if (!find_lock_two_granules(apt_addr,
                                GRANULE_STATE_DELEGATED, &g_apt,
                                rd_addr,
                                GRANULE_STATE_RD, &g_rd)) {
                return RMI_ERROR_REALM;
                goto out_free_aux;
	}

    rd = buffer_granule_map(g_rd, SLOT_RD);
    assert(rd != NULL);

 	apt = buffer_granule_map(g_apt, SLOT_APT);
    assert(apt != NULL);

    apt_reset(apt);


	// This function cannot be called at runtime
	if (get_rd_state_locked(rd) != REALM_NEW) {
                ret = RMI_ERROR_REALM;
                goto out_unmap;
        }
	// later we initialize this value in the initial content of RD created by the hypervisor
	rd->apt_pa = apt_addr;
	// Create Unique Tag fo the realm. FOr now the available IDs are hardcoded
	uint8_t ID;
	(void)realm_tag_assign(rd_addr, &ID);
	INFO("realm tag assigned %x \n", ID);

	ret = RMI_SUCCESS;

out_unmap:
        buffer_unmap(rd);
        buffer_unmap(apt);

        granule_unlock(g_rd);
        granule_unlock_transition(g_apt, GRANULE_STATE_APT);
	    return ret;

out_free_aux:
        return ret;
}

/*
 * CSM cleanup structures for smc_apt_destroy() two-phase cleanup.
 *
 * Phase 1 (locks held): reads CSM state from our APT, cleans our own S2TT
 * entries and APT entries, saves peer info for Phase 2.
 *
 * Phase 2 (no locks held): notifies peer realms (master or slaves) to remove
 * their stale back-references.  No locks are held on entry, eliminating the
 * circular-wait deadlock that would arise if we tried to acquire a peer's RD
 * lock while already holding our own.
 */
struct saved_slave_entry {
	unsigned long master_rd_pa;
	uint8_t       region_id;
};

struct saved_master_share {
	unsigned long slave_rd_pa;
	uint8_t       region_id;
};

unsigned long smc_apt_destroy(unsigned long rd_addr, unsigned long apt_addr)
{
	struct granule *g_apt;
	struct granule *g_rd;
	struct rd *rd;
	struct apt *apt;
	int ret;

	/* Saved CSM state for Phase 2 peer cleanup. */
	struct saved_slave_entry  slave_entries[MAX_MEM_REGIONS];
	struct saved_master_share master_shares[MAX_MEM_REGIONS * CSM_MAX_MASTER_SHARES];
	int n_slave_entries  = 0;
	int n_master_shares  = 0;

	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	if (g_rd == NULL)
		return RMI_ERROR_INPUT;

	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (rd->apt_pa != apt_addr) {
		ret = RMI_ERROR_REALM;
		goto out_unmap_rd;
	}

	/*
	 * Remove the realm's unique tag before cleanup.  This prevents any
	 * new CSM RSI calls from finding this realm by tag while we work.
	 */
	(void)realm_tag_remove(rd_addr);

	g_apt = find_lock_granule(apt_addr, GRANULE_STATE_APT);
	assert(g_apt != NULL);

	apt = buffer_granule_map(g_apt, SLOT_APT);
	assert(apt != NULL);

	/* ----------------------------------------------------------------
	 * PHASE 1 — clean up our own APT and S2TT while holding our locks.
	 *
	 * Lock order held here: our_g_rd → our_g_apt (→ slave_RTT via
	 * unmap_ipa_from_rd).  This is consistent with the propagation
	 * helpers in rtt.c which also hold an APT lock while calling
	 * unmap_ipa_from_rd / map_ipa_to_pa.
	 * ---------------------------------------------------------------- */

	/*
	 * SLAVE regions: this realm has borrowed memory from master realms.
	 *
	 * The critical fix: convert every CSM-mapped S2TT entry from
	 * assigned_ram to unassigned_destroyed BEFORE any subsequent
	 * smc_data_destroy call runs on these IPAs.  Without this step a
	 * slave realm's RIPAS_STATE_SET(EMPTY) would extract the physical
	 * address from the S2TT entry and destroy the master's granule
	 * (there is no ownership check in smc_data_destroy).
	 */
	for (size_t sj = 0; sj < MAX_MEM_REGIONS; sj++) {
		if (!(apt->slave_used_mask & BIT64(sj)))
			continue;

		uint8_t       region_id      = apt->slave_memory[sj].region_ID;
		unsigned long master_rd_pa   = apt->slave_memory[sj].master_rd_pa;
		unsigned long slave_ipa_base = apt->slave_memory[sj].ipa_start;
		unsigned long slave_map_size = apt->slave_memory[sj].map_size;

		/* Disable and clear our slave entry first. */
		apt_disable_slave_idx(apt, sj);
		apt->slave_used_mask &= ~BIT64(sj);
		(void)memset(&apt->slave_memory[sj], 0, sizeof(struct slave_mem));

		/*
		 * Unmap all pages in our slave IPA range.  After this, the
		 * S2TT entries are unassigned_destroyed (no physical address),
		 * so smc_data_destroy on those IPAs returns RMI_ERROR_RTT and
		 * skips them — the master's granules are left untouched.
		 */
		for (unsigned long ipa = slave_ipa_base;
		     ipa < slave_ipa_base + slave_map_size;
		     ipa += GRANULE_SIZE) {
			unmap_ipa_from_rd(rd, ipa);
		}

		/* Save peer info for Phase 2 master APT cleanup. */
		if (n_slave_entries < MAX_MEM_REGIONS) {
			slave_entries[n_slave_entries].master_rd_pa = master_rd_pa;
			slave_entries[n_slave_entries].region_id    = region_id;
			n_slave_entries++;
		}
	}

	/*
	 * MASTER regions: this realm owns CSM regions shared with slaves.
	 *
	 * Clear all share slots and the master entries from our APT, free
	 * the global region IDs, and save slave info for Phase 2 S2TT cleanup.
	 */
	for (size_t mi = 0; mi < MAX_MEM_REGIONS; mi++) {
		if (!(apt->master_used_mask & BIT64(mi)))
			continue;

		uint8_t region_id = apt->master_memory[mi].region_ID;

		for (size_t sk = 0; sk < CSM_MAX_MASTER_SHARES; sk++) {
			if (!apt->master_memory[mi].shares[sk].in_use)
				continue;

			unsigned long slave_rd_pa =
				apt->master_memory[mi].shares[sk].slave_rd_pa;

			apt->master_memory[mi].shares[sk].in_use = false;
			apt->master_memory[mi].share_count--;

			/* Save slave info for Phase 2. */
			if (n_master_shares < (int)(MAX_MEM_REGIONS * CSM_MAX_MASTER_SHARES)) {
				master_shares[n_master_shares].slave_rd_pa = slave_rd_pa;
				master_shares[n_master_shares].region_id   = region_id;
				n_master_shares++;
			}
		}

		/* Free the globally-assigned region ID. */
		(void)csm_region_id_remove(region_id);

		apt_disable_master_idx(apt, mi);
		apt->master_used_mask &= ~BIT64(mi);
		(void)memset(&apt->master_memory[mi], 0, sizeof(struct master_mem));
	}

	/* All CSM state in our APT is clean; wipe and transition the granule. */
	buffer_unmap(apt);
	buffer_granule_memzero(g_apt, SLOT_APT);
	granule_unlock_transition(g_apt, GRANULE_STATE_DELEGATED);

	buffer_unmap(rd);
	granule_unlock(g_rd);

	/* ----------------------------------------------------------------
	 * PHASE 2 — notify peers with no locks held.
	 *
	 * No lock is held on entry to each peer operation, so there is no
	 * circular-wait deadlock risk.  Each peer lookup uses find_lock_granule
	 * which will block if the peer is momentarily locked; this is safe
	 * because we hold nothing they could be waiting for.
	 *
	 * All operations here are best-effort: if a peer realm has already
	 * been cleaned up (e.g., via explicit RSI_CSM_REVOKE/DETACH), the
	 * entry will simply not be found and we skip gracefully.
	 * ---------------------------------------------------------------- */

	/*
	 * For each slave region we owned: remove our share slot from the
	 * master's APT so its share_count stays accurate and RSI_CSM_DESTROY
	 * can succeed.
	 */
	for (int i = 0; i < n_slave_entries; i++) {
		unsigned long master_rd_pa = slave_entries[i].master_rd_pa;
		uint8_t       region_id    = slave_entries[i].region_id;

		struct granule *g_mrd =
			find_lock_granule(master_rd_pa, GRANULE_STATE_RD);
		if (g_mrd == NULL)
			continue; /* master already destroyed */

		struct rd *mrd = buffer_granule_map(g_mrd, SLOT_RD2);
		assert(mrd != NULL);

		struct granule *g_mapt =
			find_lock_granule(mrd->apt_pa, GRANULE_STATE_APT);
		if (g_mapt == NULL) {
			buffer_unmap(mrd);
			granule_unlock(g_mrd);
			continue;
		}

		struct apt *mapt = buffer_granule_map(g_mapt, SLOT_APT2);
		assert(mapt != NULL);

		int midx = apt_find_master_by_region_id(mapt, region_id);
		if (midx >= 0) {
			/* Find our share slot by matching rd_addr. */
			for (size_t sk = 0; sk < CSM_MAX_MASTER_SHARES; sk++) {
				if (mapt->master_memory[midx].shares[sk].in_use &&
				    mapt->master_memory[midx].shares[sk].slave_rd_pa == rd_addr) {
					mapt->master_memory[midx].shares[sk].in_use = false;
					mapt->master_memory[midx].share_count--;
					break;
				}
			}
		}

		buffer_unmap(mapt);
		granule_unlock(g_mapt);
		buffer_unmap(mrd);
		granule_unlock(g_mrd);
	}

	/*
	 * For each slave that was sharing our master regions: remove their
	 * slave APT entry and unmap their S2TT entries for this region.
	 * Without this, slave APTs retain stale master_rd_pa references,
	 * and their S2TT still has assigned_ram entries pointing at pages
	 * that are about to be returned to the host.
	 */
	for (int i = 0; i < n_master_shares; i++) {
		unsigned long slave_rd_pa = master_shares[i].slave_rd_pa;
		uint8_t       region_id   = master_shares[i].region_id;

		struct granule *g_srd =
			find_lock_granule(slave_rd_pa, GRANULE_STATE_RD);
		if (g_srd == NULL)
			continue; /* slave already destroyed */

		struct rd *srd = buffer_granule_map(g_srd, SLOT_RD2);
		assert(srd != NULL);

		struct granule *g_sapt =
			find_lock_granule(srd->apt_pa, GRANULE_STATE_APT);
		if (g_sapt == NULL) {
			buffer_unmap(srd);
			granule_unlock(g_srd);
			continue;
		}

		struct apt *sapt = buffer_granule_map(g_sapt, SLOT_APT2);
		assert(sapt != NULL);

		unsigned long slave_ipa_base = 0UL;
		unsigned long slave_map_size = 0UL;
		size_t        found_idx      = SIZE_MAX;

		for (size_t sj = 0; sj < MAX_MEM_REGIONS; sj++) {
			if ((sapt->slave_used_mask & BIT64(sj)) &&
			    sapt->slave_memory[sj].region_ID == region_id) {
				slave_ipa_base = sapt->slave_memory[sj].ipa_start;
				slave_map_size = sapt->slave_memory[sj].map_size;
				found_idx      = sj;
				break;
			}
		}

		if (found_idx != SIZE_MAX) {
			apt_disable_slave_idx(sapt, found_idx);
			sapt->slave_used_mask &= ~BIT64(found_idx);
			(void)memset(&sapt->slave_memory[found_idx], 0,
				     sizeof(struct slave_mem));
		}

		buffer_unmap(sapt);
		granule_unlock(g_sapt);

		/*
		 * Unmap slave's S2TT entries for this region after releasing
		 * the slave's APT lock (consistent with the existing pattern in
		 * handle_rsi_csm_revoke and handle_rsi_csm_detach_and_free).
		 */
		if (found_idx != SIZE_MAX) {
			for (unsigned long ipa = slave_ipa_base;
			     ipa < slave_ipa_base + slave_map_size;
			     ipa += GRANULE_SIZE) {
				unmap_ipa_from_rd(srd, ipa);
			}
		}

		buffer_unmap(srd);
		granule_unlock(g_srd);
	}

	return RMI_SUCCESS;

out_unmap_rd:
	buffer_unmap(rd);
	granule_unlock(g_rd);
	return ret;
}
