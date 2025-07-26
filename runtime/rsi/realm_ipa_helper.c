/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <buffer.h>
#include <granule.h>
#include <realm.h>
#include <debug.h>

/**
 * Translate a realm granule IPA to PA.
 *
 * Parameters:
 * [in]   rec		    Pointer to REC granule.
 * [in]   ipa		    The intermediate physical address of the realm
 *			    granule.
 * [in]   s2_walk	    Address of s2_walk_result structure to return:
 * [out]  s2_walk.pa	    The physical address of the realm granule.
 * [out]  s2_walk.rtt_level The last level reached by the table walk.
 * [out]  s2_walk.ripas_val RIPAS of s2tte.
 * [out]  s2_walk.llt	    Pointer to the last level page table which contains
 *			    the mapping of the granule. If function returns with
 *			    WALK_SUCCESS then 's2_walk.llt' must be unlocked by
 *			    the caller. Lock avoids to destoy the realm granule
 *			    while RMM accessing to it.
 * Returns:
 * WALK_SUCCESS		Translation succeeded. The IPA is a valid mapping
 *			(hipas is RMI_ASSIGNED and ripas is RIPAS_RAM).
 *			All members of 's2_walk' are updated.
 *			The rtt granule that is pointed to by 's2_walk->pa'
 *			is locked.
 * WALK_INVALID_PARAMS	Parameter 'ipa' is unaligned to granule size or is not
 *			a Protected IPA, 's2_walk' structure is not updated.
 * WALK_FAIL		Mapping is not in the page table (either hipas is not
 *			RMI_ASSIGNED or ripas is not RIPAS_RAM).
 *			Only 's2_walk.rtt_level' and 's2_walk.ripas' are
 *			updated. NS Host needs to fix.
 */
enum s2_walk_status realm_ipa_to_pa(struct rec *rec,
				    unsigned long ipa,
				    struct s2_walk_result *s2_walk)
{
	struct granule *g_table_root;
	struct rtt_walk wi;
	unsigned long s2tte, *ll_table, offset;
	enum s2_walk_status walk_status;

	if (!GRANULE_ALIGNED(ipa) || !addr_in_rec_par(rec, ipa)) {
		return WALK_INVALID_PARAMS;
	}

	g_table_root = rec->realm_info.g_rtt;
	granule_lock(g_table_root, GRANULE_STATE_RTT);
	rtt_walk_lock_unlock(g_table_root,
			     rec->realm_info.s2_starting_level,
			     rec->realm_info.ipa_bits,
			     ipa,
			     RTT_PAGE_LEVEL,
			     &wi);

	ll_table = granule_map(wi.g_llt, SLOT_RTT);
	assert(ll_table != NULL);

	s2tte = s2tte_read(&ll_table[wi.index]);

	if (s2tte_is_assigned_ram(s2tte, wi.last_level)) {
		s2_walk->llt = wi.g_llt; /* Must be unlocked by caller */
		s2_walk->pa = s2tte_pa(s2tte, wi.last_level);
		offset = ipa & (s2tte_map_size(wi.last_level) - 1UL);
		s2_walk->pa += offset;
		s2_walk->ripas_val = RIPAS_RAM;
		walk_status = WALK_SUCCESS;
	} else {
		if (s2tte_is_unassigned_destroyed(s2tte) ||
		    s2tte_is_assigned_destroyed(s2tte, wi.last_level)) {
			s2_walk->ripas_val = RIPAS_DESTROYED;
		} else if (s2tte_is_unassigned_ram(s2tte)) {
			s2_walk->ripas_val = RIPAS_RAM;
		} else {
			/*
			 * Only unassigned_empty & assigned_empty
			 * are left as an option.
			 */
			s2_walk->ripas_val = RIPAS_EMPTY;
		}

		granule_unlock(wi.g_llt);
		walk_status = WALK_FAIL;
	}

	s2_walk->rtt_level = (unsigned long)wi.last_level;

	buffer_unmap(ll_table);
	return walk_status;
}

/**
 * Translate a realm granule IPA to PA.
 *
 * Parameters:
 * [in]   rd               Pointer to rd granule.
 * [in]   ipa               The intermediate physical address of the realm
 *                          granule.
 * [in]   s2_walk           Address of s2_walk_result structure to return:
 * [out]  s2_walk.pa        The physical address of the realm granule.
 * [out]  s2_walk.rtt_level The last level reached by the table walk.
 * [out]  s2_walk.ripas_val RIPAS of s2tte.
 * [out]  s2_walk.llt       Pointer to the last level page table which contains
 *                          the mapping of the granule. If function returns with
 *                          WALK_SUCCESS then 's2_walk.llt' must be unlocked by
 *                          the caller. Lock avoids to destoy the realm granule
 *                          while RMM accessing to it.
 * Returns:
 * WALK_SUCCESS         Translation succeeded. The IPA is a valid mapping
 *                      (hipas is RMI_ASSIGNED and ripas is RIPAS_RAM).
 *                      All members of 's2_walk' are updated.
 *                      The rtt granule that is pointed to by 's2_walk->pa'
 *                      is locked.
 * WALK_INVALID_PARAMS  Parameter 'ipa' is unaligned to granule size or is not
 *                      a Protected IPA, 's2_walk' structure is not updated.
 * WALK_FAIL            Mapping is not in the page table (either hipas is not
 *                      RMI_ASSIGNED or ripas is not RIPAS_RAM).
 *                      Only 's2_walk.rtt_level' and 's2_walk.ripas' are
 *                      updated. NS Host needs to fix.
 */
enum s2_walk_status realm_ipa_to_pa_with_rd(struct rd *rd,
				    unsigned long ipa,
				    struct s2_walk_result *s2_walk)
{
	struct granule *g_table_root;
	struct rtt_walk wi;
	unsigned long s2tte, *ll_table, offset;
	enum s2_walk_status walk_status;
	int sl;
	 unsigned long ipa_bits;

		if (!GRANULE_ALIGNED(ipa)) {
		return WALK_INVALID_PARAMS;
	}

	g_table_root = rd->s2_ctx.g_rtt;
	sl = realm_rtt_starting_level(rd);
	ipa_bits = realm_ipa_bits(rd);

	granule_lock(g_table_root, GRANULE_STATE_RTT);
	rtt_walk_lock_unlock(g_table_root, sl, ipa_bits, ipa, RTT_PAGE_LEVEL, &wi);

	ll_table = granule_map(wi.g_llt, SLOT_RTT);
	assert(ll_table != NULL);

	s2tte = s2tte_read(&ll_table[wi.index]);
	if (s2tte_is_assigned_ram(s2tte, wi.last_level)) {
		s2_walk->llt = wi.g_llt; /* Must be unlocked by caller */
		s2_walk->pa = s2tte_pa(s2tte, wi.last_level);
		offset = ipa & (s2tte_map_size(wi.last_level) - 1UL);
		s2_walk->pa += offset;

		s2_walk->ripas_val = RIPAS_RAM;
		walk_status = WALK_SUCCESS;
	} else {
		if (s2tte_is_unassigned_destroyed(s2tte) ||
		    s2tte_is_assigned_destroyed(s2tte, wi.last_level)) {
			s2_walk->ripas_val = RIPAS_DESTROYED;
		} else if (s2tte_is_unassigned_ram(s2tte)) {
			s2_walk->ripas_val = RIPAS_RAM;
		} else {
			/*
			 * Only unassigned_empty & assigned_empty
			 * are left as an option.
			 */
			s2_walk->ripas_val = RIPAS_EMPTY;
		}

		granule_unlock(wi.g_llt);
		walk_status = WALK_FAIL;
	}

	s2_walk->rtt_level = (unsigned long)wi.last_level;

	buffer_unmap(ll_table);
	return walk_status;
}

/*
 * Get RIPAS of IPA
 *
 * Parameters:
 *	[in]  @rec:		Pointer to the rec
 *	[in]  @ipa:		IPA for which RIPAS is queried.
 *	[out] @ripas_ptr:	RIPAS value returned for the IPA. This is set in
 *				case of WALK_SUCCESS is returned.
 * Returns:
 *	WALK_SUCCESS:		RIPAS of IPA found
 *	WALK_FAIL:		RIPAS of IPA not found
 */
enum s2_walk_status realm_ipa_get_ripas(struct rec *rec, unsigned long ipa,
					enum ripas *ripas_ptr)
{
	unsigned long s2tte, *ll_table;
	struct rtt_walk wi;
	enum s2_walk_status ws;

	assert(ripas_ptr != NULL);
	assert(GRANULE_ALIGNED(ipa));
	assert(addr_in_rec_par(rec, ipa));

	granule_lock(rec->realm_info.g_rtt, GRANULE_STATE_RTT);

	rtt_walk_lock_unlock(rec->realm_info.g_rtt,
			     rec->realm_info.s2_starting_level,
			     rec->realm_info.ipa_bits,
			     ipa, RTT_PAGE_LEVEL, &wi);

	ll_table = granule_map(wi.g_llt, SLOT_RTT);
	assert(ll_table != NULL);

	s2tte = s2tte_read(&ll_table[wi.index]);
	if (!s2tte_has_ripas(s2tte, wi.last_level)) {
		ws = WALK_FAIL;
		goto out_unmap_unlock;
	}

	*ripas_ptr = s2tte_is_assigned_ram(s2tte, wi.last_level) ?
			RIPAS_RAM : s2tte_get_ripas(s2tte);
	ws = WALK_SUCCESS;

out_unmap_unlock:
	buffer_unmap(ll_table);
	granule_unlock(wi.g_llt);

	return ws;
}
unsigned long map_ipa_to_pa(struct rd *rd,
                                 unsigned long pa_addr,
                                 unsigned long ipa_addr)
{
	struct granule *g_table_root;
        struct rtt_walk wi;
	unsigned long s2tte, *s2tt;
        unsigned long ipa_bits;
        int sl;

 	g_table_root = rd->s2_ctx.g_rtt;
	sl = realm_rtt_starting_level(rd);
	ipa_bits = realm_ipa_bits(rd);
	granule_lock(g_table_root, GRANULE_STATE_RTT);
        rtt_walk_lock_unlock(g_table_root, sl, ipa_bits,
                             ipa_addr, RTT_PAGE_LEVEL, &wi);
	if (wi.last_level != RTT_PAGE_LEVEL) {
              goto out_unlock_ll_table;
        }
	s2tt = granule_map(wi.g_llt, SLOT_RTT);
        assert(s2tt != NULL);

        s2tte = s2tte_read(&s2tt[wi.index]);

	if (s2tte_is_assigned_ram(s2tte, wi.last_level)) {
//	s2tte = s2tte_create_assigned_ram_read_only(pa_addr, RTT_PAGE_LEVEL);
 	s2tte = s2tte_create_assigned_ram(pa_addr, RTT_PAGE_LEVEL);
        s2tte_write(&s2tt[wi.index], s2tte);
	}
	struct realm_s2_context s2_ctx = rd->s2_ctx;
	invalidate_page(&s2_ctx, ipa_addr);

//        ret = RMI_SUCCESS;

        buffer_unmap(s2tt);
out_unlock_ll_table:
        granule_unlock(wi.g_llt);
//        granule_unlock_transition(g_data, new_data_state);
        return 0;
}

#define ALIGN_2MB (2UL * 1024 * 1024)

int is_2mb_aligned(unsigned long addr) {
    return (addr & (ALIGN_2MB - 1)) == 0;
}

unsigned long copy_page_table(struct rd *master_rd, struct rd *slave_rd,
                                 unsigned long master_ipa,
                                 unsigned long slave_ipa)
{
	struct granule *g_table_root, *g_table_root_slave;
        struct rtt_walk wi, wi_slave;
        unsigned long ipa_bits, ipa_bits_slave;
        int sl, sl_slave;
	if (!(is_2mb_aligned(master_ipa) && is_2mb_aligned(slave_ipa))){
		printf("Addresses 0x%lx or 0x%lx are not 2MB aligned.\n", master_ipa, slave_ipa);
		return 0;
	}

 	g_table_root = master_rd->s2_ctx.g_rtt;
	sl = realm_rtt_starting_level(master_rd);
	ipa_bits = realm_ipa_bits(master_rd);
	granule_lock(g_table_root, GRANULE_STATE_RTT);
        rtt_walk_lock_unlock(g_table_root, sl, ipa_bits,
                             master_ipa, RTT_PAGE_LEVEL, &wi);
	if (wi.last_level != RTT_PAGE_LEVEL) {
              goto out_unlock_ll_table;
		 INFO("out_unlock_ll_table2 \n");
        }
	void *s2tt = granule_map(wi.g_llt, SLOT_RTT2);
        assert(s2tt != NULL);

	g_table_root_slave = slave_rd->s2_ctx.g_rtt;
        sl_slave = realm_rtt_starting_level(slave_rd);
        ipa_bits_slave = realm_ipa_bits(slave_rd);
        granule_lock(g_table_root_slave, GRANULE_STATE_RTT);
        rtt_walk_lock_unlock(g_table_root_slave, sl_slave, ipa_bits_slave,
                             slave_ipa, RTT_PAGE_LEVEL, &wi_slave);
        if (wi_slave.last_level != RTT_PAGE_LEVEL) {
		INFO("out_unlock_ll_table2 \n");
              goto out_unlock_ll_table2;
        }
        void *s2tt_slave = granule_map(wi_slave.g_llt, SLOT_RTT);
        assert(s2tt_slave != NULL);

	memcpy(s2tt_slave, s2tt, GRANULE_SIZE);
	INFO("Copied rtt with starting address 0x%lx from master to slave starting address 0x%lx \n", master_ipa, slave_ipa);
	struct realm_s2_context s2_ctx = slave_rd->s2_ctx;
	invalidate_pages_in_block(&s2_ctx, slave_ipa);

        buffer_unmap(s2tt);
	buffer_unmap(s2tt_slave);
	granule_unlock(wi_slave.g_llt);
	granule_unlock(wi.g_llt);

out_unlock_ll_table:
        granule_unlock(wi.g_llt);
        return 0;

out_unlock_ll_table2:
 	buffer_unmap(s2tt);
	granule_unlock(wi_slave.g_llt);
	granule_unlock(wi.g_llt);
	return 0;
}
