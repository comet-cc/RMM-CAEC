/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <buffer.h>
#include <granule.h>
#include <realm.h>

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
	struct s2tt_walk wi;
	unsigned long s2tte, *ll_table;
	enum s2_walk_status walk_status;
	struct s2tt_context *s2_ctx;

	if (!GRANULE_ALIGNED(ipa) || !addr_in_rec_par(rec, ipa)) {
		return WALK_INVALID_PARAMS;
	}

	s2_ctx = &(rec->realm_info.s2_ctx);
	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);

	s2tt_walk_lock_unlock(s2_ctx, ipa, S2TT_PAGE_LEVEL, &wi);

	ll_table = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(ll_table != NULL);

	s2tte = s2tte_read(&ll_table[wi.index]);

	if (s2tte_is_assigned_ram(s2_ctx, s2tte, wi.last_level)) {
		unsigned long offset;

		s2_walk->llt = wi.g_llt; /* Must be unlocked by caller */
		s2_walk->pa = s2tte_pa(s2_ctx, s2tte, wi.last_level);
		offset = ipa & (s2tte_map_size(wi.last_level) - 1UL);
		s2_walk->pa += offset;
		s2_walk->ripas_val = RIPAS_RAM;
		walk_status = WALK_SUCCESS;
	} else {
		if (s2tte_is_unassigned_destroyed(s2_ctx, s2tte) ||
		    s2tte_is_assigned_destroyed(s2_ctx,
						s2tte, wi.last_level)) {
			s2_walk->ripas_val = RIPAS_DESTROYED;
		} else if (s2tte_is_unassigned_ram(s2_ctx, s2tte)) {
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

//	if (!GRANULE_ALIGNED(ipa) || !addr_in_rec_par(rec)) {
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
 *	[in]  @start:		IPA range start for which RIPAS is queried.
 *	[in]  @end:		IPA range end (excluding) for which RIPAS is queried.
 *	[out] @top:		IPA of the top address of the range completed.
 *	[out] @ripas_ptr:	RIPAS value returned for the range (start, top).
 *				Set in case of WALK_SUCCESS is returned.
 * Returns:
 *	WALK_SUCCESS:		RIPAS of IPA [start, top) range found
 *	WALK_FAIL:		RIPAS of IPA start not found
 */
enum s2_walk_status realm_ipa_get_ripas(struct rec *rec, unsigned long start,
					unsigned long end, unsigned long *top,
					enum ripas *ripas_ptr)
{
	unsigned long *ll_table;
	unsigned long addr, map_size, index;
	struct s2tt_walk wi;
	enum s2_walk_status ws;
	enum ripas res = RIPAS_EMPTY;
	struct s2tt_context *s2_ctx;

	assert(GRANULE_ALIGNED(start) && GRANULE_ALIGNED(end));
	assert(addr_in_rec_par(rec, start) && addr_in_rec_par(rec, end - 1UL));
	assert((top != NULL) && (ripas_ptr != NULL));

	s2_ctx = &(rec->realm_info.s2_ctx);
	granule_lock(s2_ctx->g_rtt, GRANULE_STATE_RTT);

	s2tt_walk_lock_unlock(s2_ctx, start, S2TT_PAGE_LEVEL, &wi);

	ll_table = buffer_granule_map(wi.g_llt, SLOT_RTT);
	assert(ll_table != NULL);

	map_size = s2tte_map_size((int)wi.last_level);
	start &= ~(map_size - 1UL);
	addr = start;

	for (index = wi.index; index < S2TTES_PER_S2TT; index++) {
		enum ripas tmp;
		unsigned long s2tte = s2tte_read(&ll_table[index]);

		if (!s2tte_has_ripas(s2_ctx, s2tte, wi.last_level)) {
			break;
		}
		tmp = s2tte_is_assigned_ram(s2_ctx, s2tte, wi.last_level) ?
			RIPAS_RAM : s2tte_get_ripas(s2_ctx, s2tte);
		/*
		 * Cache the result of the first entry and compare the rest
		 * with the first and break if there is a mismatch.
		 */
		if (addr == start) {
			res = tmp;
		} else if (tmp != res) {
			break;
		}
		addr += map_size;
		if (addr >= end) {
			break;
		}
	}

	if (addr != start) {
		ws = WALK_SUCCESS;
		*ripas_ptr = res;
		*top = addr;
	} else {
		ws = WALK_FAIL;
	}

	buffer_unmap(ll_table);
	granule_unlock(wi.g_llt);
	return ws;
}
unsigned long map_ipa_to_pa(struct rd *rd,
                                 unsigned long pa_addr,
                                 unsigned long ipa_addr)
{
       // struct granule *g_data;
        //struct granule *g_rd;
	struct granule *g_table_root;
        struct rtt_walk wi;
	unsigned long s2tte, *s2tt;
        ///enum granule_state new_data_state = GRANULE_STATE_DELEGATED;
        unsigned long ipa_bits;
//	unsigned long ret;
        int __unused meas_ret;
        int sl;

 	g_table_root = rd->s2_ctx.g_rtt;
	sl = realm_rtt_starting_level(rd);
	ipa_bits = realm_ipa_bits(rd);
	granule_lock(g_table_root, GRANULE_STATE_RTT);
        rtt_walk_lock_unlock(g_table_root, sl, ipa_bits,
                             ipa_addr, RTT_PAGE_LEVEL, &wi);
	if (wi.last_level != RTT_PAGE_LEVEL) {
//                ret = pack_return_code(RMI_ERROR_RTT,
 //                                      (unsigned int)wi.last_level);
                goto out_unlock_ll_table;
        }
	s2tt = granule_map(wi.g_llt, SLOT_RTT);
        assert(s2tt != NULL);

        s2tte = s2tte_read(&s2tt[wi.index]);
        if (!s2tte_is_unassigned(s2tte)) {
             //   ret = pack_return_code(RMI_ERROR_RTT, RTT_PAGE_LEVEL);
                goto out_unmap_ll_table;
        }
//	s2tte = s2tte_create_assigned_unchanged(s2tte, pa_addr, RTT_PAGE_LEVEL);
//	s2tte = s2tte_create_assigned_ram(pa_addr, RTT_PAGE_LEVEL);
//        new_data_state = GRANULE_STATE_DATA;
	if (s2tte_is_assigned_ram(s2tte, wi.last_level)) {
	s2tte = s2tte_create_assigned_ram(pa_addr, RTT_PAGE_LEVEL);
        s2tte_write(&s2tt[wi.index], s2tte);
	}
//        __granule_get(wi.g_llt);
	struct realm_s2_context s2_ctx = rd->s2_ctx;
	invalidate_page(&s2_ctx, ipa_addr);

//        ret = RMI_SUCCESS;

out_unmap_ll_table:
        buffer_unmap(s2tt);
out_unlock_ll_table:
        granule_unlock(wi.g_llt);
//        granule_unlock_transition(g_data, new_data_state);
        return 0;
}
