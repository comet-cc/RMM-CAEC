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
#include <realm_tag.h>


#define ADD_OK_UL(a, b, out_end) \
    (((b) <= (ULONG_MAX - (a))) ? (*(out_end) = (a) + (b), true) : false)

/* [lo, hi) half-open interval containment */
#define WITHIN(lo, hi, s, e) ((s) >= (lo) && (e) <= (hi))

/* Disjoint half-open intervals: [s1,e1) and [s2,e2) */
#define DISJOINT(s1, e1, s2, e2) ((e1) <= (s2) || (e2) <= (s1))


unsigned long smc_apt_create(unsigned long rd_addr,
			     unsigned long apt_addr, unsigned long apt_params_addr)
{
	struct granule *g_rd;
    struct granule *g_apt;
    struct apt *apt;
    struct rd *rd;
    unsigned long ret;
	struct granule *g_apt_params;
	struct apt_kvm apt_params;
	bool ns_access_ok;
	
	//enum apt_region_kind kind;
	//size_t idx;

    g_apt_params = find_granule(apt_params_addr);
	if ((g_apt_params == NULL) ||
		(granule_unlocked_state(g_apt_params) != GRANULE_STATE_NS)) {
		return RMI_ERROR_INPUT;
	}

	ns_access_ok = ns_buffer_read(SLOT_NS, g_apt_params, 0U,
				      sizeof(apt_params), &apt_params);

	if (!ns_access_ok) {
		return RMI_ERROR_INPUT;
	}

    if (!find_lock_two_granules(apt_addr,
                                GRANULE_STATE_DELEGATED, &g_apt,
                                rd_addr,
                                GRANULE_STATE_RD, &g_rd)) {
                return RMI_ERROR_REALM;
                goto out_free_aux;
	}
 	apt = buffer_granule_map(g_apt, SLOT_APT);
    assert(apt != NULL);

    rd = buffer_granule_map(g_rd, SLOT_RD);
    assert(rd != NULL);

	// This function cannot be called at runtime
	if (get_rd_state_locked(rd) != REALM_NEW) {
                ret = RMI_ERROR_REALM;
                goto out_unmap;
        }
	// later we initialize this value in the initial content of RD created by the hypervisor
	rd->apt_pa = apt_addr;
	// Create Unique Tag fo the realm. FOr now the available IDs are hardcoded
	INFO("apt_params.csdata_ipa_begin: %lx apt_params.csdata_ipa_begin %lx \n", apt_params.csdata_ipa_begin, apt_params.csdata_ipa_end);
	uint8_t ID;
	(void)realm_tag_assign(rd_addr, &ID);
	INFO("realm tag assigned %x \n", ID);
 	
	//if (apt_params.csdata_ipa_begin > apt_params.csdata_ipa_end) {
	//	ret = RMI_ERROR_REALM;
     //   goto out_unmap;
	//}
	
	apt->csdata_ipa_begin = apt_params.csdata_ipa_begin;
    apt->csdata_ipa_end = apt_params.csdata_ipa_end;
	
	//unsigned long m_start, m_end;
	//unsingned long m_size;
	//checking master address ranges
   /*
	for (int i = 0; i < MAX_MEM_REGIONS; i++) {
		
		if (apt_params.master_memory[i].enable == false)
			continue;

		if (apt_params.master_memory[i].map_size <= 0) {
			ret = RMI_ERROR_REALM;
        	goto out_unmap;
		}
	
		m_start = apt_params.master_memory[i].ipa_start;
		
		m_end = apt_params.master_memory[i].ipa_start + apt_params.master_memory[i].map_size;
		
		
		if(WITHIN(apt_params.csdata_ipa_begin, apt_params.csdata_ipa_end, m_start, m_end) == false)
		{
			INFO("Master address range is not within the csdata range %lx - %lx : %lx - %lx\n", 
				apt_params.csdata_ipa_begin, apt_params.csdata_ipa_end, m_start, m_end);
			ret = RMI_ERROR_REALM;
        	goto out_unmap;
		}
		
		apt_add_master(apt, apt_params.master_memory[i].slave_ID,
					   apt_params.master_memory[i].slave_rd_pa,
                       apt_params.master_memory[i].ipa_start,
                       apt_params.master_memory[i].map_size,
                       apt_params.master_memory[i].flags,
                       apt_params.master_memory[i].enable);
        INFO("Added master region %d : slave_ID = %x, slave_rd_pa = %lx, ipa_start = %lx, map_size = %lx \n",
             i, apt_params.master_memory[i].slave_ID,
             apt_params.master_memory[i].slave_rd_pa,
             apt_params.master_memory[i].ipa_start,
             apt_params.master_memory[i].map_size); 
	}


	for (int i = 0; i < MAX_MEM_REGIONS; i++) {
		
		if (apt_params.slave_memory[i].enable == false)
			continue;

		if (apt_params.slave_memory[i].map_size <= 0) {
			ret = RMI_ERROR_REALM;
        	goto out_unmap;
		}

	    m_start = apt_params.slave_memory[i].ipa_start;
		
		m_end = apt_params.slave_memory[i].ipa_start + apt_params.slave_memory[i].map_size;

	
		if(WITHIN(apt_params.csdata_ipa_begin, apt_params.csdata_ipa_end, m_start, m_end) == false)
		{
			INFO("Slave address range is not within the csdata range %lx - %lx : %lx - %lx\n", 
				apt_params.csdata_ipa_begin, apt_params.csdata_ipa_end, m_start, m_end);
			ret = RMI_ERROR_REALM;
        	goto out_unmap;
		}
		

      
		if (apt_find_enabled_conflict(apt, m_start, apt_params.slave_memory[i].map_size, &kind, &idx)) {
			INFO("Slave address range %lx - %lx conflicts with %s region %lx - %lx\n",
				m_start, m_end,
				(kind == APT_REGION_MASTER) ? "master" : "slave",
				(kind == APT_REGION_MASTER) ? apt->master_memory[idx].ipa_start : apt->slave_memory[idx].ipa_start,
				(kind == APT_REGION_MASTER) ? apt->master_memory[idx].ipa_start + apt->master_memory[idx].map_size : apt->slave_memory[idx].ipa_start + apt->slave_memory[idx].map_size);
			ret = RMI_ERROR_REALM;
			goto out_unmap;
		}
		
		apt_add_slave(apt, apt_params.slave_memory[i].master_ID,
					   apt_params.slave_memory[i].master_rd_pa,
                       apt_params.slave_memory[i].ipa_start,
                       apt_params.slave_memory[i].map_size,
                       apt_params.slave_memory[i].flags,
                       apt_params.slave_memory[i].enable);
        INFO("Added slave region %d : master_ID = %x, master_rd_pa = %lx, ipa_start = %lx, map_size = %lx \n",
             i, apt_params.slave_memory[i].master_ID,
             apt_params.slave_memory[i].master_rd_pa,
             apt_params.slave_memory[i].ipa_start,
             apt_params.slave_memory[i].map_size);  
	}
   
*/
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

unsigned long smc_apt_destroy(unsigned long rd_addr, unsigned long apt_addr)
{
        struct granule *g_apt;
        int ret;
	struct rd *rd;
	struct granule *g_rd;
	g_rd = find_lock_granule(rd_addr, GRANULE_STATE_RD);
	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (rd->apt_pa != apt_addr){
		ret = RMI_ERROR_REALM;
                goto out_unmap;
	}
	// Remove Unique Tag for the realm
	(void)realm_tag_remove(rd_addr);
	g_apt = find_lock_granule(apt_addr, GRANULE_STATE_APT);
	assert(g_apt != NULL);
        buffer_granule_memzero(g_apt, SLOT_APT);
        granule_unlock_transition(g_apt, GRANULE_STATE_DELEGATED);
	buffer_unmap(rd);
        granule_unlock(g_rd);
	return RMI_SUCCESS;
out_unmap:
	buffer_unmap(rd);
	granule_unlock(g_rd);
	return ret;
}




static inline size_t first_free_from_mask(uint64_t used_mask) {
    for (size_t i = 0; i < MAX_MEM_REGIONS; ++i)
        if ((used_mask & BIT64(i)) == 0) return i;
    return SIZE_MAX;
}

static inline void enable_push_master(struct apt *a, size_t idx) {
    struct enabled_master_regions *em = &a->enabled_mr;
    size_t pos = em->len;
    em->index[pos] = idx;
    em->pos_by_index[idx] = pos;
    em->len++;
    a->master_enabled_mask |= BIT64(idx);
}

static inline void enable_push_slave(struct apt *a, size_t idx) {
    struct enabled_slave_regions *es = &a->enabled_sr;
    size_t pos = es->len;
    es->index[pos] = idx;
    es->pos_by_index[idx] = pos;
    es->len++;
    a->slave_enabled_mask |= BIT64(idx);
}

static inline void disable_swap_pop_master(struct apt *a, size_t idx) {
    struct enabled_master_regions *em = &a->enabled_mr;
    size_t pos = em->pos_by_index[idx];
    size_t last_pos = em->len - 1;

    if (pos != last_pos) {
        em->index[pos] = em->index[last_pos];
        em->pos_by_index[ em->index[pos] ] = pos;
    }
    em->len--;
    a->master_enabled_mask &= ~BIT64(idx);
}

static inline void disable_swap_pop_slave(struct apt *a, size_t idx) {
    struct enabled_slave_regions *es = &a->enabled_sr;
    size_t pos = es->pos_by_index[idx];
    size_t last_pos = es->len - 1;

    if (pos != last_pos) {
        es->index[pos] = es->index[last_pos];
        es->pos_by_index[ es->index[pos] ] = pos;
    }
    es->len--;
    a->slave_enabled_mask &= ~BIT64(idx);
}

/* Safe half-open range overlap check (treat overflow as conflict) */
static inline bool range_overlaps_ul(unsigned long a_start, unsigned long a_size,
                                     unsigned long b_start, unsigned long b_size)
{
    if (a_size == 0 || b_size == 0) return false;

    unsigned long a_end = a_start + a_size;
    unsigned long b_end = b_start + b_size;

    if (a_end < a_start || b_end < b_start) return true; /* overflow → conflict */

    /* [a_start, a_end) vs [b_start, b_end) */
    return !(a_end <= b_start || b_end <= a_start);
}

/* ---- Public API ---- */

void apt_reset(struct apt *a) {
    memset(a, 0, sizeof(*a));
}

size_t apt_add_master(struct apt *a,
                      uint8_t slave_ID,
                      unsigned long slave_rd_pa,
                      unsigned long ipa_start,
                      unsigned long map_size,
                      uint8_t flags,
                      bool enable_now)
{
    size_t idx = first_free_from_mask(a->master_used_mask);
    if (idx == SIZE_MAX) return SIZE_MAX;

    struct master_mem *m = &a->master_memory[idx];
    m->slave_ID    = slave_ID;
    m->slave_rd_pa = slave_rd_pa;
    m->ipa_start   = ipa_start;
    m->map_size    = map_size;
    m->flags       = flags;

    a->master_used_mask |= BIT64(idx);

    if (enable_now && !(a->master_enabled_mask & BIT64(idx))) {
        enable_push_master(a, idx);
    }

    INFO("apt_add_master: idx=%lu slave_ID=%u slave_rd_pa=0x%lx ipa_start=0x%lx map_size=0x%lx flags=%u enable_now=%d\n",
         idx, slave_ID, slave_rd_pa, ipa_start, map_size, flags, enable_now);

    return idx;
}

size_t apt_add_slave(struct apt *a,
                     uint8_t master_ID,
                     unsigned long master_rd_pa,
                     unsigned long ipa_start,
                     unsigned long map_size,
                     uint8_t flags,
                     bool enable_now)
{
    size_t idx = first_free_from_mask(a->slave_used_mask);
    if (idx == SIZE_MAX) return SIZE_MAX;

    struct slave_mem *s = &a->slave_memory[idx];
    s->master_ID    = master_ID;
    s->master_rd_pa = master_rd_pa;
    s->ipa_start    = ipa_start;
    s->map_size     = map_size;
    s->flags        = flags;

    a->slave_used_mask |= BIT64(idx);

    if (enable_now && !(a->slave_enabled_mask & BIT64(idx))) {
        enable_push_slave(a, idx);
    }

    INFO("apt_add_slave: idx=%lu master_ID=%u master_rd_pa=0x%lx ipa_start=0x%lx map_size=0x%lx flags=%u enable_now=%d\n",
         idx, master_ID, master_rd_pa, ipa_start, map_size, flags, enable_now);

    return idx;
}

bool apt_enable_master_idx(struct apt *a, size_t idx) {
    if (!apt_idx_in_range(idx)) return false;
    if (!(a->master_used_mask & BIT64(idx))) return false;
    if (a->master_enabled_mask & BIT64(idx)) return true; /* already enabled */
    enable_push_master(a, idx);
    return true;
}

bool apt_disable_master_idx(struct apt *a, size_t idx) {
    if (!apt_idx_in_range(idx)) return false;
    if (!(a->master_enabled_mask & BIT64(idx))) return true; /* already disabled */
    disable_swap_pop_master(a, idx);
    return true;
}

bool apt_enable_slave_idx(struct apt *a, size_t idx) {
    if (!apt_idx_in_range(idx)) return false;
    if (!(a->slave_used_mask & BIT64(idx))) return false;
    if (a->slave_enabled_mask & BIT64(idx)) return true; /* already enabled */
    enable_push_slave(a, idx);
    return true;
}

bool apt_disable_slave_idx(struct apt *a, size_t idx) {
    if (!apt_idx_in_range(idx)) return false;
    if (!(a->slave_enabled_mask & BIT64(idx))) return true; /* already disabled */
    disable_swap_pop_slave(a, idx);
    return true;
}

bool apt_find_enabled_conflict(const struct apt *a,
                               unsigned long ipa_start,
                               unsigned long map_size,
                               enum apt_region_kind *kind_out,
                               size_t *idx_out)
{
    /* Check enabled masters */
    for (size_t pos = 0; pos < a->enabled_mr.len; ++pos) {
        size_t idx = a->enabled_mr.index[pos];
        const struct master_mem *m = &a->master_memory[idx];
        if (range_overlaps_ul(ipa_start, map_size, m->ipa_start, m->map_size)) {
            if (kind_out) *kind_out = APT_REGION_MASTER;
            if (idx_out)  *idx_out  = idx;
            return true;
        }
    }

    /* Check enabled slaves */
    for (size_t pos = 0; pos < a->enabled_sr.len; ++pos) {
        size_t idx = a->enabled_sr.index[pos];
        const struct slave_mem *s = &a->slave_memory[idx];
        if (range_overlaps_ul(ipa_start, map_size, s->ipa_start, s->map_size)) {
            if (kind_out) *kind_out = APT_REGION_SLAVE;
            if (idx_out)  *idx_out  = idx;
            return true;
        }
    }

    return false; /* no conflicts */
}

