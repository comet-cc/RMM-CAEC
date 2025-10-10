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
	struct apt apt_params;
	bool ns_access_ok;

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
 	
	if (apt_params.csdata_ipa_begin > apt_params.csdata_ipa_end) {
		ret = RMI_ERROR_REALM;
        goto out_unmap;
	}
	
	apt->csdata_ipa_begin = apt_params.csdata_ipa_begin;
        apt->csdata_ipa_end = apt_params.csdata_ipa_end;

	unsigned long m_start = apt_params.master_memory.ipa_start;
	unsigned long m_size  = apt_params.master_memory.map_size;
	unsigned long s_start = apt_params.slave_memory.ipa_start;
	unsigned long s_size  = apt_params.slave_memory.map_size;

	unsigned long m_end = 0, s_end = 0;
	bool err = false;


	if (apt_params.master_memory.enable && apt_params.slave_memory.enable) {

    /* Compute ends with overflow protection */
    	if (!ADD_OK_UL(m_start, m_size, &m_end)) {
    	    /* ERROR: master range overflows */
    	    err = true;
    	}
   		if (!ADD_OK_UL(s_start, s_size, &s_end)) {
   	    	/* ERROR: slave range overflows */
   	     	err = true;
    	}

    /* Containment within csdata [begin, end) */
 	    if (!WITHIN(apt->csdata_ipa_begin, apt->csdata_ipa_end, m_start, m_end)) {
        /* ERROR: master range outside csdata bounds */
			err = true;
    	}
    	if (!WITHIN(apt->csdata_ipa_begin, apt->csdata_ipa_end, s_start, s_end)) {
        	/* ERROR: slave range outside csdata bounds */
			err = true;
    	}

	    /* No overlap between enabled regions (half-open intervals) */
   		if (!DISJOINT(m_start, m_end, s_start, s_end)) {
        	/* ERROR: master/slave regions overlap */
			err = true;
    	}
	}

	if (!(apt_params.master_memory.enable) && apt_params.slave_memory.enable) {

    	if (!ADD_OK_UL(s_start, s_size, &s_end)) {
        	/* ERROR: slave range overflows */
			err = true;
    	}
	    if (!WITHIN(apt->csdata_ipa_begin, apt->csdata_ipa_end, s_start, s_end)) {
    	    /* ERROR: slave range outside csdata bounds */
			err = true;
    	}
	}

	if (apt_params.master_memory.enable && !(apt_params.slave_memory.enable)) {

    	if (!ADD_OK_UL(m_start, m_size, &m_end)) {
        	/* ERROR: master range overflows */
			err = true;
    	}
    	if (!WITHIN(apt->csdata_ipa_begin, apt->csdata_ipa_end, m_start, m_end)) {
        	/* ERROR: master range outside csdata bounds */
			err = true;
    	}
	}

	if (err) {
			ret = RMI_ERROR_REALM;
        	goto out_unmap;
	}

	apt->master_memory.ipa_start = apt_params.csdata_ipa_begin;
	apt->master_memory.map_size = apt_params.csdata_ipa_end - apt_params.csdata_ipa_begin;
	apt->slave_memory.ipa_start = apt_params.csdata_ipa_begin;
	apt->slave_memory.map_size = apt_params.csdata_ipa_end - apt_params.csdata_ipa_begin;
	apt->master_memory.enable = apt_params.master_memory.enable;
	apt->slave_memory.enable = apt_params.slave_memory.enable;
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

