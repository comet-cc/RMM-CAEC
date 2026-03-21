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
