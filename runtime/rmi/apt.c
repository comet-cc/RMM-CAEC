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


unsigned long smc_apt_create(unsigned long rd_addr,
			     unsigned long apt_addr,
			     unsigned long apt_params_addr)
{
	INFO("this is smc_apt_create \n");
	struct granule *g_rd;
        struct granule *g_apt;
        struct apt *apt;
        struct rd *rd;
        unsigned long ret;

        if (!find_lock_two_granules(apt_addr,
                                GRANULE_STATE_DELEGATED, &g_apt,
                                rd_addr,
                                GRANULE_STATE_RD, &g_rd)) {
                ret = RMI_ERROR_INPUT;
                goto out_free_aux;
	}
 	apt = buffer_granule_map(g_apt, SLOT_APT);
        assert(apt != NULL);

        rd = buffer_granule_map(g_rd, SLOT_RD);
        assert(rd != NULL);

	if (get_rd_state_locked(rd) != REALM_NEW) {
                ret = RMI_ERROR_REALM;
                goto out_unmap;
        }
	// later we initialize this value in the initial content of RD created by the hypervisor
	rd->apt_pa = apt_addr;
	INFO("this is test value %lx \n", apt->test);
	apt->test = 10;
	INFO("this is test value %lx \n", apt->test);
	ret = RMI_SUCCESS;
	goto out_unmap;
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
	INFO("this is smc_apt_destroy \n");
        struct granule *g_apt;
        int ret;
	struct rd *rd;
	struct granule *g_rd;
	g_rd = find_granule(rd_addr);
	rd = buffer_granule_map(g_rd, SLOT_RD);
	assert(rd != NULL);

	if (rd->apt_pa != apt_addr){
		ret = RMI_ERROR_REALM;
                goto out_unmap;
	}

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

