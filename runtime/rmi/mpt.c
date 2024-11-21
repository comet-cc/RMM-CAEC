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
#include <mpt.h>

//struct mpt {
//	unsigned long test;
//};

unsigned long smc_mpt_create(unsigned long rd_addr,
			     unsigned long mpt_addr,
			     unsigned long mpt_params_addr)
{
	INFO("this is smc_mpt_create \n");
	struct granule *g_rd;
        struct granule *g_mpt;
        //struct granule *g_mpt_params;
        struct mpt *mpt;
        struct rd *rd;
//        struct rmi_mpt_params mpt_params;
	//unsigned long rec_idx;
        enum granule_state new_mpt_state = GRANULE_STATE_MPT;
        unsigned long ret;
//        bool ns_access_ok;
//	g_mpt_params = find_granule(mpt_params_addr);
//        if ((g_mpt_params == NULL) || (g_mpt_params->state != GRANULE_STATE_NS)) {

  //              return RMI_ERROR_INPUT;
//	}

  //      ns_access_ok = ns_buffer_read(SLOT_NS, g_mpt_params, 0U,
    //                                  sizeof(mpt_params), &mpt_params);

      //  if (!ns_access_ok) {
       //         return RMI_ERROR_INPUT;
       // }

        if (!find_lock_two_granules(mpt_addr,
                                GRANULE_STATE_DELEGATED, &g_mpt,
                                rd_addr,
                                GRANULE_STATE_RD, &g_rd)) {
                ret = RMI_ERROR_INPUT;
                goto out_free_aux;
	}
 	mpt = granule_map(g_mpt, SLOT_MPT);
        assert(mpt != NULL);

        rd = granule_map(g_rd, SLOT_RD);
        assert(rd != NULL);

	if (get_rd_state_locked(rd) != REALM_STATE_NEW) {
                ret = RMI_ERROR_REALM;
                goto out_unmap;
        }
	// later we initialize this value in the initial content of RD created by the hypervisor
	rd->mpt_pa =  mpt_addr;
	INFO("this is test value %lx \n", mpt->test);
	mpt->test = 10;
	INFO("this is test value %lx \n", mpt->test);
	ret = RMI_SUCCESS;
out_unmap:
        buffer_unmap(rd);
        buffer_unmap(mpt);

        granule_unlock(g_rd);
        granule_unlock_transition(g_mpt, new_mpt_state);

out_free_aux:
        if (ret != RMI_SUCCESS) {
//                free_rec_aux_granules(rec_aux_granules, num_rec_aux, false);
        }
        return ret;
}


unsigned long smc_mpt_destroy(unsigned long rec_addr)
{
	INFO("this is smc_mpt_destroy \n");
	return RMI_SUCCESS;
}

