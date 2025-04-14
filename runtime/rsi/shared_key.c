/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <realm.h>
#include <ripas.h>
#include <rsi-handler.h>
#include <smc-rsi.h>
#include <status.h>
#include <granule.h>
#include <mpt.h>
#include <debug.h>

void handle_rsi_shared_key(struct rec *rec,
			      struct rmi_rec_exit *rec_exit,
			      struct rsi_result *res)
{
	unsigned long flag = rec->regs[1];
	if (flag == 0)
		handle_rsi_shared_key_set_master(rec, rec_exit, res);
	if (flag == 1)
		handle_rsi_shared_key_set_slave(rec, rec_exit, res);
}


void handle_rsi_shared_key_set_master(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	unsigned long slave_rd_pa = rec->regs[2];
        struct rd *rd;
	unsigned long mpt_pa;
	struct granule *g_mpt;
        struct mpt *mpt;
	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
        rd = granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(rd != NULL);
        mpt_pa = rd->mpt_pa;

        g_mpt = find_lock_granule(mpt_pa, GRANULE_STATE_MPT);
        mpt = granule_map(g_mpt, SLOT_MPT);
        assert(mpt != NULL);
	// Replace the number below with a randomly generated number later
	mpt->shared_key.key = 0x1000;
	mpt->shared_key.slave_rd_pa = slave_rd_pa;
	mpt->shared_key.master_rd_pa = (unsigned long)rec->realm_info.g_rd;
	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);
        buffer_unmap(mpt);
        granule_unlock(g_mpt);
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = mpt->shared_key.slave_rd_pa;
	res->smc_res.x[2] = mpt->shared_key.key;
}


void handle_rsi_shared_key_set_slave(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	unsigned long master_rd_pa = rec->regs[2];

        struct rd *rd, *master_rd;
        unsigned long mpt_pa, master_mpt_pa;
        struct granule *g_mpt, *g_mpt_master, *g_rd_master;
        struct mpt *mpt, *mpt_master;
	unsigned long secret_key;
        granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
        rd = granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(rd != NULL);
        mpt_pa = rd->mpt_pa;
	// 1- Finding the value of secret key in the master's MPT
//	granule_lock(master_rd_pa, GRANULE_STATE_RD);
        g_rd_master = find_lock_granule(master_rd_pa, GRANULE_STATE_RD);
        master_rd = granule_map(g_rd_master, SLOT_RD2);
	assert(master_rd != NULL);
	master_mpt_pa = master_rd->mpt_pa;

        g_mpt_master = find_lock_granule(master_mpt_pa, GRANULE_STATE_MPT);
        mpt_master = granule_map(g_mpt_master, SLOT_MPT);
        assert(mpt_master != NULL);

        if (mpt_master->shared_key.slave_rd_pa == (unsigned long)rec->realm_info.g_rd) {
                secret_key = mpt_master->shared_key.key;
        } else {
                INFO("Illegal, master has not set this yet \n");
		// Fix this later
		 secret_key = 0x333;
        }
	buffer_unmap(master_rd);
	granule_unlock(g_rd_master);
	buffer_unmap(mpt_master);
	granule_unlock(g_mpt_master);
	// 2- Placing the secret key info the MPT of slave realm
 	
	g_mpt = find_lock_granule(mpt_pa, GRANULE_STATE_MPT);
        mpt = granule_map(g_mpt, SLOT_MPT);
        assert(mpt != NULL);

    //    if (mpt->shared_key.key == 0) {
        // Replace the number below with a randomly generated number later
                mpt->shared_key.key = secret_key;
                mpt->shared_key.slave_rd_pa =  (unsigned long)rec->realm_info.g_rd;
                mpt->shared_key.master_rd_pa = master_rd_pa;
     //   } else {
                INFO("Nothing to do for now \n");
//
    //    }

        buffer_unmap(rd);
        granule_unlock(rec->realm_info.g_rd);
        buffer_unmap(mpt);
        granule_unlock(g_mpt);
        res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
        res->smc_res.x[1] = mpt->shared_key.master_rd_pa;
	res->smc_res.x[2] = mpt->shared_key.key;
}























