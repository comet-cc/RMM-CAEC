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

void handle_rsi_shared_memory_set(struct rec *rec,
			      struct rmi_rec_exit *rec_exit,
			      struct rsi_result *res)
{
	unsigned long flag = rec->regs[2];
	if (flag == 0)
		handle_rsi_shared_memory_set_host(rec, rec_exit, res);
	if (flag == 1)
		handle_rsi_shared_memory_set_guest(rec, rec_exit, res);
	if (flag == 2)
		handle_rsi_shared_memory_set_mapping(rec, rec_exit, res);
}


void handle_rsi_shared_memory_set_host(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	unsigned long base_ipa = rec->regs[1];
        unsigned long host_rd_pa = rec->regs[3];
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
     
	mpt->host_memory.guest_rd_pa = host_rd_pa;
        mpt->host_memory.ipa = base_ipa;
	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);
        buffer_unmap(mpt);
        granule_unlock(g_mpt);
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = host_rd_pa;
	res->smc_res.x[2] = base_ipa;
}


void handle_rsi_shared_memory_set_guest(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	unsigned long base_ipa = rec->regs[1];
        unsigned long host_rd_pa = rec->regs[3];
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
        mpt->guest_memory.host_rd_pa = host_rd_pa;
        mpt->guest_memory.ipa = base_ipa;

	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);
        buffer_unmap(mpt);
        granule_unlock(g_mpt);
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = host_rd_pa;
	res->smc_res.x[2] = base_ipa;
}


void handle_rsi_shared_memory_set_mapping(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	struct rd *rd, *host_rd;
	struct granule *g_host_rd;
        unsigned long mpt_pa, mpt_pa_host;
        struct s2_walk_result walk_res;
        unsigned long ipa, host_rd_pa;
	struct granule *g_mpt, *g_mpt_host;
        struct mpt *mpt, *mpt_host;
	unsigned long addr;
 	enum s2_walk_status walk_status;

	struct my_shared_data {
     		int field1;
    		char field2;
    		unsigned long field3;
};

	// 1- Finding the target rd and then mpt
        granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
        rd = granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(rd != NULL);
        mpt_pa = rd->mpt_pa;
        buffer_unmap(rd);
        granule_unlock(rec->realm_info.g_rd);

        g_mpt = find_lock_granule(mpt_pa, GRANULE_STATE_MPT);
        mpt = granule_map(g_mpt, SLOT_MPT);
        assert(mpt != NULL);
        ipa = mpt->guest_memory.ipa;
	host_rd_pa = mpt->guest_memory.host_rd_pa;
	buffer_unmap(mpt);
	// Might be better to keep the mpt locked before finalizing everything
	granule_unlock(g_mpt);
	INFO("test \n");
	buffer_unmap(rd);
        granule_unlock(rec->realm_info.g_rd);

	g_host_rd = find_lock_granule(host_rd_pa, GRANULE_STATE_RD);
        if (g_host_rd == NULL) {
              //  res->x[0] = RMI_ERROR_INPUT;
        	return;
        }

        host_rd = granule_map(g_host_rd, SLOT_RD);
        assert(host_rd != NULL);
        mpt_pa_host = host_rd->mpt_pa;
	INFO("test \n");
        g_mpt_host = find_lock_granule(mpt_pa_host, GRANULE_STATE_MPT);
        mpt_host = granule_map(g_mpt_host, SLOT_MPT);
        assert(mpt_host != NULL);
	 INFO("test3 \n");
	// 2- Check whether the cuurent realm is allowed to map that address into its address space

	addr = granule_addr(rec->realm_info.g_rd);
        INFO("addr = %lx \n", addr);
	INFO("mpt_host->host_memory.guest_rd_pa = %lx \n", mpt_host->host_memory.guest_rd_pa);
	if (mpt_host->host_memory.guest_rd_pa != addr){
		//res->x[0] = RMI_ERROR_INPUT;
		return;
	}
	INFO("test2131 \n");
	INFO(" mpt_host->host_memory.ipa = %lx \n", mpt_host->host_memory.ipa);
	// 3- Find physical address of that ipa, needs to unlock the last level page at the end
	walk_status = realm_ipa_to_pa_with_rd(host_rd, mpt_host->host_memory.ipa, &walk_res);
	INFO(" walk_status = %d \n", walk_status);
	struct granule *g_test = find_granule(walk_res.pa);
	struct my_shared_data *my_shared_data = (struct my_shared_data *)granule_map(g_test, SLOT_RSI_CALL);
	INFO("my_shared_data->field3 = %lx \n", my_shared_data->field3);
	buffer_unmap(my_shared_data);

	buffer_unmap(host_rd);
	granule_unlock(g_host_rd);
	INFO("tes4 \n");
	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
        rd = granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(rd != NULL);
 	INFO("test5 \n");
	// 4- Mapping the target walk_res.pa to the ipa, do we need to lock the pa during the mapping?
	map_ipa_to_pa(rd, walk_res.pa, ipa);
	INFO("test6 \n");
	granule_unlock(walk_res.llt);
	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);
	buffer_unmap(mpt_host);
        granule_unlock(g_mpt_host);
	 INFO("test343 \n");
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
        res->smc_res.x[1] = walk_res.pa;
	res->smc_res.x[2] = ipa;
}





















