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
#include <apt.h>
#include <debug.h>

void handle_rsi_shared_memory_set(struct rec *rec,
			      struct rmi_rec_exit *rec_exit,
			      struct rsi_result *res)
{
	unsigned long flag = rec->regs[1];
	if (flag == 0)
		handle_rsi_shared_memory_set_master(rec, rec_exit, res);
	if (flag == 1)
		handle_rsi_shared_memory_set_slave(rec, rec_exit, res);
	if (flag == 2)
		handle_rsi_shared_memory_set_mapping(rec, rec_exit, res);
}


void handle_rsi_shared_memory_set_master(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	unsigned long base_ipa = rec->regs[1];
        unsigned long dest_rd_pa = rec->regs[3];
        struct rd *rd;
	unsigned long apt_pa;
	struct granule *g_apt;
        struct apt *apt;
	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
        rd = granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(rd != NULL);
        apt_pa = rd->apt_pa;

        g_mpt = find_lock_granule(mpt_pa, GRANULE_STATE_MPT);
        mpt = granule_map(g_mpt, SLOT_MPT);
        assert(mpt != NULL);
	mpt->host_memory.guest_rd_pa = dest_rd_pa;
        mpt->host_memory.ipa = base_ipa;

	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);
        buffer_unmap(apt);
        granule_unlock(g_apt);
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = dest_rd_pa;
	res->smc_res.x[2] = base_ipa;
	res->smc_res.x[3] = size_ipa;
}


void handle_rsi_shared_memory_set_slave(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	unsigned long base_ipa = rec->regs[2];
	unsigned long size_ipa = rec->regs[3];
	unsigned long master_rd_pa = rec->regs[4];
        struct rd *rd;
        unsigned long apt_pa;
        struct granule *g_apt;
        struct apt *apt;


        granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
        rd = granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(rd != NULL);
        apt_pa = rd->apt_pa;

        g_mpt = find_lock_granule(mpt_pa, GRANULE_STATE_MPT);
        mpt = granule_map(g_mpt, SLOT_MPT);
        assert(mpt != NULL);
        mpt->guest_memory.host_rd_pa = dest_rd_pa;
        mpt->guest_memory.ipa = base_ipa;

	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);
        buffer_unmap(mpt);
        granule_unlock(g_mpt);
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = dest_rd_pa;
	res->smc_res.x[2] = base_ipa;
}


void handle_rsi_shared_memory_set_mapping(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	struct rd *rd, *dest_rd;
	struct granule *g_dest_rd;
        unsigned long mpt_pa, mpt_pa_host;
        struct s2_walk_result walk_res;
        unsigned long ipa, host_rd_pa;
	struct granule *g_mpt;
        struct mpt *mpt;
	unsigned long addr;
 	enum s2_walk_status walk_status;
        granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
        slave_rd = granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(slave_rd != NULL);
        apt_pa = slave_rd->apt_pa;

        g_apt_slave = find_lock_granule(apt_pa, GRANULE_STATE_APT);
        apt_slave = granule_map(g_apt_slave, SLOT_APT);
        assert(apt_slave != NULL);
        slave_ipa_start = apt_slave->slave_memory.ipa_start;
	slave_ipa_size = apt_slave->slave_memory.map_size;
	master_rd_pa = apt_slave->slave_memory.master_rd_pa;

	g_dest_rd = find_lock_granule(host_rd_pa, GRANULE_STATE_RD);
        if (g_dest_rd == NULL) {
              //  res->x[0] = RMI_ERROR_INPUT;
        	return;
        }

        dest_rd = granule_map(g_dest_rd, SLOT_RD);
        assert(dest_rd != NULL);
        mpt_pa_host = dest_rd->mpt_pa;
	INFO("test \n");
        g_mpt = find_lock_granule(mpt_pa_host, GRANULE_STATE_MPT);
        mpt = granule_map(g_mpt, SLOT_MPT);
        assert(mpt != NULL);
	 INFO("test3 \n");
	// 2- Check whether the cuurent realm is allowed to map that address into its address space

	addr = granule_addr(rec->realm_info.g_rd);
        INFO("addr = %lx \n", addr);
	INFO("mpt->host_memory.guest_rd_pa = %lx \n", mpt->host_memory.guest_rd_pa);
	if (mpt->host_memory.guest_rd_pa != addr){
		//res->x[0] = RMI_ERROR_INPUT;
		return;
	}
	INFO("test2131 \n");
	INFO(" mpt->host_memory.ipa = %lx \n", mpt->host_memory.ipa);
	// 3- Find physical address of that ipa, needs to unlock the last level page at the end
	walk_status = realm_ipa_to_pa_with_rd(dest_rd, mpt->host_memory.ipa, &walk_res);
	INFO(" walk_status = %d \n", walk_status);
	buffer_unmap(dest_rd);
	granule_unlock(g_dest_rd);
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
	buffer_unmap(mpt);
        granule_unlock(g_mpt);
	 INFO("test343 \n");
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
}


















