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
#include <buffer.h>

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
	unsigned long base_ipa = rec->regs[2];
        unsigned long size_ipa = rec->regs[3];
	unsigned long slave_rd_pa = rec->regs[4];

        struct rd *rd;
	unsigned long apt_pa;
	struct granule *g_apt;
        struct apt *apt;
	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
        rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(rd != NULL);
        apt_pa = rd->apt_pa;

        g_apt = find_lock_granule(apt_pa, GRANULE_STATE_APT);
        apt = buffer_granule_map(g_apt, SLOT_APT);
        assert(apt != NULL);
	/* check the range specified by the user at runtime to
	be in the designated range during boot time */
	if (apt->csdata_ipa_begin > base_ipa || apt->csdata_ipa_end < size_ipa) {
		INFO("Out of range use of confidential shared memory \n");
		INFO("apt->csdata_ipa_begin = %lx apt->csdata_ipa_end = %lx \n", apt->csdata_ipa_begin, apt->csdata_ipa_end);
//		res->smc_res.x[0] = RSI_ERROR_INPUT;
//		goto unmap;
	}
	apt->master_memory.slave_rd_pa = slave_rd_pa;
        apt->master_memory.ipa_start = base_ipa;
	apt->master_memory.map_size = size_ipa;
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = slave_rd_pa;
	res->smc_res.x[2] = base_ipa;
	res->smc_res.x[3] = size_ipa;
	goto unmap;
unmap:
	buffer_unmap(rd);
        granule_unlock(rec->realm_info.g_rd);
        buffer_unmap(apt);
        granule_unlock(g_apt);
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
        rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(rd != NULL);
        apt_pa = rd->apt_pa;

        g_apt = find_lock_granule(apt_pa, GRANULE_STATE_APT);
        apt = buffer_granule_map(g_apt, SLOT_APT);
        assert(apt != NULL);
        apt->slave_memory.master_rd_pa = master_rd_pa;
        apt->slave_memory.ipa_start = base_ipa;
	apt->slave_memory.map_size = size_ipa;

	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);
        buffer_unmap(apt);
        granule_unlock(g_apt);
 	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
        res->smc_res.x[1] = master_rd_pa;
        res->smc_res.x[2] = base_ipa;
 	res->smc_res.x[3] = size_ipa;

}


void handle_rsi_shared_memory_set_mapping(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	unsigned long block_mapping = rec->regs[3];
	struct rd *slave_rd, *master_rd;
	struct granule *g_master_rd;
        unsigned long apt_pa, apt_pa_master;
        struct s2_walk_result walk_res;
        unsigned long master_ipa_start, master_ipa_size, master_rd_pa;
	unsigned long slave_ipa_start, slave_ipa_size;
	struct granule *g_apt_slave, *g_apt_master;
        struct apt *apt_slave, *apt_master;
	unsigned long addr;
 	enum s2_walk_status walk_status;

	// 1- Finding the target rd and then apt
        granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
        slave_rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
        assert(slave_rd != NULL);
        apt_pa = slave_rd->apt_pa;

        g_apt_slave = find_lock_granule(apt_pa, GRANULE_STATE_APT);
        apt_slave = buffer_granule_map(g_apt_slave, SLOT_APT);
        assert(apt_slave != NULL);
        slave_ipa_start = apt_slave->slave_memory.ipa_start;
	slave_ipa_size = apt_slave->slave_memory.map_size;
	master_rd_pa = apt_slave->slave_memory.master_rd_pa;

	g_master_rd = find_lock_granule(master_rd_pa, GRANULE_STATE_RD);
        if (g_master_rd == NULL) {
                res->smc_res.x[0] = RSI_ERROR_INPUT;
        	return;
        }

        master_rd = buffer_granule_map(g_master_rd, SLOT_RD2);
        assert(master_rd != NULL);
        apt_pa_master = master_rd->apt_pa;
	INFO("test \n");
        g_apt_master = find_lock_granule(apt_pa_master, GRANULE_STATE_APT);
        apt_master = buffer_granule_map(g_apt_master, SLOT_APT2);
	master_ipa_start = apt_master->master_memory.ipa_start;
        master_ipa_size = apt_master->master_memory.map_size;
        assert(apt_master != NULL);
	INFO("test3 \n");
	// 2- Check whether the cuurent realm is allowed to map that address into its address space

	addr = granule_addr(rec->realm_info.g_rd);
	if (apt_master->master_memory.slave_rd_pa != addr){
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("Mismatching with RD addresses \n");
		return;
	}
	// 3- Checking size compatibility
	if (master_ipa_size != slave_ipa_size){
                res->smc_res.x[0] = RSI_ERROR_INPUT;
                INFO("Mismatching with IPA master_ipa_size =0x%lx and slave_ipa_size=0x%lx \n", master_ipa_size, slave_ipa_size);
                return;
        }
	INFO(" block_mapping = 0x%lx \n", block_mapping);
	if (block_mapping == 0x0){
		INFO(" apt_master->master_memory.ipa_start = %lx \n", apt_master->master_memory.ipa_start);
		// 4- Loop Through IPA range and find the associated PA, then map them in the second realm's page tables. needs to unlock the last level page at the end
		unsigned long slave_ipa = slave_ipa_start;
		for (unsigned long master_ipa = master_ipa_start; master_ipa < master_ipa_start + master_ipa_size; master_ipa += 0x1000) {
			walk_status = realm_ipa_to_pa_with_rd(master_rd, master_ipa, &walk_res);
			INFO("walk_status = %d for master_ipa = %lx and phys_addr = %lx \n", walk_status, master_ipa, walk_res.pa);

		// 5- Mapping the target walk_res.pa to the ipa, do we need to lock the pa during the mapping?
		// Check for read-only feature of map_ipa_to_pa later
			map_ipa_to_pa(slave_rd, walk_res.pa, slave_ipa);
			INFO("mapped slave_ipa = %lx to phys_addr = %lx \n", slave_ipa, walk_res.pa);
			slave_ipa += 0x1000;
			granule_unlock(walk_res.llt);
		}
	} else if (block_mapping == 0x1){
	INFO(" block mapping  is enabled \n");
		unsigned long slave_ipa = slave_ipa_start;
		for (unsigned long master_ipa = master_ipa_start; master_ipa < master_ipa_start + master_ipa_size; master_ipa += 0x200000){
			copy_page_table(master_rd, slave_rd, master_ipa, slave_ipa);
			slave_ipa += 0x200000;
		}
	}
	buffer_unmap(apt_slave);
	granule_unlock(g_apt_slave);
	buffer_unmap(apt_master);
	granule_unlock(g_apt_master);
	buffer_unmap(slave_rd);
	granule_unlock(rec->realm_info.g_rd);
	buffer_unmap(master_rd);
	granule_unlock(g_master_rd);
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
}













