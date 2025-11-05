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
#include <realm_tag.h>

#define OWNER_TAG_MASK_U64  0xFFull
#define OWNER_TAG_DECODE(x) ((uint8_t)((x) & OWNER_TAG_MASK_U64))
#define SLAVE_FLAG              1UL
#define READ_ONLY                   2UL
#define ALIGN_4KB (4UL * 1024)

void handle_rsi_shared_memory_set(struct rec *rec,
			      struct rmi_rec_exit *rec_exit,
			      struct rsi_result *res)
{
	unsigned long flag = rec->regs[1];
	if (flag && SLAVE_FLAG)
		handle_rsi_shared_memory_set_slave(rec, rec_exit, res);
	else
		handle_rsi_shared_memory_set_master(rec, rec_exit, res);
}


void handle_rsi_shared_memory_set_master(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	unsigned long base_ipa = rec->regs[2];
    unsigned long size_ipa = rec->regs[3];
	uint8_t slave_id = OWNER_TAG_DECODE(rec->regs[4]);
	unsigned long slave_rd_pa = 0;
	INFO("slave_id = %x \n", slave_id);
    struct rd *rd;
	unsigned long apt_pa;
	struct granule *g_apt;
    struct apt *apt;

	if (size_ipa == 0 || !GRANULE_ALIGNED(base_ipa) || !GRANULE_ALIGNED(size_ipa)) {
            res->smc_res.x[0] = RSI_ERROR_INPUT;
            INFO("Illegal shared memory region \n");
            return;
    }
	
	if (!(realm_tag_rd_by_tag(slave_id, &slave_rd_pa))) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("Invalid slave rd tag \n");
		//return;
	}
    INFO("this is slave rd %lx \n", slave_rd_pa);
	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
    rd =  buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
    assert(rd != NULL);
    apt_pa = rd->apt_pa;

    g_apt = find_lock_granule(apt_pa, GRANULE_STATE_APT);
    apt = buffer_granule_map(g_apt, SLOT_APT);
    assert(apt != NULL);

	int region_index = 0;
    
	INFO("Setting slave region with base ipa = 0x%lx size = 0x%lx \n", base_ipa, size_ipa);
	apt->master_memory[region_index].slave_rd_pa = slave_rd_pa;
	apt->master_memory[region_index].region_ID = 0; //dummy for now
	apt->master_memory[region_index].flags = 0; //dummy for now
	apt->master_memory[region_index].slave_ID = slave_id;
	apt->master_memory[region_index].ipa_start = base_ipa;
	apt->master_memory[region_index].map_size = size_ipa;

	rec_exit->exit_reason = RMI_EXIT_CSM_ADD_GRANULES;
	rec_exit->ripas_base = base_ipa;
	rec_exit->ripas_top = base_ipa + size_ipa;
 	res->action = UPDATE_REC_EXIT_TO_HOST;
//	res->action = UPDATE_REC_RETURN_TO_REALM;
    res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = slave_rd_pa;
	res->smc_res.x[2] = base_ipa;
 	res->smc_res.x[3] = base_ipa + size_ipa;

//unmap:
    buffer_unmap(apt);
    granule_unlock(g_apt);
	buffer_unmap(rd);
    granule_unlock(rec->realm_info.g_rd);
}

void handle_rsi_shared_memory_set_slave(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	unsigned long base_ipa = rec->regs[2];
	unsigned long size_ipa = rec->regs[3];
	uint8_t master_id = OWNER_TAG_DECODE(rec->regs[4]);
	INFO("master_id = %x \n", master_id);
    struct rd *rd, *master_rd;
    unsigned long apt_pa;
	unsigned long master_rd_pa = 0;
	struct granule *g_apt_slave, *g_apt_master, *g_master_rd;
    struct apt *apt_slave, *apt_master;
	int master_region_index = -1;
	int slave_region_index;
	unsigned long slave_rd_pa = granule_addr(rec->realm_info.g_rd);

	if (size_ipa == 0 || !GRANULE_ALIGNED(base_ipa) || !GRANULE_ALIGNED(size_ipa)) {
            res->smc_res.x[0] = RSI_ERROR_INPUT;
            INFO("Illegal shared memory region \n");
            return;
    }

	if (!(realm_tag_rd_by_tag(master_id, &master_rd_pa))) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("Invalid master rd tag \n");
		return;
	}
		
	INFO("this is master rd  %lx \n", master_rd_pa);
    granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
    rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
    assert(rd != NULL);
    apt_pa = rd->apt_pa;

    g_apt_slave = find_lock_granule(apt_pa, GRANULE_STATE_APT);
    apt_slave = buffer_granule_map(g_apt_slave, SLOT_APT);
    assert(apt_slave != NULL);


	g_master_rd = find_lock_granule(master_rd_pa, GRANULE_STATE_RD);
 	assert(g_master_rd != NULL);

	master_rd = buffer_granule_map(g_master_rd, SLOT_RD2);
    assert(master_rd != NULL);

	g_apt_master = find_lock_granule(master_rd->apt_pa, GRANULE_STATE_APT);
    apt_master = buffer_granule_map(g_apt_master, SLOT_APT2);
	assert(apt_master != NULL);

	
	// 2- Finding the matching region in the master realm
	// We assume that only one region is mapped between the two realms at a time for simplicity
	// If more regions are needed, we can loop through all regions to find the matching one or 
	// ask the caller to provide it
	for (int i = 0; i < MAX_MEM_REGIONS; i++) {
		if (apt_master->master_memory[i].slave_rd_pa != slave_rd_pa) 
			continue;
		master_region_index = i;
		INFO(" Found matching region index = %d \n", master_region_index);
		break;
	}
	if (master_region_index != -1){
		INFO(" Matching region found in master realm with base ipa = 0x%lx size = 0x%lx \n",
			 apt_master->master_memory[master_region_index].ipa_start,
			 apt_master->master_memory[master_region_index].map_size);  
	
	} else {
		INFO("No matching region found in master realm rd = %lx \n", master_rd_pa);
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		goto unmap;	
	}	

	if (apt_master->master_memory[0].map_size != size_ipa){
            res->smc_res.x[0] = RSI_ERROR_INPUT;
            INFO("Mismatching with IPA master_ipa_size =0x%lx and slave_ipa_size=0x%lx \n",apt_master->master_memory[0].map_size, size_ipa);
            goto unmap;			
    }
	slave_region_index = 0; // we assume only one region for now
    apt_slave->slave_memory[slave_region_index].master_rd_pa = master_rd_pa;
	apt_slave->slave_memory[slave_region_index].ipa_start = base_ipa;
	apt_slave->slave_memory[slave_region_index].map_size = size_ipa;
	apt_slave->slave_memory[slave_region_index].master_ID = master_id;
	apt_slave->slave_memory[slave_region_index].flags = 0; //dummy for now
	apt_slave->slave_memory[slave_region_index].region_ID = 0; //dummy for now

	INFO(" Setting slave region with base ipa = 0x%lx size = 0x%lx \n", base_ipa, size_ipa);
	
	rec_exit->exit_reason = RMI_EXIT_CSM_REMOVE_GRANULES;
	rec_exit->ripas_base = base_ipa;
	rec_exit->ripas_top = base_ipa + size_ipa;
 	res->action = UPDATE_REC_EXIT_TO_HOST;
    res->smc_res.x[0] = RSI_SUCCESS;
    res->smc_res.x[1] = master_rd_pa;
    res->smc_res.x[2] = base_ipa;
 	res->smc_res.x[3] = base_ipa + size_ipa;
unmap:
	buffer_unmap(apt_slave);
	granule_unlock(g_apt_slave);
	buffer_unmap(apt_master);
	granule_unlock(g_apt_master);
	buffer_unmap(rd);   
	granule_unlock(rec->realm_info.g_rd);
	buffer_unmap(master_rd);
	granule_unlock(g_master_rd);	 
}


void handle_rsi_shared_memory_set_mapping(struct rec *rec,
                                          struct rmi_rec_exit *rec_exit,
                                          struct rsi_result *res)
{
    INFO("handle_rsi_shared_memory_set_mapping called\n");

    int region_index = rec->regs[1];

    struct rd *slave_rd = NULL, *master_rd = NULL;
    struct granule *g_master_rd = NULL;
    struct granule *g_apt_slave = NULL, *g_apt_master = NULL;
    struct apt *apt_slave = NULL, *apt_master = NULL;

    unsigned long apt_pa, apt_pa_master;
    unsigned long master_rd_pa;

    unsigned long slave_ipa_start;
    unsigned long master_ipa_start, master_ipa_size;

    struct s2_walk_result walk_res = {0};
    enum s2_walk_status walk_status;

    /* 1) Find the target RD and APT for the slave realm */
    granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
    slave_rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
    assert(slave_rd != NULL);

    apt_pa = slave_rd->apt_pa;
    g_apt_slave = find_lock_granule(apt_pa, GRANULE_STATE_APT);
    apt_slave = buffer_granule_map(g_apt_slave, SLOT_APT);
    assert(apt_slave != NULL);

    /* Read slave region info */
    slave_ipa_start = apt_slave->slave_memory[region_index].ipa_start;
    master_rd_pa    = apt_slave->slave_memory[region_index].master_rd_pa;

    /* Lock and map the master RD */
    g_master_rd = find_lock_granule(master_rd_pa, GRANULE_STATE_RD);
    if (g_master_rd == NULL) {
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        goto out;
    }

    master_rd = buffer_granule_map(g_master_rd, SLOT_RD2);
    assert(master_rd != NULL);

    /* Map master's APT */
    apt_pa_master = master_rd->apt_pa;
    g_apt_master  = find_lock_granule(apt_pa_master, GRANULE_STATE_APT);
    apt_master    = buffer_granule_map(g_apt_master, SLOT_APT2);
    assert(apt_master != NULL);

    /* Read master region info (previously uninitialized locals) */
    master_ipa_start = apt_master->master_memory[region_index].ipa_start;
    master_ipa_size  = apt_master->master_memory[region_index].map_size;
    INFO("Mapping master IPA range [%lx - %lx) into slave @ %lx...\n",
         master_ipa_start, master_ipa_start + master_ipa_size, slave_ipa_start);

    /* 2) Walk master IPA range, map PAs into slave page tables */
    {
        unsigned long slave_ipa = slave_ipa_start;

        for (unsigned long master_ipa = master_ipa_start;
             master_ipa < master_ipa_start + master_ipa_size;
             master_ipa += 0x1000, slave_ipa += 0x1000)
        {
            walk_status = realm_ipa_to_pa_with_rd(master_rd, master_ipa, &walk_res);
          //  INFO("walk_status=%d master_ipa=%lx pa=%lx\n",
            //     walk_status, master_ipa, walk_res.pa);

            if (walk_status != WALK_SUCCESS) {
                INFO("Page table walk failed for master_ipa=%lx\n", master_ipa);
                res->smc_res.x[0] = RSI_ERROR_INPUT;
                if (walk_res.llt)
                    granule_unlock(walk_res.llt);
                goto out;
            }

            /* Map the resolved PA into the slave realm at slave_ipa */
            map_ipa_to_pa(slave_rd, walk_res.pa, slave_ipa);
           // INFO("Mapped slave_ipa=%lx -> pa=%lx\n", slave_ipa, walk_res.pa);

            if (walk_res.llt)
                granule_unlock(walk_res.llt);
        }
    }

    /* Success */
    res->action = UPDATE_REC_RETURN_TO_REALM;
    res->smc_res.x[0] = RSI_SUCCESS;

out:
    if (apt_slave)    
		buffer_unmap(apt_slave);
    if (g_apt_slave)  
		granule_unlock(g_apt_slave);

    if (apt_master)   
		buffer_unmap(apt_master);
    if (g_apt_master) 
		granule_unlock(g_apt_master);

    if (slave_rd)     
		buffer_unmap(slave_rd);
    /* We locked rec->realm_info.g_rd at the start */
    	granule_unlock(rec->realm_info.g_rd);

    if (master_rd)    
		buffer_unmap(master_rd);
    if (g_master_rd)  
		granule_unlock(g_master_rd);
}


void handle_rsi_shared_memory_set_unmapping(struct rec *rec,
                              struct rmi_rec_exit *rec_exit,
                              struct rsi_result *res)
{
	//unsigned long block_mapping = rec->regs[3];
	int region_index = 0;
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
    slave_ipa_start = apt_slave->slave_memory[region_index].ipa_start;
	slave_ipa_size = apt_slave->slave_memory[region_index].map_size;
	master_rd_pa = apt_slave->slave_memory[region_index].master_rd_pa;
    INFO("test 5 \n");
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
	master_ipa_start = apt_master->master_memory[region_index].ipa_start;
    master_ipa_size = apt_master->master_memory[region_index].map_size;
    assert(apt_master != NULL);
	INFO("test3 \n");
	// 2- Check whether the cuurent realm is allowed to map that address into its address space

	addr = granule_addr(rec->realm_info.g_rd);
	if (apt_master->master_memory[region_index].slave_rd_pa != addr){
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("Mismatching with RD addresses \n");
		return;
	}
	// 3- Checking size compatibility
	if (master_ipa_size != slave_ipa_size){
              //  res->smc_res.x[0] = RSI_ERROR_INPUT;
        INFO("Mismatching with IPA master_ipa_size =0x%lx and slave_ipa_size=0x%lx \n", master_ipa_size, slave_ipa_size);
        return;
        }
	INFO(" apt_master->master_memory[region_index].ipa_start = %lx \n", apt_master->master_memory[region_index].ipa_start);
		// 4- Loop Through IPA range and find the associated PA, then map them in the second realm's page tables. needs to unlock the last level page at the end
	unsigned long slave_ipa = slave_ipa_start;
	for (unsigned long master_ipa = master_ipa_start; master_ipa < master_ipa_start + master_ipa_size; master_ipa += 0x1000) {
		walk_status = realm_ipa_to_pa_with_rd(master_rd, master_ipa, &walk_res);
		if (walk_status != WALK_SUCCESS) {
			INFO("Page table walk failed for master_ipa=%lx\n", master_ipa);
			res->smc_res.x[0] = RSI_ERROR_INPUT;
			if (walk_res.llt)
				granule_unlock(walk_res.llt);
			return;
		}
		// 5- Mapping the target walk_res.pa to the ipa, do we need to lock the pa during the mapping?
		// Check for read-only feature of map_ipa_to_pa later
		map_ipa_to_pa(slave_rd, walk_res.pa, slave_ipa);
		//INFO("mapped slave_ipa = %lx to phys_addr = %lx \n", slave_ipa, walk_res.pa);
		slave_ipa += 0x1000;
		granule_unlock(walk_res.llt);
	}
	//} 
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










