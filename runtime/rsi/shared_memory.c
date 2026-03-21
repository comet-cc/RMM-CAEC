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
#include <spinlock.h>

#define OWNER_TAG_MASK_U64  0xFFull
#define OWNER_TAG_DECODE(x) ((uint8_t)((x) & OWNER_TAG_MASK_U64))
#define SLAVE_FLAG              1UL
#define READ_ONLY                   2UL
#define ALIGN_4KB (4UL * 1024)
#define CONFIG_MAX_CSM_REGION_IDS 64

struct csm_region_id_entry {
	uint64_t owner_rd_pa;
	uint8_t region_id;
	bool in_use;
};

static struct csm_region_id_entry g_csm_region_ids[CONFIG_MAX_CSM_REGION_IDS];
static spinlock_t g_csm_region_id_lock;
static uint8_t g_csm_region_id_counter = 1U;

static int csm_region_id_find_free_slot(void)
{
	for (int i = 0; i < CONFIG_MAX_CSM_REGION_IDS; ++i) {
		if (!g_csm_region_ids[i].in_use) {
			return i;
		}
	}

	return -1;
}

static bool csm_region_id_collides(uint8_t region_id)
{
	for (int i = 0; i < CONFIG_MAX_CSM_REGION_IDS; ++i) {
		if (g_csm_region_ids[i].in_use &&
		    g_csm_region_ids[i].region_id == region_id) {
			return true;
		}
	}

	return false;
}

static bool csm_region_id_assign(uint64_t owner_rd_pa, uint8_t *out_region_id)
{
	bool ok = false;
	uint8_t candidate;
	int slot;
	int tries = 0;

	spinlock_acquire(&g_csm_region_id_lock);

	slot = csm_region_id_find_free_slot();
	if (slot < 0) {
		goto out_unlock;
	}

	do {
		candidate = g_csm_region_id_counter++;
		if (candidate == 0U) {
			candidate = g_csm_region_id_counter++;
		}
		tries++;
		if (tries > CONFIG_MAX_CSM_REGION_IDS) {
			goto out_unlock;
		}
	} while (csm_region_id_collides(candidate));

	g_csm_region_ids[slot].owner_rd_pa = owner_rd_pa;
	g_csm_region_ids[slot].region_id = candidate;
	g_csm_region_ids[slot].in_use = true;

	if (out_region_id != NULL) {
		*out_region_id = candidate;
	}
	ok = true;

out_unlock:
	spinlock_release(&g_csm_region_id_lock);
	return ok;
}

static bool csm_region_id_remove(uint8_t region_id)
{
	bool ok = false;

	spinlock_acquire(&g_csm_region_id_lock);

	for (int i = 0; i < CONFIG_MAX_CSM_REGION_IDS; ++i) {
		if (g_csm_region_ids[i].in_use &&
		    g_csm_region_ids[i].region_id == region_id) {
			g_csm_region_ids[i].owner_rd_pa = 0UL;
			g_csm_region_ids[i].region_id = 0U;
			g_csm_region_ids[i].in_use = false;
			ok = true;
			break;
		}
	}

	spinlock_release(&g_csm_region_id_lock);
	return ok;
}

void handle_rsi_csm_create(struct rec *rec,
			   struct rmi_rec_exit *rec_exit,
			   struct rsi_result *res)
{
	unsigned long base_ipa = rec->regs[2];
	unsigned long size_ipa = rec->regs[3];
	struct rd *rd;
	unsigned long apt_pa;
	struct granule *g_apt;
	struct apt *apt;
	int region_index = 0;
	uint8_t region_id = 0U;
	unsigned long owner_rd_pa = granule_addr(rec->realm_info.g_rd);

	if (size_ipa == 0 || !GRANULE_ALIGNED(base_ipa) || !GRANULE_ALIGNED(size_ipa)) {
            res->smc_res.x[0] = RSI_ERROR_INPUT;
            INFO("Illegal shared memory region \n");
            return;
    }

	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
	rd =  buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
	assert(rd != NULL);
	apt_pa = rd->apt_pa;

	g_apt = find_lock_granule(apt_pa, GRANULE_STATE_APT);
	apt = buffer_granule_map(g_apt, SLOT_APT);
	assert(apt != NULL);

	// - Make sure the specified region does not overlap with other master and slave regions
	enum apt_region_kind kind;
	size_t idx;
	bool conflict = apt_find_enabled_conflict(apt, base_ipa, size_ipa, &kind, &idx, true);
	if (conflict) {
		INFO("Address range %lx - %lx conflicts with %s region %lx - %lx\n",
			 base_ipa, size_ipa,
			 (kind == APT_REGION_MASTER) ? "master" : "slave",
			 (kind == APT_REGION_MASTER) ? apt->master_memory[idx].ipa_start : apt->slave_memory[idx].ipa_start,
			 (kind == APT_REGION_MASTER) ? apt->master_memory[idx].ipa_start + apt->master_memory[idx].map_size : apt->slave_memory[idx].ipa_start + apt->slave_memory[idx].map_size);
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		goto unmap;
	}

	if (!csm_region_id_assign(owner_rd_pa, &region_id)) {
		res->smc_res.x[0] = RSI_ERROR_STATE;
		INFO("Unable to assign region id \n");
		goto unmap;
	}

	region_index = apt_add_master(apt, region_id, base_ipa, size_ipa, 0, true);
	if (region_index == (int)SIZE_MAX) {
		(void)csm_region_id_remove(region_id);
		res->smc_res.x[0] = RSI_ERROR_STATE;
		INFO("Unable to allocate master region slot \n");
		goto unmap;
	}
	INFO("Created CSM region id = %x base ipa = 0x%lx size = 0x%lx region_index = %d\n",
	     region_id, base_ipa, size_ipa, region_index);

	rec_exit->exit_reason = RMI_EXIT_CSM_ADD_GRANULES;
	rec_exit->ripas_base = base_ipa;
	rec_exit->ripas_top = base_ipa + size_ipa;
 	res->action = UPDATE_REC_EXIT_TO_HOST;
    res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = region_id;
	res->smc_res.x[2] = region_index;
unmap:
	buffer_unmap(apt);
	granule_unlock(g_apt);
	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);
}

void handle_rsi_csm_share(struct rec *rec,
			  struct rmi_rec_exit *rec_exit,
			  struct rsi_result *res)
{
	uint8_t region_id = OWNER_TAG_DECODE(rec->regs[1]);
	uint8_t slave_id = OWNER_TAG_DECODE(rec->regs[2]);
	uint8_t permission = OWNER_TAG_DECODE(rec->regs[3]);
	unsigned long slave_rd_pa = 0UL;
	unsigned long owner_rd_pa = granule_addr(rec->realm_info.g_rd);
	unsigned long apt_pa;
	struct rd *rd;
	struct granule *g_apt;
	struct apt *apt;
	uint8_t master_id = 0U;
	int master_region_index;
	uint32_t sharing_id;

	(void)rec_exit;

	if (region_id == 0U || slave_id == 0U) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	if (!realm_tag_rd_by_tag(slave_id, &slave_rd_pa)) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("Invalid slave rd tag for share \n");
		return;
	}

	if (!realm_tag_get_by_rd(owner_rd_pa, &master_id)) {
		res->smc_res.x[0] = RSI_ERROR_STATE;
		INFO("Invalid master rd tag during share \n");
		return;
	}

	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
	rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
	assert(rd != NULL);
	apt_pa = rd->apt_pa;

	g_apt = find_lock_granule(apt_pa, GRANULE_STATE_APT);
	apt = buffer_granule_map(g_apt, SLOT_APT);
	assert(apt != NULL);

	master_region_index = apt_find_master_by_region_id(apt, region_id);
	if (master_region_index < 0) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("Master region id %x not found \n", region_id);
		goto unmap;
	}

	if (!apt_master_add_share(apt, (size_t)master_region_index,
					  slave_id, slave_rd_pa, permission)) {
		res->smc_res.x[0] = RSI_ERROR_STATE;
		INFO("Unable to add share entry to region id %x \n", region_id);
		goto unmap;
	}

	sharing_id = apt_make_sharing_id(region_id, master_id, slave_id);
	res->action = UPDATE_REC_RETURN_TO_REALM;
	res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = sharing_id;
	res->smc_res.x[2] = master_region_index;

unmap:
	buffer_unmap(apt);
	granule_unlock(g_apt);
	buffer_unmap(rd);
	granule_unlock(rec->realm_info.g_rd);
}

void handle_rsi_csm_reserve(struct rec *rec,
			    struct rmi_rec_exit *rec_exit,
			    struct rsi_result *res)
{
	uint32_t sharing_id = (uint32_t)rec->regs[1];
	unsigned long base_ipa = rec->regs[2];
	unsigned long size_ipa = rec->regs[3];
	uint8_t region_id = apt_sharing_region_id(sharing_id);
	uint8_t master_id = apt_sharing_master_id(sharing_id);
	uint8_t slave_id = apt_sharing_slave_id(sharing_id);
	INFO("master_id = %x \n", master_id);
    struct rd *rd, *master_rd;
    unsigned long apt_pa;
	unsigned long master_rd_pa = 0;
	struct granule *g_apt_slave, *g_apt_master, *g_master_rd;
    struct apt *apt_slave, *apt_master;
	int master_region_index = -1;
	int master_share_slot = -1;
	int slave_region_index;
	unsigned long slave_rd_pa = granule_addr(rec->realm_info.g_rd);
	uint8_t current_slave_id = 0U;

	if (size_ipa == 0 || !GRANULE_ALIGNED(base_ipa) || !GRANULE_ALIGNED(size_ipa)) {
            res->smc_res.x[0] = RSI_ERROR_INPUT;
            INFO("Illegal shared memory region \n");
            return;
    }

	if (sharing_id == 0U || region_id == 0U || master_id == 0U || slave_id == 0U) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("Invalid sharing identifier \n");
		return;
	}

	if (!realm_tag_get_by_rd(slave_rd_pa, &current_slave_id) || current_slave_id != slave_id) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("Sharing identifier slave id mismatch \n");
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
	master_region_index = apt_find_master_by_region_id(apt_master, region_id);
	if (master_region_index != -1){
		INFO(" Matching region found in master realm with base ipa = 0x%lx size = 0x%lx \n",
			 apt_master->master_memory[master_region_index].ipa_start,
			 apt_master->master_memory[master_region_index].map_size);  
	
	} else {
		INFO("No matching region found in master realm rd = %lx \n", master_rd_pa);
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		goto unmap;	
	}	

	master_share_slot = apt_find_master_share_slot(&apt_master->master_memory[master_region_index],
							    slave_id);
	if (master_share_slot < 0) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("No sharing entry found for slave id = %x \n", slave_id);
		goto unmap;
	}

	if (apt_master->master_memory[master_region_index].map_size != size_ipa){
            res->smc_res.x[0] = RSI_ERROR_INPUT;
            INFO("Mismatching with IPA master_ipa_size =0x%lx and slave_ipa_size=0x%lx \n",
		 apt_master->master_memory[master_region_index].map_size, size_ipa);
            goto unmap;			
    }
	// 3- Make sure the specified region does not overlap with other master and slave regions
	enum apt_region_kind kind;
	size_t idx;
	bool conflict = apt_find_enabled_conflict(apt_slave, base_ipa, size_ipa, &kind, &idx, false);
	if (conflict) {
		INFO("Address range %lx - %lx conflicts with %s region %lx - %lx\n",
			 base_ipa, size_ipa,
			 (kind == APT_REGION_MASTER) ? "master" : "slave",
			 (kind == APT_REGION_MASTER) ? apt_slave->master_memory[idx].ipa_start : apt_slave->slave_memory[idx].ipa_start,
			 (kind == APT_REGION_MASTER) ? apt_slave->master_memory[idx].ipa_start + apt_slave->master_memory[idx].map_size : apt_slave->slave_memory[idx].ipa_start + apt_slave->slave_memory[idx].map_size);
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		goto unmap;
	}
		
	// 4- Setting the slave region in the slave realm APT
	slave_region_index = apt_add_slave(apt_slave, master_id, region_id, master_rd_pa,
					 base_ipa, size_ipa,
					 apt_master->master_memory[master_region_index].shares[master_share_slot].permission,
					 true);
	INFO("Setting slave region with base ipa = 0x%lx size = 0x%lx region_index = %d\n", base_ipa, size_ipa, slave_region_index);

	rec_exit->exit_reason = RMI_EXIT_CSM_REMOVE_GRANULES;
	rec_exit->ripas_base = base_ipa;
    rec_exit->ripas_top = base_ipa + size_ipa;
 	res->action = UPDATE_REC_EXIT_TO_HOST;
    res->smc_res.x[0] = RSI_SUCCESS;
    res->smc_res.x[1] = sharing_id;
    res->smc_res.x[2] = slave_region_index;	
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


void handle_rsi_csm_attach(struct rec *rec,
                                          struct rmi_rec_exit *rec_exit,
                                          struct rsi_result *res)
{
    INFO("handle_rsi_csm_attach called\n");

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

    int master_region_index = apt_find_master_by_region_id(
        apt_master, apt_slave->slave_memory[region_index].region_ID);
    if (master_region_index < 0) {
        res->smc_res.x[0] = RSI_ERROR_INPUT;
        goto out;
    }

    /* Read master region info (previously uninitialized locals) */
    master_ipa_start = apt_master->master_memory[master_region_index].ipa_start;
    master_ipa_size  = apt_master->master_memory[master_region_index].map_size;
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


void handle_rsi_csm_map(struct rec *rec,
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
	int master_region_index = -1;
	uint8_t current_slave_id = 0U;
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
    assert(apt_master != NULL);

	master_region_index = apt_find_master_by_region_id(
		apt_master, apt_slave->slave_memory[region_index].region_ID);
	if (master_region_index < 0) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	master_ipa_start = apt_master->master_memory[master_region_index].ipa_start;
    master_ipa_size = apt_master->master_memory[master_region_index].map_size;
	INFO("test3 \n");
	// 2- Check whether the cuurent realm is allowed to map that address into its address space

	addr = granule_addr(rec->realm_info.g_rd);
	if (!realm_tag_get_by_rd(addr, &current_slave_id) ||
	    apt_find_master_share_slot(&apt_master->master_memory[master_region_index],
					       current_slave_id) < 0) {
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
	INFO(" apt_master->master_memory[master_region_index].ipa_start = %lx \n",
	     apt_master->master_memory[master_region_index].ipa_start);
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






