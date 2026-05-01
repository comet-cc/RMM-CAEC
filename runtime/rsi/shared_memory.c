/*
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <realm.h>
#include <ripas.h>
#include <rsi-handler.h>
#include <smc-rmi.h>
#include <smc-rsi.h>
#include <status.h>
#include <granule.h>
#include <apt.h>
#include <apt_helpers.h>
#include <csm_id.h>
#include <debug.h>
#include <buffer.h>
#include <realm_tag.h>
#include <string.h>

#define OWNER_TAG_MASK_U64  0xFFull
#define OWNER_TAG_DECODE(x) ((uint8_t)((x) & OWNER_TAG_MASK_U64))
#define SLAVE_FLAG              1UL
#define READ_ONLY                   2UL
#define ALIGN_4KB (4UL * 1024)
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

	res->action = UPDATE_REC_RETURN_TO_REALM;

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

	region_index = apt_add_master(apt, region_id, base_ipa, size_ipa, true);
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
	unsigned long apt_pa;
	struct rd *rd;
	struct granule *g_apt;
	struct apt *apt;
	uint8_t master_id = 0U;
	int master_region_index;
	uint32_t sharing_id;

	(void)rec_exit;

	res->action = UPDATE_REC_RETURN_TO_REALM;

	if (!realm_tag_get_by_rd(granule_addr(rec->realm_info.g_rd), &master_id) ||
	    master_id == 0U) {
		res->smc_res.x[0] = RSI_ERROR_STATE;
		INFO("csm_share: caller realm has no tag assigned\n");
		return;
	}

	if (region_id == 0U || slave_id == 0U) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	if (!realm_tag_rd_by_tag(slave_id, &slave_rd_pa)) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("Invalid slave rd tag for share \n");
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

	res->action = UPDATE_REC_RETURN_TO_REALM;

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

	
	// Finding the matching region in the master realm
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
		INFO("No sharing entry found for slave id in this region = %x \n", slave_id);
		goto unmap;
	}
	
	// Make sure the sharing entry matches the requested IPA and size
	if (apt_master->master_memory[master_region_index].map_size != size_ipa){
            res->smc_res.x[0] = RSI_ERROR_INPUT;
            INFO("Mismatching with IPA master_ipa_size =0x%lx and slave_ipa_size=0x%lx \n",
		 apt_master->master_memory[master_region_index].map_size, size_ipa);
            goto unmap;			
    }
	// Make sure the specified region does not overlap with other master and slave regions
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
		
	// Setting the slave region in the slave realm APT
	slave_region_index = apt_add_slave(apt_slave, master_id, region_id, master_rd_pa,
					 base_ipa, size_ipa,
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


void handle_rsi_csm_attach(struct rec *rec, struct rmi_rec_exit *rec_exit, struct rsi_result *res)
{
    INFO("handle_rsi_csm_attach called\n");

    res->action = UPDATE_REC_RETURN_TO_REALM;

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


/*
 * RSI_CSM_DETACH_AND_FREE (ID 0xe) — called by the C-realm (slave).
 *
 * Unmaps all pages in the reserved CSM region from the slave's stage-2 RTT
 * and removes the slave entry from the slave's APT.  The host is then
 * notified via RMI_EXIT_CSM_ADD_GRANULES so it can re-populate the master's
 * IPA range.
 *
 * Input:  x1 = sharing_id (region_id | master_id | slave_id)
 */
void handle_rsi_csm_detach_and_free(struct rec *rec,
				    struct rmi_rec_exit *rec_exit,
				    struct rsi_result *res)
{
	uint32_t sharing_id = (uint32_t)rec->regs[1];
	uint8_t  region_id  = apt_sharing_region_id(sharing_id);
	uint8_t  slave_id   = apt_sharing_slave_id(sharing_id);

	uint8_t  caller_id  = 0U;
	unsigned long slave_rd_pa = granule_addr(rec->realm_info.g_rd);

	struct rd  *slave_rd;
	struct granule *g_slave_apt;
	struct apt *slave_apt;
	unsigned long apt_pa;

	res->action = UPDATE_REC_RETURN_TO_REALM;

	if (sharing_id == 0U || region_id == 0U || slave_id == 0U) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	if (!realm_tag_get_by_rd(slave_rd_pa, &caller_id) || caller_id != slave_id) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("csm_detach_and_free: caller is not the slave\n");
		return;
	}

	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
	slave_rd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
	assert(slave_rd != NULL);
	apt_pa = slave_rd->apt_pa;

	g_slave_apt = find_lock_granule(apt_pa, GRANULE_STATE_APT);
	if (g_slave_apt == NULL) {
		res->smc_res.x[0] = RSI_ERROR_STATE;
		goto out_rd;
	}

	slave_apt = buffer_granule_map(g_slave_apt, SLOT_APT);
	assert(slave_apt != NULL);

	/* Find the slave's entry for this region. */
	unsigned long slave_ipa_start = 0, slave_map_size = 0;
	size_t found_idx = SIZE_MAX;

	for (size_t sj = 0; sj < MAX_MEM_REGIONS; sj++) {
		if ((slave_apt->slave_used_mask & BIT64(sj)) &&
		    slave_apt->slave_memory[sj].region_ID == region_id) {
			slave_ipa_start = slave_apt->slave_memory[sj].ipa_start;
			slave_map_size  = slave_apt->slave_memory[sj].map_size;
			found_idx = sj;
			break;
		}
	}

	if (found_idx == SIZE_MAX) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("csm_detach_and_free: region %u not found in slave APT\n", region_id);
		goto out_apt;
	}

	/* Remove from APT before unmapping so propagation can't re-add. */
	apt_disable_slave_idx(slave_apt, found_idx);
	slave_apt->slave_used_mask &= ~BIT64(found_idx);

	buffer_unmap(slave_apt);
	granule_unlock(g_slave_apt);
	g_slave_apt = NULL;

	/* Unmap each page from the slave's RTT. */
	for (unsigned long ipa = slave_ipa_start;
	     ipa < slave_ipa_start + slave_map_size;
	     ipa += GRANULE_SIZE) {
		unmap_ipa_from_rd(slave_rd, ipa);
	}

	/* Tell the host to re-populate the master's IPA range. */
	rec_exit->exit_reason = RMI_EXIT_CSM_ADD_GRANULES;
	rec_exit->ripas_base  = slave_ipa_start;
	rec_exit->ripas_top   = slave_ipa_start + slave_map_size;
	res->action           = UPDATE_REC_EXIT_TO_HOST;
	res->smc_res.x[0]     = RSI_SUCCESS;

	buffer_unmap(slave_rd);
	granule_unlock(rec->realm_info.g_rd);
	return;

out_apt:
	if (g_slave_apt) {
		buffer_unmap(slave_apt);
		granule_unlock(g_slave_apt);
	}
out_rd:
	buffer_unmap(slave_rd);
	granule_unlock(rec->realm_info.g_rd);
}

/*
 * RSI_CSM_REVOKE (ID 0xf) — called by the P-realm (master).
 *
 * Revokes a previously granted sharing: removes the slave share slot from the
 * master's APT, removes the slave's APT entry for this region, and forcibly
 * unmaps the slave's RTT pages for that region.
 *
 * Input:  x1 = sharing_id (region_id | master_id | slave_id)
 */
void handle_rsi_csm_revoke(struct rec *rec,
			   struct rmi_rec_exit *rec_exit,
			   struct rsi_result *res)
{
	uint32_t sharing_id = (uint32_t)rec->regs[1];
	uint8_t  region_id  = apt_sharing_region_id(sharing_id);
	uint8_t  master_id  = apt_sharing_master_id(sharing_id);
	uint8_t  slave_id   = apt_sharing_slave_id(sharing_id);

	uint8_t  caller_id  = 0U;
	unsigned long master_rd_pa = granule_addr(rec->realm_info.g_rd);

	struct rd  *mrd;
	struct granule *g_mapt;
	struct apt *mapt;
	unsigned long apt_pa;

	(void)rec_exit;

	res->action = UPDATE_REC_RETURN_TO_REALM;

	if (sharing_id == 0U || region_id == 0U || master_id == 0U || slave_id == 0U) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	if (!realm_tag_get_by_rd(master_rd_pa, &caller_id) || caller_id != master_id) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("csm_revoke: caller is not the master\n");
		return;
	}

	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
	mrd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
	assert(mrd != NULL);
	apt_pa = mrd->apt_pa;

	g_mapt = find_lock_granule(apt_pa, GRANULE_STATE_APT);
	if (g_mapt == NULL) {
		res->smc_res.x[0] = RSI_ERROR_STATE;
		goto out_rd;
	}

	mapt = buffer_granule_map(g_mapt, SLOT_APT);
	assert(mapt != NULL);

	int midx = apt_find_master_by_region_id(mapt, region_id);
	if (midx < 0) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("csm_revoke: region %u not found in master APT\n", region_id);
		goto out_mapt;
	}

	int share_slot = apt_find_master_share_slot(&mapt->master_memory[midx], slave_id);
	if (share_slot < 0) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("csm_revoke: slave %u not sharing region %u\n", slave_id, region_id);
		goto out_mapt;
	}

	unsigned long slave_rd_pa = mapt->master_memory[midx].shares[share_slot].slave_rd_pa;

	/* Remove share slot from master APT now (before touching slave). */
	mapt->master_memory[midx].shares[share_slot].in_use = false;
	mapt->master_memory[midx].share_count--;

	buffer_unmap(mapt);
	granule_unlock(g_mapt);
	g_mapt = NULL;
	buffer_unmap(mrd);
	granule_unlock(rec->realm_info.g_rd);

	/* Now clean up the slave: remove its APT entry and unmap its RTT. */
	struct granule *g_srd = find_lock_granule(slave_rd_pa, GRANULE_STATE_RD);
	if (g_srd == NULL)
		goto done;

	struct rd *srd = buffer_granule_map(g_srd, SLOT_RD);
	assert(srd != NULL);

	struct granule *g_sapt = find_lock_granule(srd->apt_pa, GRANULE_STATE_APT);
	if (g_sapt == NULL) {
		buffer_unmap(srd);
		granule_unlock(g_srd);
		goto done;
	}

	struct apt *sapt = buffer_granule_map(g_sapt, SLOT_APT);
	assert(sapt != NULL);

	unsigned long slave_ipa_start = 0, slave_map_size = 0;
	size_t found_idx = SIZE_MAX;

	for (size_t sj = 0; sj < MAX_MEM_REGIONS; sj++) {
		if ((sapt->slave_used_mask & BIT64(sj)) &&
		    sapt->slave_memory[sj].region_ID == region_id) {
			slave_ipa_start = sapt->slave_memory[sj].ipa_start;
			slave_map_size  = sapt->slave_memory[sj].map_size;
			found_idx = sj;
			break;
		}
	}

	if (found_idx != SIZE_MAX) {
		apt_disable_slave_idx(sapt, found_idx);
		sapt->slave_used_mask &= ~BIT64(found_idx);
	}

	buffer_unmap(sapt);
	granule_unlock(g_sapt);

	if (found_idx != SIZE_MAX) {
		for (unsigned long ipa = slave_ipa_start;
		     ipa < slave_ipa_start + slave_map_size;
		     ipa += GRANULE_SIZE) {
			unmap_ipa_from_rd(srd, ipa);
		}
	}

	buffer_unmap(srd);
	granule_unlock(g_srd);

done:
	res->action       = UPDATE_REC_RETURN_TO_REALM;
	res->smc_res.x[0] = RSI_SUCCESS;
	return;

out_mapt:
	if (g_mapt) {
		buffer_unmap(mapt);
		granule_unlock(g_mapt);
	}
out_rd:
	buffer_unmap(mrd);
	granule_unlock(rec->realm_info.g_rd);
}

/*
 * RSI_CSM_DESTROY (ID 0x10) — called by the P-realm (master).
 *
 * Destroys a CSM region identified by region_id.  The region must have no
 * active shares (share_count == 0); callers must RSI_CSM_REVOKE all slaves
 * first.  The host is notified via RMI_EXIT_CSM_REALM_REMOVE so it can
 * reclaim the granules from the master's IPA range.
 *
 * Input:  x1 = region_id (as returned by RSI_CSM_CREATE)
 */
void handle_rsi_csm_destroy(struct rec *rec,
			    struct rmi_rec_exit *rec_exit,
			    struct rsi_result *res)
{
	uint8_t region_id = (uint8_t)(rec->regs[1] & 0xFFU);

	struct rd  *mrd;
	struct granule *g_mapt;
	struct apt *mapt;
	unsigned long apt_pa;
	unsigned long master_rd_pa = granule_addr(rec->realm_info.g_rd);

	res->action = UPDATE_REC_RETURN_TO_REALM;

	if (region_id == 0U) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		return;
	}

	granule_lock(rec->realm_info.g_rd, GRANULE_STATE_RD);
	mrd = buffer_granule_map(rec->realm_info.g_rd, SLOT_RD);
	assert(mrd != NULL);
	apt_pa = mrd->apt_pa;

	g_mapt = find_lock_granule(apt_pa, GRANULE_STATE_APT);
	if (g_mapt == NULL) {
		res->smc_res.x[0] = RSI_ERROR_STATE;
		goto out_rd;
	}

	mapt = buffer_granule_map(g_mapt, SLOT_APT);
	assert(mapt != NULL);

	int midx = apt_find_master_by_region_id(mapt, region_id);
	if (midx < 0) {
		res->smc_res.x[0] = RSI_ERROR_INPUT;
		INFO("csm_destroy: region %u not found\n", region_id);
		goto out_mapt;
	}

	if (mapt->master_memory[midx].share_count != 0U) {
		res->smc_res.x[0] = RSI_ERROR_STATE;
		INFO("csm_destroy: region %u still has %u active shares\n",
		     region_id, mapt->master_memory[midx].share_count);
		goto out_mapt;
	}

	unsigned long ipa_start = mapt->master_memory[midx].ipa_start;
	unsigned long map_size  = mapt->master_memory[midx].map_size;

	/* Remove from APT. */
	apt_disable_master_idx(mapt, (size_t)midx);
	mapt->master_used_mask &= ~BIT64((size_t)midx);
	(void)memset(&mapt->master_memory[midx], 0, sizeof(struct master_mem));

	buffer_unmap(mapt);
	granule_unlock(g_mapt);
	buffer_unmap(mrd);
	granule_unlock(rec->realm_info.g_rd);

	/* Release the globally unique region ID. */
	(void)csm_region_id_remove(region_id);

	/* Tell the host to reclaim granules from master's IPA range. */
	rec_exit->exit_reason = RMI_EXIT_CSM_REALM_REMOVE;
	rec_exit->ripas_base  = ipa_start;
	rec_exit->ripas_top   = ipa_start + map_size;
	res->action           = UPDATE_REC_EXIT_TO_HOST;
	res->smc_res.x[0]     = RSI_SUCCESS;

	INFO("csm_destroy: destroyed region %u at IPA [%lx, %lx)\n",
	     region_id, ipa_start, ipa_start + map_size);
	return;

out_mapt:
	buffer_unmap(mapt);
	granule_unlock(g_mapt);
out_rd:
	buffer_unmap(mrd);
	granule_unlock(rec->realm_info.g_rd);
	(void)master_rd_pa;
}






