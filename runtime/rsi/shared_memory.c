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

void handle_rsi_shared_memory_set(struct rec *rec,
			      struct rmi_rec_exit *rec_exit,
			      struct rsi_result *res)
{
	unsigned long base_ipa;
	unsigned long flag = rec->regs[2];
	unsigned long dest_rd_pa;
	unsigned long dest_base_ipa;
	enum s2_walk_status walk_status;
	struct s2_walk_result walk_res;
        struct granule *g_dest_table_root;
        struct granule *g_dest_rd;
        struct rd *dest_rd;
        struct rtt_walk wi;
        unsigned long *s2tt, s2tte;
        unsigned long ipa_bits;
	unsigned long  target_pa;
//        long level = (long)level;
        int sl;

	if (flag == 0) {
	base_ipa = rec->regs[1];
        //dest_rd_pa = rec->regs[3];
        //dest_base_ipa = rec->regs[4];
	if (!GRANULE_ALIGNED(base_ipa) || !addr_in_rec_par(rec, base_ipa)) {
                res->smc_res.x[0] = RSI_ERROR_INPUT;
                return;
        }
	/* If returns success, the last level should be unlocked later as the function automatically lock it.
	*/

        walk_status = realm_ipa_to_pa(rec, base_ipa, &walk_res);

        if (walk_status == WALK_FAIL) {
               // if (walk_res.ripas_val == RIPAS_EMPTY) {
                //        res->smc_res.x[0] = RSI_ERROR_INPUT;
                //} else {
                  //      res->action = STAGE_2_TRANSLATION_FAULT;
                    //    res->rtt_level = walk_res.rtt_level;
                //}
                return;
        }

        if (walk_status == WALK_INVALID_PARAMS) {
                res->smc_res.x[0] = RSI_ERROR_INPUT;
                return;
        }
	granule_unlock(walk_res.llt);
	res->action = UPDATE_REC_RETURN_TO_REALM;
        res->smc_res.x[0] = RSI_SUCCESS;
	res->smc_res.x[1] = walk_res.pa;
	}

//	target_pa = walk_res.pa;
	if (flag != 0) {
	target_pa = rec->regs[4];
	dest_base_ipa = rec->regs[1];
	dest_rd_pa = rec->regs[3];
	/* so far walk_res.pa keeps the physical address of target ipa in the master realm

	// we need to find the rtt of slave realm and map this physical address to its rtt structure at
	 the appropriate ipa specified by its metadata
	*/

	// cosider we have dest_base_ipa somehow:

	//dest_walk_status = realm_ipa_to_pa(dest_rec, dest_base_ipa, &dest_walk_res);

	g_dest_rd = find_lock_granule(dest_rd_pa, GRANULE_STATE_RD);

        if (g_dest_rd == NULL) {
//                res->x[0] = RMI_ERROR_INPUT;
                return;
        }

        dest_rd = granule_map(g_dest_rd, SLOT_RD);
        assert(dest_rd != NULL);

//        if (!GRANULE_ALIGNED(dest_base_ipa) || !addr_in_rec_par(dest_rec, dest_base_ipa)) {
                //return WALK_INVALID_PARAMS;
  //      }

        sl = realm_rtt_starting_level(dest_rd);
        ipa_bits = realm_ipa_bits(dest_rd);
	g_dest_table_root = dest_rd->s2_ctx.g_rtt;
        granule_lock(g_dest_table_root, GRANULE_STATE_RTT);
	buffer_unmap(dest_rd);
	granule_unlock(g_dest_rd);
        rtt_walk_lock_unlock(g_dest_table_root, sl, ipa_bits,
                             dest_base_ipa, RTT_PAGE_LEVEL, &wi);

	if (wi.last_level != RTT_PAGE_LEVEL) {
               // ret = pack_return_code(RMI_ERROR_RTT,
                //                        (unsigned int)wi.last_level);
                goto out_unlock_ll_table;
        }

        s2tt = granule_map(wi.g_llt, SLOT_RTT);
        assert(s2tt != NULL);

        s2tte = s2tte_read(&s2tt[wi.index]);
        if (!s2tte_is_unassigned(s2tte)) {
//                ret = pack_return_code(RMI_ERROR_RTT, RTT_PAGE_LEVEL);
  //              goto out_unmap_ll_table;
        }

        if (s2tte_is_assigned_ram(s2tte, wi.last_level)) {
		s2tte = s2tte_create_assigned_ram(target_pa, RTT_PAGE_LEVEL);
        	s2tte_write(&s2tt[wi.index], s2tte);
        }


out_unlock_ll_table:
	//granule_unlock(walk_res.llt);
        granule_unlock(wi.g_llt);
	res->action = UPDATE_REC_RETURN_TO_REALM;
	res->smc_res.x[0] = RSI_SUCCESS;
}
}

