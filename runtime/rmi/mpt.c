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

unsigned long smc_mpt_create(unsigned long rd_addr,
			     unsigned long rec_addr,
			     unsigned long rec_params_addr)
{ 
	INFO("this is smc_mpt_create \n"); 
 	return RMI_SUCCESS;
}

unsigned long smc_mpt_destroy(unsigned long rec_addr)
{
	INFO("this is smc_mpt_destroy \n");
	return RMI_SUCCESS;
}

