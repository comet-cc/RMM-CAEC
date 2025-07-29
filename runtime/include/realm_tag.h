#pragma once
/*
 * Simple per-Realm tag registry.
 * Stores a 64-bit tag for each Realm (keyed by RD physical address).
 *
 * This is RMM-owned state (outside RD/REC) so Realms/host don't see it unless
 * you expose an RMI/RSI getter.
 */

#include <stdint.h>
#include <stdbool.h>


/* Initialize registry. Call once during RMM init. */
void realm_tag_init(void);

/* Assign a tag to the Realm identified by rd_pa. Fails if already present. */
bool realm_tag_assign(uint64_t rd_pa, uint64_t *out_tag);

/* Lookup the tag for a given RD. Returns false if not found. */
bool realm_tag_get_by_rd(uint64_t rd_pa, uint64_t *out_tag);

/* Remove the tag for a Realm (e.g., at destroy). Returns false if not found. */
bool realm_tag_remove(uint64_t rd_pa);

/* Optional convenience: check if a tag exists (debug/diagnostic). */
bool realm_tag_exists(uint64_t tag);

