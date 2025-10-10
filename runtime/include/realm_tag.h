// runtime/core/realm_tag.h

#include <stdint.h>
#include <stdbool.h>


/*
 * Realm tag API (8-bit tags).
 * Tag value 0 is reserved as "invalid / unassigned".
 */

/* Initialize the realm tag registry. Call during RMM init. */
void realm_tag_init(void);

/*
 * Assign a new unique 8-bit tag to the Realm identified by its RD granule PA.
 * Returns true on success; out_tag (if not NULL) receives the assigned tag.
 * Fails (false) if the RD already has a tag or registry is full.
 */
bool realm_tag_assign(uint64_t rd_pa, uint8_t *out_tag);

/*
 * Look up the tag for a Realm by RD PA.
 * Returns true and writes the tag to out_tag if found; false otherwise.
 */
bool realm_tag_get_by_rd(uint64_t rd_pa, uint8_t *out_tag);

/*
 * Remove the tag entry for the given RD PA.
 * Returns true if an entry existed and was removed; false otherwise.
 */
bool realm_tag_remove(uint64_t rd_pa);

/*
 * Check whether a given 8-bit tag currently exists in the registry.
 * Returns true if present; false if not (or if tag == 0).
 */
bool realm_tag_exists(uint8_t tag);

bool realm_tag_rd_by_tag(uint8_t tag, uint64_t *out_rd_pa);

