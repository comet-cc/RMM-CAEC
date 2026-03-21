#ifndef CSM_ID_H
#define CSM_ID_H

#include <stdbool.h>
#include <stdint.h>

bool csm_region_id_assign(uint64_t owner_rd_pa, uint8_t *out_region_id);
bool csm_region_id_remove(uint8_t region_id);

#endif /* CSM_ID_H */
