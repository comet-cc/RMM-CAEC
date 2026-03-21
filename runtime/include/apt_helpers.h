#ifndef APT_HELPERS_H
#define APT_HELPERS_H

#include <apt.h>

void apt_reset(struct apt *a);

size_t apt_add_master(struct apt *a,
                      uint8_t region_ID,
                      unsigned long ipa_start,
                      unsigned long map_size,
                      bool enable_now);

size_t apt_add_slave(struct apt *a,
                     uint8_t master_ID,
                     uint8_t region_ID,
                     unsigned long master_rd_pa,
                     unsigned long ipa_start,
                     unsigned long map_size,
                     bool enable_now);

bool apt_enable_master_idx(struct apt *a, size_t idx);
bool apt_disable_master_idx(struct apt *a, size_t idx);
bool apt_enable_slave_idx(struct apt *a, size_t idx);
bool apt_disable_slave_idx(struct apt *a, size_t idx);

bool apt_find_enabled_conflict(const struct apt *a,
                               unsigned long ipa_start,
                               unsigned long map_size,
                               enum apt_region_kind *kind_out,
                               size_t *idx_out,
                               bool skip_master_check);

#endif /* APT_HELPERS_H */
