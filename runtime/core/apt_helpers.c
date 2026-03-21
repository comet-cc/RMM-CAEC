/*
 * SPDX-License-Identifier: BSD-3-Clause
 * SPDX-FileCopyrightText: Copyright TF-RMM Contributors.
 */

#include <limits.h>
#include <stddef.h>
#include <string.h>

#include <apt_helpers.h>
#include <debug.h>

static inline size_t first_free_from_mask(uint64_t used_mask) {
    for (size_t i = 0; i < MAX_MEM_REGIONS; ++i)
        if ((used_mask & BIT64(i)) == 0) return i;
    return SIZE_MAX;
}

static inline void enable_push_master(struct apt *a, size_t idx) {
    struct enabled_master_regions *em = &a->enabled_mr;
    size_t pos = em->len;
    em->index[pos] = idx;
    em->pos_by_index[idx] = pos;
    em->len++;
    a->master_enabled_mask |= BIT64(idx);
}

static inline void enable_push_slave(struct apt *a, size_t idx) {
    struct enabled_slave_regions *es = &a->enabled_sr;
    size_t pos = es->len;
    es->index[pos] = idx;
    es->pos_by_index[idx] = pos;
    es->len++;
    a->slave_enabled_mask |= BIT64(idx);
}

static inline void disable_swap_pop_master(struct apt *a, size_t idx) {
    struct enabled_master_regions *em = &a->enabled_mr;
    size_t pos = em->pos_by_index[idx];
    size_t last_pos = em->len - 1;

    if (pos != last_pos) {
        em->index[pos] = em->index[last_pos];
        em->pos_by_index[ em->index[pos] ] = pos;
    }
    em->len--;
    a->master_enabled_mask &= ~BIT64(idx);
}

static inline void disable_swap_pop_slave(struct apt *a, size_t idx) {
    struct enabled_slave_regions *es = &a->enabled_sr;
    size_t pos = es->pos_by_index[idx];
    size_t last_pos = es->len - 1;

    if (pos != last_pos) {
        es->index[pos] = es->index[last_pos];
        es->pos_by_index[ es->index[pos] ] = pos;
    }
    es->len--;
    a->slave_enabled_mask &= ~BIT64(idx);
}

/* Safe half-open range overlap check (treat overflow as conflict) */
static inline bool range_overlaps_ul(unsigned long a_start, unsigned long a_size,
                                     unsigned long b_start, unsigned long b_size)
{
    if (a_size == 0 || b_size == 0) return false;

    unsigned long a_end = a_start + a_size;
    unsigned long b_end = b_start + b_size;

    if (a_end < a_start || b_end < b_start) return true; /* overflow → conflict */

    /* [a_start, a_end) vs [b_start, b_end) */
    return !(a_end <= b_start || b_end <= a_start);
}

/* ---- Public API ---- */

void apt_reset(struct apt *a) {
    memset(a, 0, sizeof(*a));
}

size_t apt_add_master(struct apt *a,
                      uint8_t region_ID,
                      unsigned long ipa_start,
                      unsigned long map_size,
                      bool enable_now)
{
    size_t idx = first_free_from_mask(a->master_used_mask);
    if (idx == SIZE_MAX) 
        return SIZE_MAX;

    struct master_mem *m = &a->master_memory[idx];
    m->region_ID   = region_ID;
    m->ipa_start   = ipa_start;
    m->map_size    = map_size;
    m->share_count = 0U;
    memset(m->shares, 0, sizeof(m->shares));

    a->master_used_mask |= BIT64(idx);

    if (enable_now && !(a->master_enabled_mask & BIT64(idx))) {
        enable_push_master(a, idx);
    }

    INFO("apt_add_master: idx=%lu region_ID=%u ipa_start=0x%lx map_size=0x%lx enable_now=%d\n",
         idx, region_ID, ipa_start, map_size, enable_now);

    return idx;
}

size_t apt_add_slave(struct apt *a,
                     uint8_t master_ID,
                     uint8_t region_ID,
                     unsigned long master_rd_pa,
                     unsigned long ipa_start,
                     unsigned long map_size,
                     bool enable_now)
{
    size_t idx = first_free_from_mask(a->slave_used_mask);
    if (idx == SIZE_MAX) return SIZE_MAX;

    struct slave_mem *s = &a->slave_memory[idx];
    s->master_ID    = master_ID;
    s->region_ID    = region_ID;
    s->master_rd_pa = master_rd_pa;
    s->ipa_start    = ipa_start;
    s->map_size     = map_size;

    a->slave_used_mask |= BIT64(idx);

    if (enable_now && !(a->slave_enabled_mask & BIT64(idx))) {
        enable_push_slave(a, idx);
    }

    INFO("apt_add_slave: idx=%lu master_ID=%u region_ID=%u master_rd_pa=0x%lx ipa_start=0x%lx map_size=0x%lx enable_now=%d\n",
         idx, master_ID, region_ID, master_rd_pa, ipa_start, map_size, enable_now);

    return idx;
}

bool apt_enable_master_idx(struct apt *a, size_t idx) {
    if (!apt_idx_in_range(idx)) return false;
    if (!(a->master_used_mask & BIT64(idx))) return false;
    if (a->master_enabled_mask & BIT64(idx)) return true; /* already enabled */
    enable_push_master(a, idx);
    return true;
}

bool apt_disable_master_idx(struct apt *a, size_t idx) {
    if (!apt_idx_in_range(idx)) return false;
    if (!(a->master_enabled_mask & BIT64(idx))) return true; /* already disabled */
    disable_swap_pop_master(a, idx);
    return true;
}

bool apt_enable_slave_idx(struct apt *a, size_t idx) {
    if (!apt_idx_in_range(idx)) return false;
    if (!(a->slave_used_mask & BIT64(idx))) return false;
    if (a->slave_enabled_mask & BIT64(idx)) return true; /* already enabled */
    enable_push_slave(a, idx);
    return true;
}

bool apt_disable_slave_idx(struct apt *a, size_t idx) {
    if (!apt_idx_in_range(idx)) return false;
    if (!(a->slave_enabled_mask & BIT64(idx))) return true; /* already disabled */
    disable_swap_pop_slave(a, idx);
    return true;
}

bool apt_find_enabled_conflict(const struct apt *a,
                                  unsigned long ipa_start,
                                  unsigned long map_size,
                                  enum apt_region_kind *kind_out,
                                  size_t *idx_out,
                                  bool skip_master_check)
{
    /* Optionally check enabled masters */
    if (!skip_master_check) {
        for (size_t pos = 0; pos < a->enabled_mr.len; ++pos) {
            size_t idx = a->enabled_mr.index[pos];
            const struct master_mem *m = &a->master_memory[idx];
            if (range_overlaps_ul(ipa_start, map_size, m->ipa_start, m->map_size)) {
                if (kind_out) *kind_out = APT_REGION_MASTER;
                if (idx_out)  *idx_out  = idx;
                return true;
            }
        }
    }
    /* Always check enabled slaves */
    for (size_t pos = 0; pos < a->enabled_sr.len; ++pos) {
        size_t idx = a->enabled_sr.index[pos];
        const struct slave_mem *s = &a->slave_memory[idx];
        if (range_overlaps_ul(ipa_start, map_size, s->ipa_start, s->map_size)) {
            if (kind_out) *kind_out = APT_REGION_SLAVE;
            if (idx_out)  *idx_out  = idx;
            return true;
        }
    }

    return false; /* no conflicts */
}
