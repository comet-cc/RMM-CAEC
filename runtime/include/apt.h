#include <sizes.h>
#include <utils_def.h>

#include <stddef.h>   // size_t
#include <stdint.h>   // uint64_t, uint8_t
#include <stdbool.h>  // bool

#ifndef BIT64
#define BIT64(i) (1ULL << (i))
#endif

struct granule;

#ifndef MAX_MEM_REGIONS
#define MAX_MEM_REGIONS 20
#endif

#ifndef CSM_MAX_MASTER_SHARES
#define CSM_MAX_MASTER_SHARES 3
#endif

/* -------- Region records -------- */

struct master_share {
    uint8_t       slave_ID;
    unsigned long slave_rd_pa;
    uint8_t       permission;
    bool          in_use;
};

struct master_mem {
    uint8_t       region_ID;
    unsigned long ipa_start;
    unsigned long map_size;
    uint8_t       flags;
    uint8_t       share_count;
    struct master_share shares[CSM_MAX_MASTER_SHARES];
};

struct slave_mem {
    uint8_t       master_ID;
    uint8_t       region_ID;
    unsigned long master_rd_pa;
    unsigned long ipa_start;
    unsigned long map_size;
    uint8_t       flags;
};

/* Enabled sets (unordered, packed) */
struct enabled_master_regions {
    uint8_t len;                            /* number of enabled regions */
    size_t  index[MAX_MEM_REGIONS];         /* enabled position -> region index */
    size_t  pos_by_index[MAX_MEM_REGIONS];  /* region index -> enabled position */
};

struct enabled_slave_regions {
    uint8_t len;
    size_t  index[MAX_MEM_REGIONS];
    size_t  pos_by_index[MAX_MEM_REGIONS];
};

/* Main APT */
struct apt {

    struct master_mem master_memory[MAX_MEM_REGIONS];
    struct slave_mem slave_memory[MAX_MEM_REGIONS];

    struct enabled_master_regions enabled_mr;
    struct enabled_slave_regions  enabled_sr;

    /* Masks for O(1) checks */
    uint64_t master_used_mask;
    uint64_t slave_used_mask;
    uint64_t master_enabled_mask;
    uint64_t slave_enabled_mask;
};

COMPILER_ASSERT(sizeof(struct apt) <= GRANULE_SIZE);
COMPILER_ASSERT(MAX_MEM_REGIONS <= 63);

/* -------- Public enums / prototypes -------- */

enum apt_region_kind {
    APT_REGION_MASTER = 0,
    APT_REGION_SLAVE  = 1
};

/* Implemented in apt.c */
void   apt_reset(struct apt *a);

size_t apt_add_master(struct apt *a,
                      uint8_t region_ID,
                      unsigned long ipa_start,
                      unsigned long map_size,
                      uint8_t flags,
                      bool enable_now);

size_t apt_add_slave(struct apt *a,
                     uint8_t master_ID,
                     uint8_t region_ID,
                     unsigned long master_rd_pa,
                     unsigned long ipa_start,
                     unsigned long map_size,
                     uint8_t flags,
                     bool enable_now);

bool apt_enable_master_idx(struct apt *a, size_t idx);
bool apt_disable_master_idx(struct apt *a, size_t idx);
bool apt_enable_slave_idx(struct apt *a, size_t idx);
bool apt_disable_slave_idx(struct apt *a, size_t idx);

/* Conflict check vs currently enabled regions (masters + slaves) */
bool apt_find_enabled_conflict(const struct apt *a,
                                  unsigned long ipa_start,
                                  unsigned long map_size,
                                  enum apt_region_kind *kind_out,
                                  size_t *idx_out,
                                  bool skip_master_check);

static inline uint32_t apt_make_sharing_id(uint8_t region_ID,
                                           uint8_t master_ID,
                                           uint8_t slave_ID)
{
    return ((uint32_t)region_ID << 16) |
           ((uint32_t)master_ID << 8) |
           (uint32_t)slave_ID;
}

static inline uint8_t apt_sharing_region_id(uint32_t sharing_ID)
{
    return (uint8_t)((sharing_ID >> 16) & 0xFFU);
}

static inline uint8_t apt_sharing_master_id(uint32_t sharing_ID)
{
    return (uint8_t)((sharing_ID >> 8) & 0xFFU);
}

static inline uint8_t apt_sharing_slave_id(uint32_t sharing_ID)
{
    return (uint8_t)(sharing_ID & 0xFFU);
}

                                
/* -------- Small inline helpers (header-only) -------- */

static inline bool apt_idx_in_range(size_t idx) { return idx < MAX_MEM_REGIONS; }

static inline bool apt_master_used(const struct apt *a, size_t idx) {
    return apt_idx_in_range(idx) && (a->master_used_mask & BIT64(idx));
}
static inline bool apt_slave_used(const struct apt *a, size_t idx) {
    return apt_idx_in_range(idx) && (a->slave_used_mask & BIT64(idx));
}
static inline bool apt_master_enabled(const struct apt *a, size_t idx) {
    return apt_idx_in_range(idx) && (a->master_enabled_mask & BIT64(idx));
}
static inline bool apt_slave_enabled(const struct apt *a, size_t idx) {
    return apt_idx_in_range(idx) && (a->slave_enabled_mask & BIT64(idx));
}

static inline size_t apt_enabled_master_len(const struct apt *a) {
    return a->enabled_mr.len;
}
static inline const struct master_mem *
apt_enabled_master_at(const struct apt *a, size_t pos) {
    return &a->master_memory[a->enabled_mr.index[pos]];
}
static inline size_t apt_enabled_master_index_at(const struct apt *a, size_t pos) {
    return a->enabled_mr.index[pos];
}

static inline size_t apt_enabled_slave_len(const struct apt *a) {
    return a->enabled_sr.len;
}
static inline const struct slave_mem *
apt_enabled_slave_at(const struct apt *a, size_t pos) {
    return &a->slave_memory[a->enabled_sr.index[pos]];
}
static inline size_t apt_enabled_slave_index_at(const struct apt *a, size_t pos) {
    return a->enabled_sr.index[pos];
}

static inline int apt_find_master_by_region_id(const struct apt *a, uint8_t region_ID)
{
    for (size_t i = 0; i < MAX_MEM_REGIONS; ++i) {
        if ((a->master_used_mask & BIT64(i)) &&
            a->master_memory[i].region_ID == region_ID) {
            return (int)i;
        }
    }

    return -1;
}

static inline int apt_find_master_share_slot(const struct master_mem *m, uint8_t slave_ID)
{
    for (size_t i = 0; i < CSM_MAX_MASTER_SHARES; ++i) {
        if (m->shares[i].in_use && m->shares[i].slave_ID == slave_ID) {
            return (int)i;
        }
    }

    return -1;
}

static inline bool apt_master_add_share(struct apt *a,
                                        size_t idx,
                                        uint8_t slave_ID,
                                        unsigned long slave_rd_pa,
                                        uint8_t permission)
{
    if (!apt_idx_in_range(idx)) {
        return false;
    }
    if ((a->master_used_mask & BIT64(idx)) == 0U) {
        return false;
    }

    struct master_mem *m = &a->master_memory[idx];

    if (apt_find_master_share_slot(m, slave_ID) >= 0) {
        return false;
    }

    for (size_t i = 0; i < CSM_MAX_MASTER_SHARES; ++i) {
        if (!m->shares[i].in_use) {
            m->shares[i].slave_ID    = slave_ID;
            m->shares[i].slave_rd_pa = slave_rd_pa;
            m->shares[i].permission  = permission;
            m->shares[i].in_use      = true;
            m->share_count++;
            return true;
        }
    }

    return false;
}

/* Optional: quick “find free slot” helpers in header */
static inline int apt_find_free_master(const struct apt *a) {
    for (size_t i = 0; i < MAX_MEM_REGIONS; ++i)
        if ((a->master_used_mask & BIT64(i)) == 0) return (int)i;
    return -1;
}
static inline int apt_find_free_slave(const struct apt *a) {
    for (size_t i = 0; i < MAX_MEM_REGIONS; ++i)
        if ((a->slave_used_mask & BIT64(i)) == 0) return (int)i;
    return -1;
}
