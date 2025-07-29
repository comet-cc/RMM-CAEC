/*
 * Simple per-Realm tag registry (outside RD/REC).
 * For now, tag generation uses a small set of hardcoded 64-bit values, then
 * falls back to a deterministic pattern. The generator is isolated so you can
 * replace it later with RNG/HMAC/etc. without touching callers.
 */

#include "realm_tag.h"

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "spinlock.h"   // Uses RMM's existing spinlock implementation

/* Choose a safe upper bound or derive from platform limits if you prefer. */
#define CONFIG_MAX_REALMS 10

struct tag_entry {
    uint64_t rd_pa;   /* Physical address of the RD granule (stable handle) */
    uint64_t tag;     /* 64-bit tag */
    bool     in_use;
};

static struct tag_entry g_tags[CONFIG_MAX_REALMS];
static spinlock_t       g_tag_lock;

/* --- Tag generation state & helpers ------------------------------------- */

static size_t   g_tag_next_index;     /* next index into k_default_tags[] */
static uint64_t g_tag_counter;        /* fallback counter for synthesized tags */

/* A few simple hardcoded tags to start with (easy to spot in logs/tests). */
static const uint64_t k_default_tags[] = {
    0x1111111111111111ULL,
    0x2222222222222222ULL,
    0x3333333333333333ULL,
    0x4444444444444444ULL,
    0x5555555555555555ULL,
    0x6666666666666666ULL,
    0x7777777777777777ULL,
    0x8888888888888888ULL,
    0x9999999999999999ULL,
    0xAAAAAAAAAAAAAAAAULL
};

/* Forward decls */
static int  find_slot_by_rd(uint64_t rd_pa);
static int  find_free_slot(void);
static bool tag_collides(uint64_t tag);


static uint64_t realm_tag_generate_next(void)
{
    /* 1) Prefer hardcoded values first. */
    if (g_tag_next_index < (sizeof(k_default_tags) / sizeof(k_default_tags[0]))) {
        uint64_t t = k_default_tags[g_tag_next_index++];
        if (t == 0) t = 1; /* reserve 0 as invalid */
        return t;
    }

    /* 2) Fallback: deterministic pattern based on a counter. */
    /* Using a simple xor with a fixed mask; keep it obvious & test-friendly. */
    uint64_t candidate = 0;
    do {
        /* 0xF00D... is arbitrary; change freely later if you like. */
        candidate = 0xF00D000000000000ULL ^ g_tag_counter++;
        if (candidate == 0) 
            candidate = 1;
        /* Loop ends once caller confirms non-collision. */
        /* We don't collision-check here to keep generator independent. */
        return candidate;
    } while (0);
}

/* --- Registry internals -------------------------------------------------- */

static int find_slot_by_rd(uint64_t rd_pa)
{
    for (int i = 0; i < (int)CONFIG_MAX_REALMS; ++i) {
        if (g_tags[i].in_use && g_tags[i].rd_pa == rd_pa) 
        return i;
    }
    return -1;
}

static int find_free_slot(void)
{
    for (int i = 0; i < (int)CONFIG_MAX_REALMS; ++i) {
        if (!g_tags[i].in_use) return i;
    }
    return -1;
}

static bool tag_collides(uint64_t tag)
{
    if (tag == 0) return true; /* 0 is reserved as "invalid" */
    for (int i = 0; i < (int)CONFIG_MAX_REALMS; ++i) {
        if (g_tags[i].in_use && g_tags[i].tag == tag) 
            return true;
    }
    return false;
}


void realm_tag_init(void)
{
    /* spinlock_t is zero-initialized (unlocked) in .bss; no explicit init needed. */
    memset(g_tags, 0, sizeof(g_tags));
    g_tag_next_index = 0;
    g_tag_counter    = 1; /* start at 1 to keep 0 invalid */
}

bool realm_tag_assign(uint64_t rd_pa, uint64_t *out_tag)
{
    bool ok = false;

       spinlock_acquire(&g_tag_lock);

    /* Don't double-assign for the same RD. */
    if (find_slot_by_rd(rd_pa) >= 0) {
        goto out_unlock;
    }

    int slot = find_free_slot();
    if (slot < 0) {
        goto out_unlock; /* registry full */
    }

    /* Generate a unique tag; try a few times in case of collision. */
    uint64_t tag = 0;
    int tries = 0;
    do {
        tag = realm_tag_generate_next();
        tries++;
        if (tries > 16) { /* extremely unlikely to hit this with our scheme */
            goto out_unlock;
        }
    } while (tag_collides(tag));

    g_tags[slot].rd_pa  = rd_pa;
    g_tags[slot].tag    = tag;
    g_tags[slot].in_use = true;

    if (out_tag) *out_tag = tag;
    ok = true;

out_unlock:
    spinlock_release(&g_tag_lock);
    return ok;
}

bool realm_tag_get_by_rd(uint64_t rd_pa, uint64_t *out_tag)
{
    bool ok = false;
    spinlock_acquire(&g_tag_lock);
    int idx = find_slot_by_rd(rd_pa);
    if (idx >= 0 && out_tag) {
        *out_tag = g_tags[idx].tag;
        ok = true;
    }
    spinlock_release(&g_tag_lock);
    return ok;
}

bool realm_tag_remove(uint64_t rd_pa)
{
    bool ok = false;
    spinlock_acquire(&g_tag_lock);
    int idx = find_slot_by_rd(rd_pa);
    if (idx >= 0) {
        g_tags[idx].in_use = false;
        g_tags[idx].rd_pa  = 0;
        g_tags[idx].tag    = 0;
        ok = true;
    }
    spinlock_release(&g_tag_lock);
    return ok;
}

bool realm_tag_exists(uint64_t tag)
{
    bool found = false;
    if (tag == 0) 
        return false;
    spinlock_acquire(&g_tag_lock);
    for (int i = 0; i < (int)CONFIG_MAX_REALMS; ++i) {
        if (g_tags[i].in_use && g_tags[i].tag == tag) { found = true; break; }
    }
    spinlock_release(&g_tag_lock);
    return found;
}
