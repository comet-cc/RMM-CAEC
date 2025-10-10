#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <spinlock.h>
#include <realm_tag.h>
#include <debug.h>

#define CONFIG_MAX_REALMS 10

static int  find_slot_by_rd(uint64_t rd_pa);
static int  find_free_slot(void);
static bool tag_collides(uint8_t tag);   // note: uint8_t now

struct tag_entry {
    uint64_t rd_pa;   /* Physical address of the Realm's RD granule */
    uint8_t  tag;     /* 8-bit tag (owner ID) */
    bool     in_use;
};

static struct tag_entry g_tags[CONFIG_MAX_REALMS];
static spinlock_t       g_tag_lock;

static size_t   g_tag_next_index;
static uint8_t  g_tag_counter;  /* 8-bit counter for synthesized tags */

/* A few simple hardcoded 8-bit tags to start with (easy to spot). */
static const uint8_t k_default_tags[] = {
    0x11, 0x22, 0x33, 0x44, 0x55,
    0x66, 0x77, 0x88, 0x99, 0xAA
};

/* Generate the next unique 8-bit Realm tag */
static uint8_t realm_tag_generate_next(void)
{
    // 1) Use hardcoded values first
    if (g_tag_next_index < sizeof(k_default_tags)) {
        uint8_t t = k_default_tags[g_tag_next_index++];
        if (t == 0) t = 1;  // reserve 0 as invalid
        return t;
    }
    // 2) Fallback: deterministic pattern based on counter
    uint8_t candidate;
    do {
        candidate = (uint8_t)(0xF0 ^ g_tag_counter++);  // XOR counter with 0xF0
        if (candidate == 0)
            candidate = 1;
        return candidate;
    } while (0);
}

/* Find the slot index by RD physical address */
static int find_slot_by_rd(uint64_t rd_pa)
{
    for (int i = 0; i < CONFIG_MAX_REALMS; i++) {
        if (g_tags[i].in_use && g_tags[i].rd_pa == rd_pa) {
            return i;
        }
    }
    return -1;
}

/* Find a free slot in the tag registry */
static int find_free_slot(void)
{
    for (int i = 0; i < CONFIG_MAX_REALMS; i++) {
        if (!g_tags[i].in_use) {
            return i;
        }
    }
    return -1;
}

/* Check for tag collisions */
static bool tag_collides(uint8_t tag)
{
    for (int i = 0; i < CONFIG_MAX_REALMS; i++) {
        if (g_tags[i].in_use && g_tags[i].tag == tag) {
            return true;
        }
    }
    return false;
}

void realm_tag_init(void)
{
    memset(g_tags, 0, sizeof(g_tags));
    g_tag_next_index = 0;
    g_tag_counter    = 1;  // start at 1 to keep 0 as invalid
}

bool realm_tag_assign(uint64_t rd_pa, uint8_t *out_tag)
{
    bool ok = false;
    spinlock_acquire(&g_tag_lock);

    if (find_slot_by_rd(rd_pa) >= 0) {
        goto out_unlock;  // RD already has a tag
    }
    int slot = find_free_slot();
    if (slot < 0) {
        goto out_unlock;  // no free slot (registry full)
    }
    // Generate a unique tag (avoid collisions with existing tags)
    uint8_t tag;
    int tries = 0;
    do {
        tag = realm_tag_generate_next();
        tries++;
        if (tries > 16) {
            goto out_unlock;  // too many collisions (unlikely)
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

bool realm_tag_get_by_rd(uint64_t rd_pa, uint8_t *out_tag)
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
        g_tags[idx].tag    = 0;   /* 0 reserved as invalid/unassigned */
        ok = true;
    }

    spinlock_release(&g_tag_lock);
    return ok;
}

/* Check if a given 8-bit tag exists in the registry. */
bool realm_tag_exists(uint8_t tag)
{
    if (tag == 0) {
        return false; /* 0 is reserved */
    }

    bool found = false;
    spinlock_acquire(&g_tag_lock);

    for (int i = 0; i < (int)CONFIG_MAX_REALMS; ++i) {
        if (g_tags[i].in_use && g_tags[i].tag == tag) {
            found = true;
            break;
        }
    }

    spinlock_release(&g_tag_lock);
    return found;
}
bool realm_tag_rd_by_tag(uint8_t tag, uint64_t *out_rd_pa)
{
    if (tag == 0 || out_rd_pa == NULL)
        return false;

    bool ok = false;

    spinlock_acquire(&g_tag_lock);

    for (int i = 0; i < (int)CONFIG_MAX_REALMS; ++i) {
        if (g_tags[i].in_use && g_tags[i].tag == tag) {
            *out_rd_pa = g_tags[i].rd_pa;
            ok = true;
            break;
        }
    }

    spinlock_release(&g_tag_lock);
    return ok;
}
