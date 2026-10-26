#include "ph_internal.h"

struct ph_entry g_entries[2][PH_MAX_ENTRIES];
volatile int g_entry_count[2];
volatile int g_active;
struct ph_dir_slot g_dir_slots[PH_DIR_MAP_N];

/* registry lookup */

int ph_active_idx(void)
{
    return smp_load_acquire(&g_active) & 1;
}

int ph_entry_snapshot(int *idx)
{
    int i = smp_load_acquire(&g_active) & 1;
    int n = smp_load_acquire(&g_entry_count[i]);

    if (n < 0) n = 0;
    if (n > PH_MAX_ENTRIES) n = PH_MAX_ENTRIES;
    *idx = i;
    return n;
}

bool ph_match_inode(void *inode)
{
    u64 sb = inode_sb(inode);
    u64 ino = inode_ino(inode);
    int idx, n = ph_entry_snapshot(&idx);

    for (int i = 0; i < n; i++) {
        if (g_entries[idx][i].sb == sb && g_entries[idx][i].ino == ino) return true;
    }
    return false;
}

/*
 * readdir only gives us (ino, name), not the superblock.  For each registry
 * entry with the same ino, confirm via ilookup() that the inode really lives
 * on that sb.  This also handles the FUSE /sdcard case when the underlying
 * /data/media/0 path was registered: the FUSE readdir ino matches the
 * backing inode number.
 */
bool ph_match_ino(u64 ino)
{
    int idx, n;

    if (!g_ilookup || !g_iput) return false;

    n = ph_entry_snapshot(&idx);
    for (int i = 0; i < n; i++) {
        void *inode;

        if (g_entries[idx][i].ino != ino) continue;
        inode = g_ilookup((void *)(unsigned long)g_entries[idx][i].sb, (unsigned long)ino);
        if (inode) {
            bool hide = inode_uid(inode) != current_uid();
            g_iput(inode);
            if (hide) return true;
        }
    }
    return false;
}

/* ctx -> directory sb map (for readdir) */

void ph_dir_sb_store(void *ctx, void *sb)
{
    for (int i = 0; i < PH_DIR_MAP_N; i++) {
        int expected = 0;

        if (!__atomic_compare_exchange_n(&g_dir_slots[i].state, &expected, -1, false, __ATOMIC_ACQ_REL,
                                         __ATOMIC_ACQUIRE))
            continue;
        g_dir_slots[i].ctx = ctx;
        g_dir_slots[i].sb = sb;
        __atomic_store_n(&g_dir_slots[i].state, 1, __ATOMIC_RELEASE);
        return;
    }
}

void ph_dir_sb_remove(void *ctx)
{
    for (int i = 0; i < PH_DIR_MAP_N; i++) {
        if (__atomic_load_n(&g_dir_slots[i].state, __ATOMIC_ACQUIRE) != 1) continue;
        if (g_dir_slots[i].ctx != ctx) continue;
        g_dir_slots[i].ctx = NULL;
        __atomic_store_n(&g_dir_slots[i].state, 0, __ATOMIC_RELEASE);
        return;
    }
}

void *ph_dir_sb_lookup(void *ctx)
{
    for (int i = 0; i < PH_DIR_MAP_N; i++) {
        if (__atomic_load_n(&g_dir_slots[i].state, __ATOMIC_ACQUIRE) != 1) continue;
        if (g_dir_slots[i].ctx == ctx) return g_dir_slots[i].sb;
    }
    return NULL;
}

/*
 * Direct match: the directory sb is authoritative, so no inode lookup is
 * needed.  Returns 1 = hide, 0 = entry belongs to current uid, -1 = no match.
 */
static int ph_match_dir(void *sb, u64 ino)
{
    u64 sbv = (u64)(unsigned long)sb;
    int idx, n = ph_entry_snapshot(&idx);

    for (int i = 0; i < n; i++) {
        if (g_entries[idx][i].sb != sbv || g_entries[idx][i].ino != ino) continue;
        return g_entries[idx][i].i_uid != current_uid();
    }
    return -1;
}

bool ph_match_readdir(void *ctx, u64 ino)
{
    void *sb = ctx ? ph_dir_sb_lookup(ctx) : NULL;

    if (sb) {
        int r = ph_match_dir(sb, ino);

        if (r >= 0) return r;
    }

    /*
     * Fallback for the FUSE /sdcard case: if only the backing
     * /data/media/0 path was registered, the directory sb is the FUSE sb
     * but the entry ino matches the backing inode.  This also covers a
     * full/expired ctx->sb slot.
     */
    return ph_match_ino(ino);
}
