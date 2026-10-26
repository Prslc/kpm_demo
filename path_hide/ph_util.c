#include "ph_internal.h"

/*
 * GCC lowers __atomic_compare_exchange_n() to an outline call on arm64.
 * KPMs must not depend on libgcc symbols (KP resolves undefined symbols
 * against its own table), so provide the exact libgcc helper locally.
 * ABI: returns the old value; newval is stored when oldval matches.
 */
int __aarch64_cas4_acq_rel(int oldval, int newval, int *ptr)
{
    int old, fail;

    do {
        fail = 0;
        __asm__ __volatile__("ldaxr %w0, [%2]\n"
                             "cmp   %w0, %w3\n"
                             "b.ne  1f\n"
                             "stlxr %w1, %w4, [%2]\n"
                             "1:\n"
                             : "=&r"(old), "+r"(fail)
                             : "r"(ptr), "r"(oldval), "r"(newval)
                             : "memory");
    } while (fail);

    return old;
}

bool ph_krange(const void *p)
{
    return (unsigned long)p >= 0xffff000000000000UL;
}

bool ph_kptr(const void *p)
{
    unsigned long v = (unsigned long)p;
    return v >= 0xffff000000000000UL && !(v & 7);
}

int ph_parse_u64(const char *s, u64 *out)
{
    u64 v = 0;
    int any = 0;

    while (*s == ' ')
        s++;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (u64)(*s - '0');
        s++;
        any = 1;
    }
    if (!any) return -EINVAL;
    *out = v;
    return 0;
}

int ph_parse_hex(const char *s, u64 *out)
{
    u64 v = 0;
    int any = 0;

    while (*s == ' ')
        s++;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    for (;;) {
        int d;

        if (*s >= '0' && *s <= '9')
            d = *s - '0';
        else if (*s >= 'a' && *s <= 'f')
            d = *s - 'a' + 10;
        else if (*s >= 'A' && *s <= 'F')
            d = *s - 'A' + 10;
        else
            break;
        v = (v << 4) | (u64)d;
        s++;
        any = 1;
    }
    if (!any) return -EINVAL;
    *out = v;
    return 0;
}

int ph_sputs(char *buf, int cap, int pos, const char *s)
{
    while (*s && pos < cap - 1)
        buf[pos++] = *s++;
    buf[pos] = 0;
    return pos;
}

int ph_sput_u64(char *buf, int cap, int pos, u64 v)
{
    char tmp[24];
    int n = 0;

    if (v == 0) tmp[n++] = '0';
    while (v && n < (int)sizeof(tmp)) {
        tmp[n++] = '0' + (char)(v % 10);
        v /= 10;
    }
    while (n > 0 && pos < cap - 1)
        buf[pos++] = tmp[--n];
    buf[pos] = 0;
    return pos;
}

int ph_sput_i64(char *buf, int cap, int pos, long v)
{
    if (v < 0) {
        if (pos < cap - 1) buf[pos++] = '-';
        buf[pos] = 0;
        return ph_sput_u64(buf, cap, pos, (u64)(-v));
    }
    return ph_sput_u64(buf, cap, pos, (u64)v);
}

int ph_sput_hex(char *buf, int cap, int pos, u64 v)
{
    char tmp[16];
    int n = 0;

    if (!v) tmp[n++] = '0';
    while (v && n < (int)sizeof(tmp)) {
        int d = (int)(v & 0xf);
        tmp[n++] = (char)(d < 10 ? '0' + d : 'a' + d - 10);
        v >>= 4;
    }
    while (n > 0 && pos < cap - 1)
        buf[pos++] = tmp[--n];
    buf[pos] = 0;
    return pos;
}

int ph_sput_off(char *buf, int cap, int pos, const char *name, int v)
{
    pos = ph_sputs(buf, cap, pos, name);
    pos = ph_sputs(buf, cap, pos, "=");
    return ph_sput_hex(buf, cap, pos, (u64)v);
}

char *ph_trim(char *s)
{
    char *e;

    while (*s == ' ' || *s == '\t' || *s == '\r')
        s++;
    e = s;
    while (*e)
        e++;
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n'))
        *--e = 0;
    return s;
}

u32 ph_strlen(const char *s)
{
    u32 n = 0;

    while (s[n])
        n++;
    return n;
}

/* put_cred() is inline; __put_cred() BUG_ONs unless usage is already 0. */
int ph_atomic_dec_and_test(int *p)
{
    int old = __atomic_load_n(p, __ATOMIC_ACQUIRE);

    for (;;) {
        if (old <= 0) return 0;
        if (__atomic_compare_exchange_n(p, &old, old - 1, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) return old == 1;
    }
}
