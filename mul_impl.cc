/*
openssl 大数乘法实现
 */
typedef struct bignum_st BIGNUM;

struct bignum_st
       {
BN_ULONG *d;
int top;   //用来指明大数占多少个BN_ULONG空间
int dmax;  //d数组的大小
int neg;   //是否为负数，如果为1，则是负数，为0，则为正数
int flags; // 用于存放一些标记，比如flags含有BN_FLG_STATIC_DATA时，表明d的内存是静态分配的；含有BN_FLG_MALLOCED时，d的内存是动态分配的。
       };
/*
The integer value is stored in d, a malloc()ed array of words (BN_ULONG), least significant word first. A BN_ULONG can be either 16, 32 or 64 bits in size, depending on the 'number of bits' (BITS2) specified in openssl/bn.h.

dmax is the size of the d array that has been allocated. top is the number of words being used, so for a value of 4, bn.d[0]=4 and bn.top=1. neg is 1 if the number is negative. When a BIGNUM is 0, the d field can be NULL and top == 0.

flags is a bit field of flags which are defined in openssl/bn.h. The flags begin with BN_FLG_. The macros BN_set_flags(b, n) and BN_get_flags(b, n) exist to enable or fetch flag(s) n from BIGNUM structure b.
 */

/*
int / uint / long /(long long)
默认/ ul   /  L   / LL
*/

# ifdef SIXTY_FOUR_BIT_LONG
#  define BN_ULLONG       unsigned long long
#  define BN_BITS4        32
#  define BN_MASK2        (0xffffffffffffffffL)
# endif

# ifdef SIXTY_FOUR_BIT
#  undef BN_LLONG
#  undef BN_ULLONG
#  define BN_BITS4        32
#  define BN_MASK2        (0xffffffffffffffffLL)
# endif

int BN_mul_word(BIGNUM *a, BN_ULONG w)
{
    BN_ULONG ll;

    bn_check_top(a); //for verifying that there are no leading zeroes

    w &= BN_MASK2; //什么目的

    if (a->top) {
        if (w == 0)
            BN_zero(a);
        else {
            ll = bn_mul_words(a->d, a->d, a->top, w);
            if (ll) {
                if (bn_wexpand(a, a->top + 1) == NULL)
                    return 0;
                a->d[a->top++] = ll;
            }
        }
    }

    bn_check_top(a);
    return 1;
}

BN_ULONG bn_mul_words(BN_ULONG *rp, const BN_ULONG *ap, int num, BN_ULONG w)
{
    BN_ULONG c1 = 0;

    assert(num >= 0);
    if (num <= 0)
        return c1;

# ifndef OPENSSL_SMALL_FOOTPRINT
    while (num & ~3) {
        mul(rp[0], ap[0], w, c1);
        mul(rp[1], ap[1], w, c1);
        mul(rp[2], ap[2], w, c1);
        mul(rp[3], ap[3], w, c1);
        ap += 4;
        rp += 4;
        num -= 4;
    }
# endif
    while (num) {
        mul(rp[0], ap[0], w, c1);
        ap++;
        rp++;
        num--;
    }
    return c1;
}

#  define Lw(t)    (((BN_ULONG)(t))&BN_MASK2)
#  define Hw(t)    (((BN_ULONG)((t)>>BN_BITS2))&BN_MASK2)
#  define mul(r,a,w,c) { \
        BN_ULLONG t; \
        t=(BN_ULLONG)w * (a) + (c); \
        (r)= Lw(t); \
        (c)= Hw(t); \
        }
