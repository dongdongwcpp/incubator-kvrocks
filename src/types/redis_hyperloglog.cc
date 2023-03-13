/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

// This file is modified from several source code files about hyperloglog of Redis.
// See the original code at https://github.com/redis/redis.

#include "redis_hyperloglog.h"

#include <iostream>

#include "common/sds.h"
using namespace std;
#define Debug cout << __FILE__ << ":" << __LINE__ << " "

namespace Redis {

struct hllhdr {
  char magic[4];       /* "HYLL" */
  uint8_t encoding;    /* HLL_DENSE or HLL_SPARSE. */
  uint8_t notused[3];  /* Reserved for future use, must be zero. */
  uint8_t card[8];     /* Cached cardinality, little endian. */
  uint8_t registers[]; /* Data bytes. */
};

/* The cached cardinality MSB is used to signal validity of the cached value. */
#define HLL_INVALIDATE_CACHE(hdr) (hdr)->card[0] |= (1 << 7)
#define HLL_VALID_CACHE(hdr) (((hdr)->card[0] & (1 << 7)) == 0)

#define HLL_P 14                       /* The greater is P, the smaller the error. */
#define HLL_REGISTERS (1 << HLL_P)     /* With P=14, 16384 registers. */
#define HLL_P_MASK (HLL_REGISTERS - 1) /* Mask to index register. */
#define HLL_BITS 6                     /* Enough to count up to 63 leading zeroes. */
#define HLL_REGISTER_MAX ((1 << HLL_BITS) - 1)
#define HLL_HDR_SIZE sizeof(struct hllhdr)
#define HLL_DENSE_SIZE (HLL_HDR_SIZE + ((HLL_REGISTERS * HLL_BITS + 7) / 8))
#define HLL_DENSE 0  /* Dense encoding. */
#define HLL_SPARSE 1 /* Sparse encoding. */
#define HLL_RAW 255  /* Only used internally, never exposed. */
#define HLL_MAX_ENCODING 1

#define HLL_DENSE_GET_REGISTER(target, p, regnum)             \
  do {                                                        \
    uint8_t *_p = (uint8_t *)p;                               \
    unsigned long _byte = regnum * HLL_BITS / 8;              \
    unsigned long _fb = regnum * HLL_BITS & 7;                \
    unsigned long _fb8 = 8 - _fb;                             \
    unsigned long b0 = _p[_byte];                             \
    unsigned long b1 = _p[_byte + 1];                         \
    target = ((b0 >> _fb) | (b1 << _fb8)) & HLL_REGISTER_MAX; \
  } while (0)

/* Set the value of the register at position 'regnum' to 'val'.
 * 'p' is an array of unsigned bytes. */
#define HLL_DENSE_SET_REGISTER(p, regnum, val)    \
  do {                                            \
    uint8_t *_p = (uint8_t *)p;                   \
    unsigned long _byte = regnum * HLL_BITS / 8;  \
    unsigned long _fb = regnum * HLL_BITS & 7;    \
    unsigned long _fb8 = 8 - _fb;                 \
    unsigned long _v = val;                       \
    _p[_byte] &= ~(HLL_REGISTER_MAX << _fb);      \
    _p[_byte] |= _v << _fb;                       \
    _p[_byte + 1] &= ~(HLL_REGISTER_MAX >> _fb8); \
    _p[_byte + 1] |= _v >> _fb8;                  \
  } while (0)

/* Macros to access the sparse representation.
 * The macros parameter is expected to be an uint8_t pointer. */
#define HLL_SPARSE_XZERO_BIT 0x40                    /* 01xxxxxx */
#define HLL_SPARSE_VAL_BIT 0x80                      /* 1vvvvvxx */
#define HLL_SPARSE_IS_ZERO(p) (((*(p)) & 0xc0) == 0) /* 00xxxxxx */
#define HLL_SPARSE_IS_XZERO(p) (((*(p)) & 0xc0) == HLL_SPARSE_XZERO_BIT)
#define HLL_SPARSE_IS_VAL(p) ((*(p)) & HLL_SPARSE_VAL_BIT)
#define HLL_SPARSE_ZERO_LEN(p) (((*(p)) & 0x3f) + 1)
#define HLL_SPARSE_XZERO_LEN(p) (((((*(p)) & 0x3f) << 8) | (*((p) + 1))) + 1)
#define HLL_SPARSE_VAL_VALUE(p) ((((*(p)) >> 2) & 0x1f) + 1)
#define HLL_SPARSE_VAL_LEN(p) (((*(p)) & 0x3) + 1)
#define HLL_SPARSE_VAL_MAX_VALUE 32
#define HLL_SPARSE_VAL_MAX_LEN 4
#define HLL_SPARSE_ZERO_MAX_LEN 64
#define HLL_SPARSE_XZERO_MAX_LEN 16384
#define HLL_SPARSE_VAL_SET(p, val, len)                       \
  do {                                                        \
    *(p) = (((val)-1) << 2 | ((len)-1)) | HLL_SPARSE_VAL_BIT; \
  } while (0)
#define HLL_SPARSE_ZERO_SET(p, len) \
  do {                              \
    *(p) = (len)-1;                 \
  } while (0)
#define HLL_SPARSE_XZERO_SET(p, len)         \
  do {                                       \
    int _l = (len)-1;                        \
    *(p) = (_l >> 8) | HLL_SPARSE_XZERO_BIT; \
    *((p) + 1) = (_l & 0xff);                \
  } while (0)

/* ========================= HyperLogLog algorithm  ========================= */

/* Our hash function is MurmurHash2, 64 bit version.
 * It was modified for Redis in order to provide the same result in
 * big and little endian archs (endian neutral). */
uint64_t MurmurHash64A(const void *key, int len, unsigned int seed) {
  const uint64_t m = 0xc6a4a7935bd1e995;
  const int r = 47;
  uint64_t h = seed ^ (len * m);
  const uint8_t *data = (const uint8_t *)key;
  const uint8_t *end = data + (len - (len & 7));

  while (data != end) {
    uint64_t k;

#if (BYTE_ORDER == LITTLE_ENDIAN)
    k = *((uint64_t *)data);
#else
    k = (uint64_t)data[0];
    k |= (uint64_t)data[1] << 8;
    k |= (uint64_t)data[2] << 16;
    k |= (uint64_t)data[3] << 24;
    k |= (uint64_t)data[4] << 32;
    k |= (uint64_t)data[5] << 40;
    k |= (uint64_t)data[6] << 48;
    k |= (uint64_t)data[7] << 56;
#endif

    k *= m;
    k ^= k >> r;
    k *= m;
    h ^= k;
    h *= m;
    data += 8;
  }

  switch (len & 7) {
    case 7:
      h ^= (uint64_t)data[6] << 48;
    case 6:
      h ^= (uint64_t)data[5] << 40;
    case 5:
      h ^= (uint64_t)data[4] << 32;
    case 4:
      h ^= (uint64_t)data[3] << 24;
    case 3:
      h ^= (uint64_t)data[2] << 16;
    case 2:
      h ^= (uint64_t)data[1] << 8;
    case 1:
      h ^= (uint64_t)data[0];
      h *= m;
  };

  h ^= h >> r;
  h *= m;
  h ^= h >> r;
  return h;
}

/* Given a string element to add to the HyperLogLog, returns the length
 * of the pattern 000..1 of the element hash. As a side effect 'regp' is
 * set to the register index this element hashes to. */
int hllPatLen(unsigned char *ele, size_t elesize, long *regp) {
  uint64_t hash, bit, index;
  int count;

  /* Count the number of zeroes starting from bit HLL_REGISTERS
   * (that is a power of two corresponding to the first bit we don't use
   * as index). The max run can be 64-P+1 bits.
   *
   * Note that the final "1" ending the sequence of zeroes must be
   * included in the count, so if we find "001" the count is 3, and
   * the smallest count possible is no zeroes at all, just a 1 bit
   * at the first position, that is a count of 1.
   *
   * This may sound like inefficient, but actually in the average case
   * there are high probabilities to find a 1 after a few iterations. */
  hash = MurmurHash64A(ele, elesize, 0xadc83b19ULL);
  index = hash & HLL_P_MASK;   /* Register index. */
  hash |= ((uint64_t)1 << 63); /* Make sure the loop terminates. */
  bit = HLL_REGISTERS;         /* First bit not used to address the register. */
  count = 1;                   /* Initialized to 1 since we count the "00000...1" pattern. */
  while ((hash & bit) == 0) {
    count++;
    bit <<= 1;
  }
  *regp = (int)index;
  return count;
}

/* ================== Dense representation implementation  ================== */

/* "Add" the element in the dense hyperloglog data structure.
 * Actually nothing is added, but the max 0 pattern counter of the subset
 * the element belongs to is incremented if needed.
 *
 * 'registers' is expected to have room for HLL_REGISTERS plus an
 * additional byte on the right. This requirement is met by sds strings
 * automatically since they are implicitly null terminated.
 *
 * The function always succeed, however if as a result of the operation
 * the approximated cardinality changed, 1 is returned. Otherwise 0
 * is returned. */
int hllDenseAdd(uint8_t *registers, unsigned char *ele, size_t elesize) {
  uint8_t oldcount, count;
  long index;

  /* Update the register if this element produced a longer run of zeroes. */
  count = hllPatLen(ele, elesize, &index);
  HLL_DENSE_GET_REGISTER(oldcount, registers, index);
  if (count > oldcount) {
    HLL_DENSE_SET_REGISTER(registers, index, count);
    return 1;
  } else {
    return 0;
  }
}

/* Compute SUM(2^-reg) in the dense representation.
 * PE is an array with a pre-computer table of values 2^-reg indexed by reg.
 * As a side effect the integer pointed by 'ezp' is set to the number
 * of zero registers. */
double hllDenseSum(uint8_t *registers, double *PE, int *ezp) {
  double E = 0;
  int j, ez = 0;

  /* Redis default is to use 16384 registers 6 bits each. The code works
   * with other values by modifying the defines, but for our target value
   * we take a faster path with unrolled loops. */
  if (HLL_REGISTERS == 16384 && HLL_BITS == 6) {
    uint8_t *r = registers;
    unsigned long r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15;
    for (j = 0; j < 1024; j++) {
      /* Handle 16 registers per iteration. */
      r0 = r[0] & 63;
      if (r0 == 0) ez++;
      r1 = (r[0] >> 6 | r[1] << 2) & 63;
      if (r1 == 0) ez++;
      r2 = (r[1] >> 4 | r[2] << 4) & 63;
      if (r2 == 0) ez++;
      r3 = (r[2] >> 2) & 63;
      if (r3 == 0) ez++;
      r4 = r[3] & 63;
      if (r4 == 0) ez++;
      r5 = (r[3] >> 6 | r[4] << 2) & 63;
      if (r5 == 0) ez++;
      r6 = (r[4] >> 4 | r[5] << 4) & 63;
      if (r6 == 0) ez++;
      r7 = (r[5] >> 2) & 63;
      if (r7 == 0) ez++;
      r8 = r[6] & 63;
      if (r8 == 0) ez++;
      r9 = (r[6] >> 6 | r[7] << 2) & 63;
      if (r9 == 0) ez++;
      r10 = (r[7] >> 4 | r[8] << 4) & 63;
      if (r10 == 0) ez++;
      r11 = (r[8] >> 2) & 63;
      if (r11 == 0) ez++;
      r12 = r[9] & 63;
      if (r12 == 0) ez++;
      r13 = (r[9] >> 6 | r[10] << 2) & 63;
      if (r13 == 0) ez++;
      r14 = (r[10] >> 4 | r[11] << 4) & 63;
      if (r14 == 0) ez++;
      r15 = (r[11] >> 2) & 63;
      if (r15 == 0) ez++;

      /* Additional parens will allow the compiler to optimize the
       * code more with a loss of precision that is not very relevant
       * here (floating point math is not commutative!). */
      E += (PE[r0] + PE[r1]) + (PE[r2] + PE[r3]) + (PE[r4] + PE[r5]) + (PE[r6] + PE[r7]) + (PE[r8] + PE[r9]) +
           (PE[r10] + PE[r11]) + (PE[r12] + PE[r13]) + (PE[r14] + PE[r15]);
      r += 12;
    }
  } else {
    for (j = 0; j < HLL_REGISTERS; j++) {
      unsigned long reg;

      HLL_DENSE_GET_REGISTER(reg, registers, j);
      if (reg == 0) {
        ez++;
        /* Increment E at the end of the loop. */
      } else {
        E += PE[reg]; /* Precomputed 2^(-reg[j]). */
      }
    }
    E += ez; /* Add 2^0 'ez' times. */
  }
  *ezp = ez;
  return E;
}

/* ================== Sparse representation implementation  ================= */

/* Convert the HLL with sparse representation given as input in its dense
 * representation. Both representations are represented by SDS strings, and
 * the input representation is freed as a side effect.
 *
 * The function returns REDIS_OK if the sparse representation was valid,
 * otherwise REDIS_ERR is returned if the representation was corrupted. */
int hllSparseToDense(sds *value) {
  sds sparse = *value;
  struct hllhdr *hdr, *oldhdr = (struct hllhdr *)sparse;
  int idx = 0, runlen, regval;
  uint8_t *p = (uint8_t *)sparse, *end = p + sdslen(sparse);

  /* If the representation is already the right one return ASAP. */
  hdr = (struct hllhdr *)sparse;
  if (hdr->encoding == HLL_DENSE) return 0;

  /* Create a string of the right size filled with zero bytes.
   * Note that the cached cardinality is set to 0 as a side effect
   * that is exactly the cardinality of an empty HLL. */
  // dense = sdsnewlen(NULL, HLL_DENSE_SIZE);
  sds dense = sdsnewlen(NULL, HLL_DENSE_SIZE);
  hdr = (struct hllhdr *)(&dense[0]);
  *hdr = *oldhdr; /* This will copy the magic and cached cardinality. */
  hdr->encoding = HLL_DENSE;

  /* Now read the sparse representation and set non-zero registers
   * accordingly. */
  p += HLL_HDR_SIZE;
  while (p < end) {
    if (HLL_SPARSE_IS_ZERO(p)) {
      runlen = HLL_SPARSE_ZERO_LEN(p);
      idx += runlen;
      p++;
    } else if (HLL_SPARSE_IS_XZERO(p)) {
      runlen = HLL_SPARSE_XZERO_LEN(p);
      idx += runlen;
      p += 2;
    } else {
      runlen = HLL_SPARSE_VAL_LEN(p);
      regval = HLL_SPARSE_VAL_VALUE(p);
      while (runlen--) {
        HLL_DENSE_SET_REGISTER(hdr->registers, idx, regval);
        idx++;
      }
      p++;
    }
  }

  /* If the sparse representation was valid, we expect to find idx
   * set to HLL_REGISTERS. */
  if (idx != HLL_REGISTERS) {
    return -1;
  }

  /* Free the old representation and set the new one. */
  sdsfree(*value);
  *value = dense;
  return 0;
}

/* "Add" the element in the sparse hyperloglog data structure.
 * Actually nothing is added, but the max 0 pattern counter of the subset
 * the element belongs to is incremented if needed.
 *
 * The object 'o' is the String object holding the HLL. The function requires
 * a reference to the object in order to be able to enlarge the string if
 * needed.
 *
 * On success, the function returns 1 if the cardinality changed, or 0
 * if the register for this element was not updated.
 * On error (if the representation is invalid) -1 is returned.
 *
 * As a side effect the function may promote the HLL representation from
 * sparse to dense: this happens when a register requires to be set to a value
 * not representable with the sparse representation, or when the resulting
 * size would be greater than server.hll_sparse_max_bytes. */
int hllSparseAdd(sds *value, unsigned char *ele, size_t elesize, uint32_t hll_sparse_max_bytes) {
  struct hllhdr *hdr;
  uint8_t oldcount, count, *sparse, *end, *p, *prev, *next;
  long index, first, span;
  long is_zero = 0, is_xzero = 0, is_val = 0, runlen = 0;
  int scanlen;
  int seqlen;
  int oldlen;
  int deltalen;
  int last;
  int len;
  uint8_t seq[5], *n;

  /* Update the register if this element produced a longer run of zeroes. */
  count = hllPatLen(ele, elesize, &index);

  /* If the count is too big to be representable by the sparse representation
   * switch to dense representation. */
  if (count > HLL_SPARSE_VAL_MAX_VALUE) goto promote;

  /* When updating a sparse representation, sometimes we may need to
   * enlarge the buffer for up to 3 bytes in the worst case (XZERO split
   * into XZERO-VAL-XZERO). Make sure there is enough space right now
   * so that the pointers we take during the execution of the function
   * will be valid all the time. */
  *value = sdsMakeRoomFor(*value, 3);

  /* Step 1: we need to locate the opcode we need to modify to check
   * if a value update is actually needed. */
  sparse = p = ((uint8_t *)(*value)) + HLL_HDR_SIZE;
  end = p + sdslen(*value) - HLL_HDR_SIZE;

  first = 0;
  prev = NULL; /* Points to previos opcode at the end of the loop. */
  next = NULL; /* Points to the next opcode at the end of the loop. */
  span = 0;
  while (p < end) {
    long oplen;

    /* Set span to the number of registers covered by this opcode.
     *
     * This is the most performance critical loop of the sparse
     * representation. Sorting the conditionals from the most to the
     * least frequent opcode in many-bytes sparse HLLs is faster. */
    oplen = 1;
    if (HLL_SPARSE_IS_ZERO(p)) {
      span = HLL_SPARSE_ZERO_LEN(p);
    } else if (HLL_SPARSE_IS_VAL(p)) {
      span = HLL_SPARSE_VAL_LEN(p);
    } else { /* XZERO. */
      span = HLL_SPARSE_XZERO_LEN(p);
      oplen = 2;
    }
    /* Break if this opcode covers the register as 'index'. */
    if (index <= first + span - 1) break;
    prev = p;
    p += oplen;
    first += span;
  }
  if (span == 0) return -1; /* Invalid format. */

  next = HLL_SPARSE_IS_XZERO(p) ? p + 2 : p + 1;
  if (next >= end) next = NULL;

  /* Cache current opcode type to avoid using the macro again and
   * again for something that will not change.
   * Also cache the run-length of the opcode. */
  if (HLL_SPARSE_IS_ZERO(p)) {
    is_zero = 1;
    runlen = HLL_SPARSE_ZERO_LEN(p);
  } else if (HLL_SPARSE_IS_XZERO(p)) {
    is_xzero = 1;
    runlen = HLL_SPARSE_XZERO_LEN(p);
  } else {
    is_val = 1;
    runlen = HLL_SPARSE_VAL_LEN(p);
  }

  /* Step 2: After the loop:
   *
   * 'first' stores to the index of the first register covered
   *  by the current opcode, which is pointed by 'p'.
   *
   * 'next' ad 'prev' store respectively the next and previous opcode,
   *  or NULL if the opcode at 'p' is respectively the last or first.
   *
   * 'span' is set to the number of registers covered by the current
   *  opcode.
   *
   * There are different cases in order to update the data structure
   * in place without generating it from scratch:
   *
   * A) If it is a VAL opcode already set to a value >= our 'count'
   *    no update is needed, regardless of the VAL run-length field.
   *    In this case PFADD returns 0 since no changes are performed.
   *
   * B) If it is a VAL opcode with len = 1 (representing only our
   *    register) and the value is less than 'count', we just update it
   *    since this is a trivial case. */
  if (is_val) {
    oldcount = HLL_SPARSE_VAL_VALUE(p);
    /* Case A. */
    if (oldcount >= count) return 0;

    /* Case B. */
    if (runlen == 1) {
      HLL_SPARSE_VAL_SET(p, count, 1);
      goto updated;
    }
  }

  /* C) Another trivial to handle case is a ZERO opcode with a len of 1.
   * We can just replace it with a VAL opcode with our value and len of 1. */
  if (is_zero && runlen == 1) {
    HLL_SPARSE_VAL_SET(p, count, 1);
    goto updated;
  }

  /* D) General case.
   *
   * The other cases are more complex: our register requires to be updated
   * and is either currently represented by a VAL opcode with len > 1,
   * by a ZERO opcode with len > 1, or by an XZERO opcode.
   *
   * In those cases the original opcode must be split into muliple
   * opcodes. The worst case is an XZERO split in the middle resuling into
   * XZERO - VAL - XZERO, so the resulting sequence max length is
   * 5 bytes.
   *
   * We perform the split writing the new sequence into the 'new' buffer
   * with 'newlen' as length. Later the new sequence is inserted in place
   * of the old one, possibly moving what is on the right a few bytes
   * if the new sequence is longer than the older one. */
  n = seq;
  last = first + span - 1; /* Last register covered by the sequence. */
  // int len;

  if (is_zero || is_xzero) {
    /* Handle splitting of ZERO / XZERO. */
    if (index != first) {
      len = index - first;
      if (len > HLL_SPARSE_ZERO_MAX_LEN) {
        HLL_SPARSE_XZERO_SET(n, len);
        n += 2;
      } else {
        HLL_SPARSE_ZERO_SET(n, len);
        n++;
      }
    }
    HLL_SPARSE_VAL_SET(n, count, 1);
    n++;
    if (index != last) {
      len = last - index;
      if (len > HLL_SPARSE_ZERO_MAX_LEN) {
        HLL_SPARSE_XZERO_SET(n, len);
        n += 2;
      } else {
        HLL_SPARSE_ZERO_SET(n, len);
        n++;
      }
    }
  } else {
    /* Handle splitting of VAL. */
    int curval = HLL_SPARSE_VAL_VALUE(p);

    if (index != first) {
      len = index - first;
      HLL_SPARSE_VAL_SET(n, curval, len);
      n++;
    }
    HLL_SPARSE_VAL_SET(n, count, 1);
    n++;
    if (index != last) {
      len = last - index;
      HLL_SPARSE_VAL_SET(n, curval, len);
      n++;
    }
  }

  /* Step 3: substitute the new sequence with the old one.
   *
   * Note that we already allocated space on the sds string
   * calling sdsMakeRoomFor(). */
  seqlen = n - seq;
  oldlen = is_xzero ? 2 : 1;
  deltalen = seqlen - oldlen;

  if (deltalen > 0 && sdslen(*value) + deltalen > hll_sparse_max_bytes) goto promote;
  if (deltalen && next) memmove(next + deltalen, next, end - next);
  sdsIncrLen(*value, deltalen);
  memcpy(p, seq, seqlen);
  end += deltalen;

updated:
  /* Step 4: Merge adjacent values if possible.
   *
   * The representation was updated, however the resulting representation
   * may not be optimal: adjacent VAL opcodes can sometimes be merged into
   * a single one. */
  p = prev ? prev : sparse;
  scanlen = 5; /* Scan up to 5 upcodes starting from prev. */
  while (p < end && scanlen--) {
    if (HLL_SPARSE_IS_XZERO(p)) {
      p += 2;
      continue;
    } else if (HLL_SPARSE_IS_ZERO(p)) {
      p++;
      continue;
    }
    /* We need two adjacent VAL opcodes to try a merge, having
     * the same value, and a len that fits the VAL opcode max len. */
    if (p + 1 < end && HLL_SPARSE_IS_VAL(p + 1)) {
      int v1 = HLL_SPARSE_VAL_VALUE(p);
      int v2 = HLL_SPARSE_VAL_VALUE(p + 1);
      if (v1 == v2) {
        int len = HLL_SPARSE_VAL_LEN(p) + HLL_SPARSE_VAL_LEN(p + 1);
        if (len <= HLL_SPARSE_VAL_MAX_LEN) {
          HLL_SPARSE_VAL_SET(p + 1, v1, len);
          memmove(p, p + 1, end - p);
          sdsIncrLen(*value, -1);
          end--;
          /* After a merge we reiterate without incrementing 'p'
           * in order to try to merge the just merged value with
           * a value on its right. */
          continue;
        }
      }
    }
    p++;
  }

  /* Invalidate the cached cardinality. */
  hdr = (struct hllhdr *)(*value);
  HLL_INVALIDATE_CACHE(hdr);
  return 1;

promote:                                        /* Promote to dense representation. */
  if (hllSparseToDense(value) == -1) return -1; /* Corrupted HLL. */
  hdr = (struct hllhdr *)(*value);

  /* We need to call hllDenseAdd() to perform the operation after the
   * conversion. However the result must be 1, since if we need to
   * convert from sparse to dense a register requires to be updated.
   *
   * Note that this in turn means that PFADD will make sure the command
   * is propagated to slaves / AOF, so if there is a sparse -> dense
   * convertion, it will be performed in all the slaves as well. */
  int dense_retval = hllDenseAdd(hdr->registers, ele, elesize);
  // ASSERT(dense_retval == 1);
  return dense_retval;
}

/* Compute SUM(2^-reg) in the sparse representation.
 * PE is an array with a pre-computer table of values 2^-reg indexed by reg.
 * As a side effect the integer pointed by 'ezp' is set to the number
 * of zero registers. */
double hllSparseSum(uint8_t *sparse, int sparselen, double *PE, int *ezp, int *invalid) {
  double E = 0;
  int ez = 0, idx = 0, runlen, regval;
  uint8_t *end = sparse + sparselen, *p = sparse;

  while (p < end) {
    if (HLL_SPARSE_IS_ZERO(p)) {
      runlen = HLL_SPARSE_ZERO_LEN(p);
      idx += runlen;
      ez += runlen;
      /* Increment E at the end of the loop. */
      p++;
    } else if (HLL_SPARSE_IS_XZERO(p)) {
      runlen = HLL_SPARSE_XZERO_LEN(p);
      idx += runlen;
      ez += runlen;
      /* Increment E at the end of the loop. */
      p += 2;
    } else {
      runlen = HLL_SPARSE_VAL_LEN(p);
      regval = HLL_SPARSE_VAL_VALUE(p);
      idx += runlen;
      E += PE[regval] * runlen;
      p++;
    }
  }

  if (idx != HLL_REGISTERS && invalid) {
    *invalid = 1;
  }
  E += ez; /* Add 2^0 'ez' times. */
  *ezp = ez;
  return E;
}

/* ========================= HyperLogLog Count ==============================
 * This is the core of the algorithm where the approximated count is computed.
 * The function uses the lower level hllDenseSum() and hllSparseSum() functions
 * as helpers to compute the SUM(2^-reg) part of the computation, which is
 * representation-specific, while all the rest is common. */

/* Implements the SUM operation for uint8_t data type which is only used
 * internally as speedup for PFCOUNT with multiple keys. */
double hllRawSum(uint8_t *registers, double *PE, int *ezp) {
  double E = 0;
  int j, ez = 0;
  uint64_t *word = (uint64_t *)registers;
  uint8_t *bytes;

  for (j = 0; j < HLL_REGISTERS / 8; j++) {
    if (*word == 0) {
      ez += 8;
    } else {
      bytes = (uint8_t *)word;
      if (bytes[0])
        E += PE[bytes[0]];
      else
        ez++;
      if (bytes[1])
        E += PE[bytes[1]];
      else
        ez++;
      if (bytes[2])
        E += PE[bytes[2]];
      else
        ez++;
      if (bytes[3])
        E += PE[bytes[3]];
      else
        ez++;
      if (bytes[4])
        E += PE[bytes[4]];
      else
        ez++;
      if (bytes[5])
        E += PE[bytes[5]];
      else
        ez++;
      if (bytes[6])
        E += PE[bytes[6]];
      else
        ez++;
      if (bytes[7])
        E += PE[bytes[7]];
      else
        ez++;
    }
    word++;
  }
  E += ez; /* 2^(-reg[j]) is 1 when m is 0, add it 'ez' times for every
   zero register in the HLL. */
  *ezp = ez;
  return E;
}

/* Return the approximated cardinality of the set based on the armonic
 * mean of the registers values. 'hdr' points to the start of the SDS
 * representing the String object holding the HLL representation.
 *
 * If the sparse representation of the HLL object is not valid, the integer
 * pointed by 'invalid' is set to non-zero, otherwise it is left untouched.
 *
 * hllCount() supports a special internal-only encoding of HLL_RAW, that
 * is, hdr->registers will point to an uint8_t array of HLL_REGISTERS element.
 * This is useful in order to speedup PFCOUNT when called against multiple
 * keys (no need to work with 6-bit integers encoding). */
uint64_t hllCount(struct hllhdr *hdr, uint32_t slen, int *invalid) {
  double m = HLL_REGISTERS;
  double E, alpha = 0.7213 / (1 + 1.079 / m);
  int j, ez; /* Number of registers equal to 0. */

  /* We precompute 2^(-reg[j]) in a small table in order to
   * speedup the computation of SUM(2^-register[0..i]). */
  static int initialized = 0;
  static double PE[64];
  if (!initialized) {
    PE[0] = 1; /* 2^(-reg[j]) is 1 when m is 0. */
    for (j = 1; j < 64; j++) {
      /* 2^(-reg[j]) is the same as 1/2^reg[j]. */
      PE[j] = 1.0 / (1ULL << j);
    }
    initialized = 1;
  }

  /* Compute SUM(2^-register[0..i]). */
  if (hdr->encoding == HLL_DENSE) {
    E = hllDenseSum(hdr->registers, PE, &ez);
  } else if (hdr->encoding == HLL_SPARSE) {
    E = hllSparseSum(hdr->registers, slen - HLL_HDR_SIZE, PE, &ez, invalid);
  } else if (hdr->encoding == HLL_RAW) {
    E = hllRawSum(hdr->registers, PE, &ez);
  } else {
    // redisPanic("Unknown HyperLogLog encoding in hllCount()");
    abort();
  }

  /* Muliply the inverse of E for alpha_m * m^2 to have the raw estimate. */
  E = (1 / E) * alpha * m * m;

  /* Use the LINEARCOUNTING algorithm for small cardinalities.
   * For larger values but up to 72000 HyperLogLog raw approximation is
   * used since linear counting error starts to increase. However HyperLogLog
   * shows a strong bias in the range 2.5*16384 - 72000, so we try to
   * compensate for it. */
  if (E < m * 2.5 && ez != 0) {
    E = m * log(m / ez); /* LINEARCOUNTING() */
  } else if (m == 16384 && E < 72000) {
    /* We did polynomial regression of the bias for this range, this
     * way we can compute the bias for a given cardinality and correct
     * according to it. Only apply the correction for P=14 that's what
     * we use and the value the correction was verified with. */
    double bias = 5.9119 * 1.0e-18 * (E * E * E * E) - 1.4253 * 1.0e-12 * (E * E * E) + 1.2940 * 1.0e-7 * (E * E) -
                  5.2921 * 1.0e-3 * E + 83.3216;
    E -= E * (bias / 100);
  }
  /* We don't apply the correction for E > 1/30 of 2^32 since we use
   * a 64 bit function and 6 bit counters. To apply the correction for
   * 1/30 of 2^64 is not needed since it would require a huge set
   * to approach such a value. */
  return (uint64_t)E;
}

/* Call hllDenseAdd() or hllSparseAdd() according to the HLL encoding. */
int hllAdd(std::string &value, unsigned char *ele, size_t elesize, uint32_t hll_sparse_max_bytes) {
  struct hllhdr *hdr = (struct hllhdr *)(&value[0]);
  switch (hdr->encoding) {
    case HLL_DENSE:
      return hllDenseAdd(hdr->registers, ele, elesize);
    case HLL_SPARSE: {
      sds v = sdsnewlen(value.data(), value.size());
      int retval = hllSparseAdd(&v, ele, elesize, hll_sparse_max_bytes);
      if (retval > 0) {
        value.clear();
        value.append(v, sdslen(v));
        sdsfree(v);
      }
      return retval;
    }
    default:
      return -1; /* Invalid representation. */
  }
}

/* Merge by computing MAX(registers[i],hll[i]) the HyperLogLog 'hll'
 * with an array of uint8_t HLL_REGISTERS registers pointed by 'max'.
 *
 * The hll object must be already validated via isHLLObjectOrReply()
 * or in some other way.
 *
 * If the HyperLogLog is sparse and is found to be invalid, REDIS_ERR
 * is returned, otherwise the function always succeeds. */
int hllMerge(uint8_t *max, std::string &hll) {
  struct hllhdr *hdr = (struct hllhdr *)&(hll[0]);
  int i;

  if (hdr->encoding == HLL_DENSE) {
    uint8_t val;

    for (i = 0; i < HLL_REGISTERS; i++) {
      HLL_DENSE_GET_REGISTER(val, hdr->registers, i);
      if (val > max[i]) max[i] = val;
    }
  } else {
    uint8_t *p = (uint8_t *)&(hll[0]), *end = p + hll.size();
    long runlen, regval;

    p += HLL_HDR_SIZE;
    i = 0;
    while (p < end) {
      if (HLL_SPARSE_IS_ZERO(p)) {
        runlen = HLL_SPARSE_ZERO_LEN(p);
        i += runlen;
        p++;
      } else if (HLL_SPARSE_IS_XZERO(p)) {
        runlen = HLL_SPARSE_XZERO_LEN(p);
        i += runlen;
        p += 2;
      } else {
        runlen = HLL_SPARSE_VAL_LEN(p);
        regval = HLL_SPARSE_VAL_VALUE(p);
        while (runlen--) {
          if (regval > max[i]) max[i] = regval;
          i++;
        }
        p++;
      }
    }
    if (i != HLL_REGISTERS) return -1;
  }
  return 0;
}

/* ========================== HyperLogLog commands ========================== */
/* Create an HLL object. We always create the HLL using sparse encoding.
 * This will be upgraded to the dense representation as needed. */
void createHLLObject(std::string &value) {
  struct hllhdr *hdr;
  uint8_t *p;
  int sparselen = HLL_HDR_SIZE + (((HLL_REGISTERS + (HLL_SPARSE_XZERO_MAX_LEN - 1)) / HLL_SPARSE_XZERO_MAX_LEN) * 2);
  int aux;

  /* Populate the sparse representation with as many XZERO opcodes as
   * needed to represent all the registers. */
  aux = HLL_REGISTERS;
  // s = sdsnewlen(NULL, sparselen);
  value.resize(sparselen);
  p = (uint8_t *)(&value[0]) + HLL_HDR_SIZE;
  while (aux) {
    int xzero = HLL_SPARSE_XZERO_MAX_LEN;
    if (xzero > aux) xzero = aux;
    HLL_SPARSE_XZERO_SET(p, xzero);
    p += 2;
    aux -= xzero;
  }
  // redisAssert((p - (uint8_t*) s) == sparselen);

  /* Create the actual object. */
  // o = createObject(REDIS_STRING, s);
  hdr = (struct hllhdr *)(&value[0]);
  memcpy(hdr->magic, "HYLL", 4);
  hdr->encoding = HLL_SPARSE;
}

/* Check if the object is a String with a valid HLL representation.
 * Return REDIS_OK if this is true, otherwise reply to the client
 * with an error and return REDIS_ERR. */
bool isHLLObjectOrReply(std::string &value) {
  struct hllhdr *hdr;
  if (value.size() < sizeof(*hdr)) goto invalid;
  hdr = (struct hllhdr *)(&value[0]);

  /* Magic should be "HYLL". */
  if (hdr->magic[0] != 'H' || hdr->magic[1] != 'Y' || hdr->magic[2] != 'L' || hdr->magic[3] != 'L') goto invalid;

  if (hdr->encoding > HLL_MAX_ENCODING) goto invalid;

  /* Dense representation string length should match exactly. */
  if (hdr->encoding == HLL_DENSE && value.size() != HLL_DENSE_SIZE) goto invalid;

  /* All tests passed. */
  return true;
invalid:
  //    invalid: addReplySds(c, sdsnew("-WRONGTYPE Key is not a valid "
  //            "HyperLogLog string value.\r\n"));
  return false;
}
rocksdb::Status HyperLogLog::PFAdd(const Slice &user_key, const Slice &member) {
  std::string ns_key;
  AppendNamespacePrefix(user_key, &ns_key);

  LockGuard guard(storage_->GetLockManager(), ns_key);
  std::string hllObj;
  rocksdb::Status s = getValue(ns_key, &hllObj);
  if (!s.IsNotFound() && !s.ok()) return s;

  bool createdHll = false;
  if (s.IsNotFound()) {
    createHLLObject(hllObj);
    createdHll = true;
  }

  int ret = Redis::hllAdd(hllObj, (unsigned char *)(member.data()), member.size(), hll_sparse_max_bytes);

  if (-1 == ret) {
    // error..
    return rocksdb::Status::Corruption("corruption hyperloglog obj");
  }
  struct hllhdr *hdr = (struct hllhdr *)(&hllObj[0]);

  std::string value_bytes;

  HyperloglogMetadata metadata(false);
  metadata.Encode(&value_bytes);

  value_bytes.append(hllObj.data(), hllObj.size());

  if (createdHll) {
    HLL_INVALIDATE_CACHE(hdr);
  }

  auto batch = storage_->GetWriteBatchBase();
  WriteBatchLogData log_data(kRedisHyperLogLog);
  batch->PutLogData(log_data.Encode());
  batch->Put(metadata_cf_handle_, ns_key, value_bytes);
  s = storage_->Write(storage_->DefaultWriteOptions(), batch->GetWriteBatch());
  return s;
}

rocksdb::Status HyperLogLog::getValue(const std::string &ns_key, std::string *raw_value) {
  rocksdb::ReadOptions read_options;
  // reading one cf for hll didn't need a snapshot
  // LatestSnapShot ss(storage_);
  // read_options.snapshot = ss.GetSnapShot();
  rocksdb::Status s = storage_->Get(read_options, metadata_cf_handle_, ns_key, raw_value);
  if (!s.ok()) return s;

  HyperloglogMetadata metadata(false);
  s = metadata.DecodeAndRemovePrefix(raw_value);
  if (metadata.Expired()) {
    raw_value->clear();
    return rocksdb::Status::NotFound(kErrMsgKeyExpired);
  }
  if (metadata.Type() != kRedisHyperLogLog && metadata.size > 0) {
    return rocksdb::Status::InvalidArgument(kErrMsgWrongType);
  }
  return rocksdb::Status::OK();
}

int HyperLogLog::PFCount(const Slice &user_key) {
  std::string ns_key;
  AppendNamespacePrefix(user_key, &ns_key);
  std::string hllObj;
  rocksdb::Status s = getValue(ns_key, &hllObj);
  if (s.IsNotFound() || !s.ok()) {
    return 0;
  }

  if (!isHLLObjectOrReply(hllObj)) {
    // TODO
    // reply.SetErrCode(ERR_INVALID_HLL_STRING);
    return 0;
  }
  struct hllhdr *hdr;
  uint64_t card = 0;

  /* Check if the cached cardinality is valid. */
  hdr = (struct hllhdr *)(&hllObj[0]);
  if (HLL_VALID_CACHE(hdr)) {
    /* Just return the cached value. */
    card = (uint64_t)hdr->card[0];
    card |= (uint64_t)hdr->card[1] << 8;
    card |= (uint64_t)hdr->card[2] << 16;
    card |= (uint64_t)hdr->card[3] << 24;
    card |= (uint64_t)hdr->card[4] << 32;
    card |= (uint64_t)hdr->card[5] << 40;
    card |= (uint64_t)hdr->card[6] << 48;
    card |= (uint64_t)hdr->card[7] << 56;
  } else {
    int invalid = 0;
    /* Recompute it and update the cached value. */
    card = hllCount(hdr, hllObj.size(), &invalid);
    if (invalid) {
      // reply.SetErrCode(ERR_CORRUPTED_HLL_OBJECT);
      return 0;
    }
    hdr->card[0] = card & 0xff;
    hdr->card[1] = (card >> 8) & 0xff;
    hdr->card[2] = (card >> 16) & 0xff;
    hdr->card[3] = (card >> 24) & 0xff;
    hdr->card[4] = (card >> 32) & 0xff;
    hdr->card[5] = (card >> 40) & 0xff;
    hdr->card[6] = (card >> 48) & 0xff;
    hdr->card[7] = (card >> 56) & 0xff;
    /* This is not considered a read-only command even if the
     * data structure is not modified, since the cached value
     * may be modified and given that the HLL is a Redis string
     * we need to propagate the change. */
    // signalModifiedKey(c->db, c->argv[1]);
    // server.dirty++;
    auto batch = storage_->GetWriteBatchBase();
    WriteBatchLogData log_data(kRedisHyperLogLog);
    batch->PutLogData(log_data.Encode());

    std::string value_bytes;
    HyperloglogMetadata metadata(false);
    metadata.Encode(&value_bytes);
    value_bytes.append(hllObj.data(), hllObj.size());
    batch->Put(metadata_cf_handle_, ns_key, value_bytes);
    s = storage_->Write(storage_->DefaultWriteOptions(), batch->GetWriteBatch());
    return card;
  }

  return card;
}

std::vector<rocksdb::Status> HyperLogLog::getValues(const std::vector<Slice> &user_keys,
                                                    std::vector<std::string> *values) {
  std::vector<string> ns_keys_holder;
  std::vector<Slice> ns_keys;
  ns_keys.reserve(user_keys.size());
  for (const auto &item : user_keys) {
    string ns_key;
    AppendNamespacePrefix(item, &ns_key);
    ns_keys_holder.emplace_back(ns_key);
  }
  for (const auto &item : ns_keys_holder) {
    ns_keys.emplace_back(item);
  }

  values->clear();

  rocksdb::ReadOptions read_options;
  LatestSnapShot ss(storage_);
  read_options.snapshot = ss.GetSnapShot();
  values->resize(ns_keys.size());
  std::vector<rocksdb::Status> statuses(ns_keys.size());
  std::vector<rocksdb::PinnableSlice> pin_values(ns_keys.size());
  storage_->MultiGet(read_options, metadata_cf_handle_, ns_keys.size(), ns_keys.data(), pin_values.data(),
                     statuses.data());
  for (size_t i = 0; i < ns_keys.size(); i++) {
    if (!statuses[i].ok()) {
      Debug << i << " " << statuses[i].ToString() << endl;
      continue;
    }
    (*values)[i].assign(pin_values[i].data(), pin_values[i].size());
    HyperloglogMetadata metadata(false);
    if (metadata.Expired()) {
      (*values)[i].clear();
      statuses[i] = rocksdb::Status::NotFound(kErrMsgKeyExpired);
      continue;
    }
    if (metadata.Type() != kRedisHyperLogLog) {
      (*values)[i].clear();
      statuses[i] = rocksdb::Status::InvalidArgument(kErrMsgWrongType);
      continue;
    }
    auto s = metadata.DecodeAndRemovePrefix(&(*values)[i]);
    if (!s.ok()) {
      statuses[i] = rocksdb::Status::Corruption("corruption hll Slice");
      (*values)[i].clear();
      continue;
    }
  }
  return statuses;
}

rocksdb::Status HyperLogLog::PFMerge(const std::vector<Slice> &user_keys) {
  vector<string> values;
  auto vStatus = getValues(user_keys, &values);

  uint8_t max[HLL_REGISTERS];
  /* Compute an HLL with M[i] = MAX(M[i]_j).
   * We we the maximum into the max array of registers. We'll write
   * it to the target variable later. */
  memset(max, 0, sizeof(max));

  for (size_t i = 0; i < values.size(); i++) {
    if (!vStatus[i].ok()) {
      Debug << i << " something wrong:" << vStatus[i].ToString() << endl;
      continue;
    }
    // if some merge key isnot hll obj,just continue;
    if (!isHLLObjectOrReply(values[i])) {
      // TODO log
      Debug << i << " not hll obj:" << vStatus[i].ToString() << endl;
      continue;
    }
    /* Merge with this HLL with our 'max' HHL by setting max[i] to MAX(max[i],hll[i]). */
    if (hllMerge(max, values[i]) == -1) {
      Debug << i << " merge failed" << endl;
      continue;
    }
  }
  if (vStatus.empty() || !vStatus[0].ok()) {
    return rocksdb::Status::Corruption("Corruption hll");
  }

  // merge all value to userkey[0];

  /* Only support dense objects as destination. */
  sds hlls = sdsnewlen(values[0].data(), values[0].size());
  if (hllSparseToDense(&hlls) == -1) {
    sdsfree(hlls);
    return rocksdb::Status::Corruption("Corruption hll");
  }

  /* Write the resulting HLL to the destination HLL registers and
   * invalidate the cached value. */
  struct hllhdr *hdr = (struct hllhdr *)hlls;
  for (uint32_t j = 0; j < HLL_REGISTERS; j++) {
    HLL_DENSE_SET_REGISTER(hdr->registers, j, max[j]);
  }
  HLL_INVALIDATE_CACHE(hdr);
  values[0].clear();
  values[0].append(hlls, sdslen(hlls));
  sdsfree(hlls);

  auto batch = storage_->GetWriteBatchBase();
  WriteBatchLogData log_data(kRedisHyperLogLog);
  batch->PutLogData(log_data.Encode());

  std::string value_bytes;
  HyperloglogMetadata metadata(false);
  metadata.Encode(&value_bytes);
  value_bytes.append(values[0].data(), values[0].size());

  string ns_key_target;
  AppendNamespacePrefix(user_keys[0], &ns_key_target);
  batch->Put(metadata_cf_handle_, ns_key_target, value_bytes);
  auto s = storage_->Write(storage_->DefaultWriteOptions(), batch->GetWriteBatch());

  return s;
}

}  // namespace Redis