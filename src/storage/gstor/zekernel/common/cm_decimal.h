/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * openGauss is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cm_decimal.h
 *    The head file of two DECIMAL types: dec4_t and dec8_t. The former
 * has a compact format, and is designed for storage. Whereas the latter has an
 * efficient structure, and thus can be applied for numeric computation.
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_decimal.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CM_NUMBER_H_
#define __CM_NUMBER_H_

#include "cm_dec8.h"

extern const uint32 g_1ten_powers[];
extern const uint32 g_5ten_powers[];

#ifdef __cplusplus
extern "C" {
#endif

/* Truncate tailing *prec* number of digits of an int64 into zeros.
 * e.g., cm_truncate_bigint(123123, 3) ==> 123000
 *   cm_truncate_bigint(123623, 3) ==> 124000
 * @note prec can not exceed 9  */
static inline int64 cm_truncate_bigint(int64 val, uint32 prec)
{
    if (val >= 0) {
        val += g_5ten_powers[prec];  // for round
    } else {
        val -= g_5ten_powers[prec];  // for round
    }

    return (val / g_1ten_powers[prec]) * g_1ten_powers[prec];
}

/*
 * Count the number of 10-base digits of an uint16.
 * e.g. 451 ==> 3, 12 ==> 2, abs(-100) ==> 3, 0 ==> 1, 1 ==> 1
 */
static inline uint32 cm_count_u16digits(uint16 u16)
{
    // Binary search
    if (u16 >= 1000u) {
        return (uint32)((u16 >= 10000u) ? 5 : 4);
    }

    return (uint32)((u16 >= 100u) ? 3 : ((u16 >= 10u) ? 2 : 1));
}

static inline uint32 cm_count_u32digits(uint32 u32)
{
    // Binary search
    if (u32 >= 100000u) {
        if (u32 >= 10000000u) {
            return (uint32)((u32 < 100000000u) ? 8 : ((u32 >= 1000000000u) ? 10 : 9));
        }
        return (uint32)((u32 >= 1000000u) ? 7 : 6);
    }

    if (u32 >= 1000u) {
        return (uint32)((u32 >= 10000u) ? 5 : 4);
    }

    return (uint32)((u32 >= 100u) ? 3 : ((u32 >= 10u) ? 2 : 1));
}

static inline double cm_round_real(double val, round_mode_t mode)
{
    switch (mode) {
        case ROUND_TRUNC:
            return trunc(val);

        case ROUND_CEILING:
            return ceil(val);

        case ROUND_FLOOR:
            return floor(val);

        case ROUND_HALF_UP:
            return round(val);
        default:
            CM_NEVER;
            return 0;
    }
}

/**
 * Convert a single cell text into uint32. A single cell text is a text of
 * digits, with the number of text is no more than 9
 * @author Added, 2018/04/16
 */
static inline uint32 cm_celltext2uint32(const text_t *cellt)
{
    uint32 val = 0;

    for (uint32 i = 0; i < cellt->len; ++i) {
        val = val * 10 + (uint32)(uint8)CM_C2D(cellt->str[i]);
    }

    return val;
}

/*
 * Decode a decimal from a void data with size
 */
static inline status_t cm_dec_4_to_8(dec8_t *d8, const dec4_t *d4, uint32 sz_byte)
{
    if (sz_byte == 0) {
        cm_zero_dec8(d8);
        return GS_SUCCESS;
    }
    // check validation again
    if ((uint32)(cm_dec4_stor_sz(d4)) > sz_byte) {
        GS_THROW_ERROR_EX(ERR_ASSERT_ERROR, "cm_dec4_stor_sz(d4)(%u) <= sz_byte(%u)",
                          (uint32)(cm_dec4_stor_sz(d4)), sz_byte);
        return GS_ERROR;
    }
    if (DECIMAL_IS_ZERO(d4)) {
        cm_zero_dec8(d8);
        return GS_SUCCESS;
    }

    uint32 i4 = 0;
    uint32 i8 = 0;
    d8->sign = d4->sign;

    if (d4->expn < 0) {
        d8->expn = (d4->expn - 1) / 2;
    } else {
        d8->expn = d4->expn / 2;
    }

    if (d4->expn % 2 == 0) {
        d8->cells[0] = d4->cells[0];
        i4 = 1;
        i8 = 1;
    }

    for (; i4 < d4->ncells && i4 < DEC4_CELL_SIZE - 1; i4 += 2, i8++) {
        d8->cells[i8] = (c8typ_t)d4->cells[i4] * DEC4_CELL_MASK;
        if (i4 + 1 < d4->ncells) {
            d8->cells[i8] += d4->cells[i4 + 1];
        }
    }
    d8->ncells = i8;
    cm_dec8_trim_zeros(d8);
    return GS_SUCCESS;
}

static inline status_t cm_dec_8_to_4(dec4_t *d4, const dec8_t *d8)
{
    if (DECIMAL_IS_ZERO(d8)) {
        cm_zero_dec4(d4);
        return GS_SUCCESS;
    }

    int16 expn = DEC8_GET_SEXP(d8);
    if (expn > MAX_NUMERIC_EXPN) {
        GS_THROW_ERROR(ERR_NUM_OVERFLOW);
        return GS_ERROR;
    } else if (expn < MIN_NUMERIC_EXPN) {
        cm_zero_dec4(d4);
        return GS_SUCCESS;
    }

    uint32 i8 = 0;
    uint32 i4 = 0;

    d4->sign = d8->sign;
    d4->expn = (int8)(d8->expn * 2 + 1);
    if (d8->cells[0] < DEC4_CELL_MASK) {
        d4->cells[0] = (c4typ_t)d8->cells[0];
        d4->expn--;
        i4++;
        i8++;
    }

    for (; i8 < d8->ncells && i4 < DEC4_CELL_SIZE - 1; i8++, i4 += 2) {
        d4->cells[i4] = d8->cells[i8] / DEC4_CELL_MASK;
        d4->cells[i4 + 1] = d8->cells[i8] % DEC4_CELL_MASK;
    }

    // remove tailing zero if exits
    if (d4->cells[i4 - 1] == 0) {
        i4--;
    }
    d4->ncells = (uint8)i4;
    return GS_SUCCESS;
}

/* The actual bytes of a dec8 in storage */
static inline uint32 cm_dec8_stor_sz(const dec8_t *d8)
{
    dec4_t d4;
    (void)cm_dec_8_to_4(&d4, d8);
    return cm_dec4_stor_sz(&d4);
}

static inline status_t cm_adjust_double(double *val, int32 precision, int32 scale)
{
    if (precision == GS_UNSPECIFIED_NUM_PREC) {
        return GS_SUCCESS;
    }

    dec8_t dec;
    GS_RETURN_IFERR(cm_real_to_dec8(*val, &dec));
    GS_RETURN_IFERR(cm_adjust_dec8(&dec, precision, scale));

    *val = cm_dec8_to_real(&dec);
    return GS_SUCCESS;
}

/* The arithmetic operations among DECIMAL and BIGINT */
static inline status_t cm_dec8_add_int64(const dec8_t *dec, int64 i64, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_add(dec, &i64_dec, result);
}

static inline status_t cm_dec8_add_int32(const dec8_t *dec, int32 i32, dec8_t *result)
{
    dec8_t i32_dec;
    cm_int64_to_dec8(i32, &i32_dec);
    return cm_dec8_add(dec, &i32_dec, result);
}

#define cm_int64_add_dec8(i64, dec, result) cm_dec8_add_int64((dec), (i64), (result))
#define cm_dec8_sub_int64(dec, i64, result) cm_dec8_add_int64((dec), (-(i64)), (result))

static inline status_t cm_int64_sub_dec(int64 i64, const dec8_t *dec, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_subtract(&i64_dec, dec, result);
}

static inline status_t cm_dec8_mul_int64(const dec8_t *dec, int64 i64, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_multiply(dec, &i64_dec, result);
}

#define cm_int64_mul_dec8(i64, dec, result) cm_dec8_mul_int64((dec), (i64), (result))

static inline status_t cm_dec8_div_int64(const dec8_t *dec, int64 i64, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_divide(dec, &i64_dec, result);
}

static inline status_t cm_int64_div_dec8(int64 i64, const dec8_t *dec, dec8_t *result)
{
    dec8_t i64_dec;
    cm_int64_to_dec8(i64, &i64_dec);
    return cm_dec8_divide(&i64_dec, dec, result);
}

/* The arithmetic operations among DECIMAL and REAL/DOUBLE */
static inline status_t cm_dec8_add_real(const dec8_t *dec, double real, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec8_add(dec, &real_dec, result);
}

#define cm_real_add_dec8(real, dec, result) cm_dec8_add_real((dec), (real), (result))
#define cm_dec8_sub_real(dec, real, result) cm_dec8_add_real((dec), (-(real)), (result))

static inline status_t cm_real_sub_dec8(double real, const dec8_t *dec, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec8_subtract(&real_dec, dec, result);
}

static inline status_t cm_dec8_mul_real(const dec8_t *dec, double real, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec8_multiply(dec, &real_dec, result);
}

#define cm_real_mul_dec8(real, dec, result) cm_dec8_mul_real((dec), (real), (result))

static inline status_t cm_dec8_div_real(const dec8_t *dec, double real, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec8_divide(dec, &real_dec, result);
}

static inline status_t cm_real_div_dec8(double real, const dec8_t *dec, dec8_t *result)
{
    dec8_t real_dec;
    if (cm_real_to_dec8(real, &real_dec) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec8_divide(&real_dec, dec, result);
}

#ifdef __cplusplus
}
#endif

#endif
