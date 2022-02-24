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
 * cm_dec4.c
 *    This file high-precision dec4. The number 4 means each digital cell
 * can capacity accommodate 4 digits. Here, the digital cells are defied by uint16.
 * This implementation is more compact than dec8, but less efficient, thus it is
 * more suitable for storage.
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_dec4.c
 *
 * -------------------------------------------------------------------------
 */
#include "cm_text.h"
#include "cm_decimal.h"
#include "cm_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

/* DEC_POW2_MASK is 10^8 */
#define DEC_POW2_MASK ((uint32)(DEC4_CELL_MASK) * (DEC4_CELL_MASK))

/* DEC_POW3_MASK is 10^12 */
#define DEC_POW3_MASK ((uint64)(DEC_POW2_MASK) * (DEC4_CELL_MASK))

/* DEC_POW4_MASK is 10^16 */
#define DEC_POW4_MASK (DEC_POW3_MASK * DEC4_CELL_MASK)

static const uint64 g_pow10000_u64[] = {
    1,              // 10000^0
    DEC4_CELL_MASK,  // 10000^1
    DEC_POW2_MASK,  // 10000^2
    DEC_POW3_MASK,  // 10000^3
    DEC_POW4_MASK,  // 10000^4
};

/* decimal 1 */
const dec4_t DEC4_ONE = {
    .expn = SEXP_2_D4EXP(0), .sign = DEC_SIGN_PLUS, .ncells = (uint8)1, .cells = { 1 }
};

/* decimal of the minimal int64 is -9 223 372 036 854 775 808 */
const dec4_t DEC4_MIN_INT64 = {
    // to make the expn be the integer multiple times of DEC4_CELL_DIGIT
    .expn = SEXP_2_D4EXP(16),
    .sign = DEC_SIGN_MINUS,
    .ncells = (uint8)5,
    .cells = { 922, 3372, 368, 5477, 5808 }
};

/* decimal of the maximal bigint is 9,223,372,036,854,775,807 */
const dec4_t DECIMAL_MAX_INT64 = {
    .expn = SEXP_2_D4EXP(16),
    .sign = DEC_SIGN_PLUS,
    .ncells = (uint8)5,
    .cells = { 922, 3372, 368, 5477, 5807 }
};

/* decimal of the maximal uint64 is 18,446,744,073,709,551,615 */
const dec4_t DECIMAL_MAX_UINT64 = {
    .expn = SEXP_2_D4EXP(16), .sign = DEC_SIGN_PLUS, .ncells = (uint8)5, .cells = { 1844, 6744, 737, 955, 1615 }
};

/* decimal of the minimal int32 is -2 147 483 648 */
static const dec4_t DEC8_MIN_INT32 = {
    // to make the expn be the integer multiple times of DEC4_CELL_DIGIT
    .expn = SEXP_2_D4EXP(8),
    .sign = DEC_SIGN_MINUS,
    .ncells = (uint8)3,
    .cells = { 21, 4748, 3648 }
};

const uint32 g_1ten_powers[10] = {
    1u,          // 10^0
    10u,         // 10^1
    100u,        // 10^2
    1000u,       // 10^3
    10000u,      // 10^4
    100000u,     // 10^5
    1000000u,    // 10^6
    10000000u,   // 10^7
    100000000u,  // 10^8
    1000000000u  // 10^9
};

// half of g_1ten_powers, used for rounding a decimal
const uint32 g_5ten_powers[10] = {
    0u,          // 0
    5u,          // 5 x 10^0
    50u,         // 5 x 10^1
    500u,        // 5 x 10^2
    5000u,       // 5 x 10^3
    50000u,      // 5 x 10^4
    500000u,     // 5 x 10^5
    5000000u,    // 5 x 10^6
    50000000u,   // 5 x 10^7
    500000000u,  // 5 x 10^8
};

static int32 cm_dec4_calc_prec(const dec4_t *dec);

static inline bool32 cm_dec4_taylor_break(const dec4_t *total, const dec4_t *delta, int32 prec)
{
    if (DECIMAL_IS_ZERO(delta)) {
        return GS_TRUE;
    }

    if (((int32)total->expn + (((total)->cells[0] >= 1000) ? 1 : 0))
          > (int32)SEXP_2_D4EXP(prec) + (int32)delta->expn) {
        return GS_TRUE;
    }
    return GS_FALSE;
}

static inline void cm_dec4_left_shift(const dec4_t *dec, uint32 offset, dec4_t *rs)
{
    uint32 ri, di;

    for (ri = 0, di = offset; di < (uint32)dec->ncells; ++ri, ++di) {
        rs->cells[ri] = dec->cells[di];
    }
    rs->ncells = (int8)((uint32)dec->ncells - offset);
    rs->expn = (int8)((uint32)dec->expn - offset);
}

/**
* Right shift decimal cells. The leading cells are filled with zero.
* @note The following conditions should be guaranteed by caller
* + offset > 0 and offset < DEC_CELL_SIZE
* + dec->ncells > 0
*/
static inline void cm_dec4_right_shift(const dec4_t *dec, int32 offset, dec4_t *rs)
{
    int32 di = dec->ncells - 1;
    int32 ri = di + offset;

    if (ri >= (DEC4_CELL_SIZE - 1)) {
        di -= (ri - (DEC4_CELL_SIZE - 1));
        ri = (DEC4_CELL_SIZE - 1);
    }

    rs->ncells = (uint8)(ri + 1);
    rs->sign = dec->sign;
    rs->expn = (int8)(dec->expn + offset);

    while (di >= 0) {
        rs->cells[ri] = dec->cells[di];
        ri--;
        di--;
    }

    while (ri >= 0) {
        rs->cells[ri] = 0;
        ri--;
    }
}

static inline void cm_dec4_rebuild(dec4_t *rs, uint32 cell0)
{
    /* decide the number of cells */
    if (rs->ncells < DEC4_CELL_SIZE) {
        rs->ncells++;
    }

    /* right shift cell data by 1 */
    uint32 i = rs->ncells;
    while (i-- > 1) {
        rs->cells[i] = rs->cells[i - 1];
    }

    /* put the carry into cells[0] */
    rs->cells[0] = (c4typ_t)cell0;
    rs->expn++;
}

/*
 * Truncate the tail of a decimal so that its precision is no more than prec
 * It must be that prec > 0
 */
status_t cm_dec4_finalise(dec4_t *dec, uint32 prec, bool32 allow_overflow)
{
    uint32 dpos;  // position of truncating in decimal
    uint32 cpos;  // the position of truncating in decimal->cells
    uint32 npos;  // the position of truncating in decimal->cells[x]
    uint32 carry;
    int32 i;
    int32 sci_exp = DEC4_GET_SEXP(dec);

    // underflow check
    if (sci_exp < MIN_NUMERIC_EXPN) {
        cm_zero_dec4(dec);
        return GS_SUCCESS;
    }
    if (!allow_overflow) {
        DEC_OVERFLOW_CHECK_BY_SCIEXP(sci_exp);
    }

    GS_RETSUC_IFTRUE((uint32)dec->ncells <= (prec / DEC4_CELL_DIGIT));

    GS_RETVALUE_IFTRUE(((uint32)cm_dec4_calc_prec(dec) <= prec), GS_SUCCESS);

    dpos = (uint32)DEC4_POS_N_BY_PREC0(prec, cm_count_u16digits(dec->cells[0]));
    cpos = dpos / (uint32)DEC4_CELL_DIGIT;
    npos = dpos % (uint32)DEC4_CELL_DIGIT;
    carry = g_5ten_powers[DEC4_CELL_DIGIT - npos];

    dec->ncells = cpos + 1;
    for (i = (int32)cpos; i >= 0; --i) {
        dec->cells[i] += carry;
        carry = (dec->cells[i] >= DEC4_CELL_MASK);
        if (carry == 0) {
            break;
        }
        dec->cells[i] -= DEC4_CELL_MASK;
    }

    // truncate tailing digits to zeros
    dec->cells[cpos] /= g_1ten_powers[DEC4_CELL_DIGIT - npos];
    dec->cells[cpos] *= g_1ten_powers[DEC4_CELL_DIGIT - npos];

    if (carry > 0) {
        cm_dec4_rebuild(dec, 1);
        if (!allow_overflow) {
            DEC_OVERFLOW_CHECK_BY_SCIEXP(sci_exp + DEC4_CELL_DIGIT);
        }
    }

    (void)cm_dec4_trim_zeros(dec);
    return GS_SUCCESS;
}

/**
* Product a cell array with the digit at pos (starting from left) is k
*/
static inline bool32 cm_dec4_make_round(const dec4_t* dec, uint32 pos, dec4_t* dx)
{
    int32 i;
    uint32 carry, j;

    cm_dec4_copy(dx, dec);
    if (pos >= DEC4_MAX_ALLOWED_PREC) {
        return GS_FALSE;
    }

    i = (int32)(pos / DEC4_CELL_DIGIT);
    j = pos % DEC4_CELL_DIGIT;

    carry = (uint32)g_5ten_powers[DEC4_CELL_DIGIT - j];
    for (; i >= 0; i--) {
        dx->cells[i] += carry;
        carry = (dx->cells[i] >= DEC4_CELL_MASK);
        if (!carry) {
            return GS_FALSE;
        }
        dx->cells[i] -= DEC4_CELL_MASK;
    }

    if (carry > 0) {
        cm_dec4_rebuild(dx, 1);
    }

    return carry;
}

// whether abs(dec) is equal to 1
static inline bool32 cm_dec4_is_absolute_one(const dec4_t *dec)
{
    return (bool32)(dec->expn == 0 && dec->ncells == 1 && dec->cells[0] == 1);
}

//  whether dec is equal to 1
static inline bool32 cm_dec4_is_one(const dec4_t *dec)
{
    return (bool32)(dec->head == 2 && dec->cells[0] == 1);
}

static inline void cm_add_aligned_dec4(const dec4_t *d1, const dec4_t *d2, dec4_t *rs)
{
    uint32 i;
    c4typ_t carry = 0;

    if (d1->ncells > d2->ncells) {
        SWAP(const dec4_t *, d1, d2);
    }

    i = d2->ncells;
    while (i > (uint32)d1->ncells) {
        i--;
        rs->cells[i] = d2->cells[i];
    }
    rs->head = d2->head;

    while (i-- > 0) {
        rs->cells[i] = d1->cells[i] + d2->cells[i] + carry;
        carry = (rs->cells[i] >= DEC4_CELL_MASK);  // carry can be either 1 or 0 in addition
        if (carry) {
            rs->cells[i] -= DEC4_CELL_MASK;
        }
    }

    if (carry) {
        cm_dec4_rebuild(rs, 1);
    }

    (void)cm_dec4_trim_zeros(rs);
}

/** Subtraction of two cell array. large must greater than small.  */
static inline void cm_sub_aligned_dec4(
    const dec4_t *large, const dec4_t *small, bool32 flip_sign, dec4_t *rs)
{
    /* if small has more cells than large, a borrow must be happened */
    int32 borrow = (small->ncells > large->ncells) ? 1 : 0;
    uint32 i;

    if ((bool32)borrow) {
        i = small->ncells - 1;
        rs->cells[i] = DEC4_CELL_MASK - small->cells[i];
        while (i > (uint32)large->ncells) {
            i--;
            rs->cells[i] = (DEC4_CELL_MASK - 1) - small->cells[i];
        }
        rs->ncells = small->ncells;
    } else {
        i = large->ncells;
        while (i > (uint32)small->ncells) {
            i--;
            rs->cells[i] = large->cells[i];
        }
        rs->ncells = large->ncells;
    }

    while (i-- > 0) {
        int32 tmp = (int32)(large->cells[i] - (small->cells[i] + borrow));
        borrow = (tmp < 0);  // borrow can be either 1 or 0
        if (borrow) {
            tmp += (int32)DEC4_CELL_MASK;
        }
        rs->cells[i] = (c4typ_t)tmp;
    }

    rs->expn = large->expn;
    rs->sign = flip_sign ? NEGATE_SIGN(large->sign) : large->sign;

    if (rs->cells[0] == 0) {
        for (i = 1; i < (uint32)rs->ncells; i++) {
            if (rs->cells[i] > 0) {
                break;
            }
        }
        cm_dec4_left_shift(rs, i, rs);
    }

    (void)cm_dec4_trim_zeros(rs);
}

/**
* Quickly find the precision of a cells
* @note  (1) The cell u0 should be specially treated;
*        (2) The tailing zeros will not be counted. If all cell except u0 are
*        zeros, then the precision of u0 is re-counted by ignoring tailing zeros
*        e.g. | u0 = 1000 | u1 = 0 | u2 = 0 |..., the precision 1 will be
*        returned.
*/
static int32 cm_dec4_calc_prec(const dec4_t *dec)
{
    int32 i, j;
    uint32 u;
    int32 prec = 0;

    if (dec->ncells == 0) {
        return 0;
    }

    /* Step 1: Find the precision of remaining cells starting from backend */
    for (i = dec->ncells - 1; i > 0; --i) {
        if (dec->cells[i] > 0) {  // found the last non-zero cell (dec->cells[i]>0)
            // count digits in this cell by ignoring tailing zeros
            j = 0;
            u = dec->cells[i];
            while (u % 10 == 0) {
                ++j;
                u /= 10;
            }
            prec += (i * DEC4_CELL_DIGIT - j);
            break;
        }
    }

    /* Step 1: Count the precision of u0 */
    if (i == 0) {  // if u1, u2, ... are zeros, then the precision of u0 should remove tailing zeros
        u = dec->cells[0];
        while (u % 10 == 0) { // remove tailing zeros
            u /= 10;
        }
        prec = (int32)cm_count_u16digits((c4typ_t)u);
    } else {
        prec += (int32)cm_count_u16digits(dec->cells[0]);
    }

    return prec;
}

/**
* Convert the significant digits of cells into text with a maximal len
* @note  The tailing zeros are removed when outputting
*/
static void cm_cell4s_to_text(const cell4_t cells, uint32 ncell, text_t *text, int32 max_len)
{
    uint32 i;
    int iret_snprintf;

    iret_snprintf = snprintf_s(text->str, DEC4_CELL_DIGIT + 1, DEC4_CELL_DIGIT, "%u", cells[0]);
    PRTS_RETVOID_IFERR(iret_snprintf);
    text->len = (uint32)iret_snprintf;
    for (i = 1; (text->len < (uint32)max_len) && (i < ncell); ++i) {
        iret_snprintf = snprintf_s(CM_GET_TAIL(text), DEC4_CELL_DIGIT + 1,
                                   DEC4_CELL_DIGIT, DEC4_CELL_FMT, (uint32)cells[i]);
        PRTS_RETVOID_IFERR(iret_snprintf);
        text->len += (uint32)iret_snprintf;
    }

    // truncate redundant digits
    if (text->len > (uint32)max_len) {
        text->len = (uint32)max_len;
    }

    // truncate tailing zeros
    for (i = (uint32)text->len - 1; i > 0; --i) {
        if (!CM_IS_ZERO(text->str[i])) {
            break;
        }
        --text->len;
    }

    CM_NULL_TERM(text);
}

/**
* Round a decimal to a text with the maximal length max_len
* If the precision is greater than max_len, a rounding mode is used.
* The rounding mode may cause a change on precision, e.g., the 8-precision
* decimal 99999.999 rounds to 7-precision decimal is 100000.00, and then
* its actual precision is 8. The function will return the change. If
* no change occurs, zero is returned.
* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. 1.max_len > 0    2.dec->cells[0] > 0
*/
static int32 cm_dec4_round_to_text(const dec4_t *dec, int32 max_len, text_t *text_out)
{
    dec4_t txtdec;
    uint32 prec_u0;
    int32 prec;

    prec = cm_dec4_calc_prec(dec);
    if (prec <= max_len) {  // total prec under the max_len
        cm_cell4s_to_text(dec->cells, dec->ncells, text_out, prec);
        return 0;
    }

    /** if prec > max_len, the rounding mode is applied */
    prec_u0 = cm_count_u16digits(dec->cells[0]);
    // Rounding model begins by adding with {5[(prec - max_len) zeros]}
    // Obtain the pos of 5 for rounding, then prec is used to represent position
    prec = DEC4_POS_N_BY_PREC0(max_len, prec_u0);
    // add for rounding and check whether the carry happens, and capture the changes of the precision
    if (cm_dec4_make_round(dec, (uint32)prec, &txtdec)) {
        // if carry happens, the change must exist
        cm_cell4s_to_text(txtdec.cells, dec->ncells + 1, text_out, max_len);
        return 1;
    } else {
        cm_cell4s_to_text(txtdec.cells, dec->ncells, text_out, max_len);
        return (cm_count_u16digits(txtdec.cells[0]) > prec_u0) ? 1 : 0;
    }
}

/*
* Convert a cell text into a cell of big integer by specifying the
* length digits in u0 (i.e., len_u0), and return the number of non-zero cells
* Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. cells[0] > 0
*/
static inline int32 cm_digitext_to_cell8s(digitext_t *dtext, cell4_t cells, int32 len_u0)
{
    uint32 i, k;
    text_t cell_text;

    // make u0
    cell_text.str = dtext->str;
    cell_text.len = (uint32)len_u0;
    cells[0] = (c4typ_t)cm_celltext2uint32(&cell_text);

    // make u1, u2, ..., uk
    k = 1;
    for (i = (uint32)len_u0; k < DEC4_CELL_SIZE && i < dtext->len; k++) {
        cell_text.str = dtext->str + i;
        cell_text.len = (uint32)DEC4_CELL_DIGIT;
        cells[k] = (c4typ_t)cm_celltext2uint32(&cell_text);
        i += DEC4_CELL_DIGIT;
    }

    // the tailing cells of significant cells may be zeros, for returning
    // accurate ncells, they should be ignored.
    while (cells[k - 1] == 0) {
        --k;
    }

    return (int32)k;
}

/**
* Convert a digit text with a scientific exponent into a decimal
* The digit text may be changed when adjust the scale of decimal to be
* an integral multiple of DEC4_CELL_DIGIT, by appending zeros.
* @return the precision of u0
* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller,
* i.g. dtext->len > 0 && dtext->len <= (uint32)DEC4_MAX_ALLOWED_PREC
*/
static inline int32 cm_digitext_to_dec4(dec4_t *dec, digitext_t *dtext, int32 sci_exp)
{
    int32 delta;
    int32 len_u0;  // the length of u0

    len_u0 = (int32)dtext->len % DEC4_CELL_DIGIT;

    ++sci_exp;  // increase the sci_exp to obtain the position of dot

    delta = sci_exp - len_u0;
    delta += (int32)DEC4_CELL_DIGIT << 16;  // make delta to be positive
    delta %= DEC4_CELL_DIGIT;               // get the number of appending zeros
    len_u0 = (len_u0 + delta) % DEC4_CELL_DIGIT;

    if (len_u0 == 0) {
        len_u0 = DEC4_CELL_DIGIT;
    }

    while (delta-- > 0) {
        CM_TEXT_APPEND(dtext, '0');
    }

    CM_NULL_TERM(dtext);

    dec->ncells = (uint8)cm_digitext_to_cell8s(dtext, dec->cells, len_u0);
    dec->expn = SEXP_2_D4EXP(sci_exp - len_u0);
    return len_u0;
}

#define DEC_EXPN_BUFF_SZ 16
/**
* Output a decimal type in scientific format, e.g., 2.34566E-20
*/
static inline status_t cm_dec4_to_sci_text(text_t *text, const dec4_t *dec, int32 max_len)
{
    int32 i;
    char obuff[GS_NUMBER_BUFFER_SIZE]; /** output buff */
    text_t cell_text = { .str = obuff, .len = 0 };
    char sci_buff[DEC_EXPN_BUFF_SZ] = { 0 };
    int32 sci_len;
    int32 sci_exp; /** The scientific scale of the dec */
    int32 placer;
    int iret_snprintf;

    sci_exp = DEC4_GET_SEXP(dec);
    // digits of sci_exp + sign(dec) + dot + E + sign(expn)
    placer = (int32)dec->sign + 3;
    placer += (int32)cm_count_u16digits((c4typ_t)abs(sci_exp));
    if (max_len <= placer) {
        return GS_ERROR;
    }

    /* The round of a decimal may increase the precision by 1 */
    if (cm_dec4_round_to_text(dec, max_len - placer, &cell_text) > 0) {
        ++sci_exp;
    }
    // compute the exponent placer
    iret_snprintf = snprintf_s(sci_buff, DEC_EXPN_BUFF_SZ, DEC_EXPN_BUFF_SZ - 1, "E%+d", sci_exp);
    PRTS_RETURN_IFERR(iret_snprintf);
    placer = iret_snprintf;

    // Step 1. output sign
    text->len = 0;
    if (dec->sign == DEC_SIGN_MINUS) {
        CM_TEXT_APPEND(text, '-');
    }

    CM_TEXT_APPEND(text, cell_text.str[0]);
    CM_TEXT_APPEND(text, '.');
    for (i = 1; (int32)text->len < max_len - placer; ++i) {
        if (i < (int32)cell_text.len) {
            CM_TEXT_APPEND(text, cell_text.str[i]);
        } else {
            CM_TEXT_APPEND(text, '0');
        }
    }

    sci_len = (int32)strlen(sci_buff);
    if ((int32)text->len + sci_len > max_len) {
        GS_THROW_ERROR(ERR_BUFFER_OVERFLOW, (int32)text->len + sci_len, max_len);
        return GS_ERROR;
    }

    MEMS_RETURN_IFERR(memcpy_s(&text->str[text->len], sci_len, sci_buff, sci_len));
    text->len += sci_len;
    return GS_SUCCESS;
}

/**
* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller, i.g. dot_pos <= max_len - dec->sign
*/
static inline status_t cm_dec4_to_plain_text(text_t *text, const dec4_t *dec, int32 max_len, int32 sci_exp,
                                             int32 prec)
{
    int32 dot_pos;
    char obuff[GS_NUMBER_BUFFER_SIZE]; /** output buff */
    text_t cell_text;
    cell_text.str = obuff;
    cell_text.len = 0;

    // clear text & output sign
    text->len = 0;
    if (dec->sign == DEC_SIGN_MINUS) {
        CM_TEXT_APPEND(text, '-');
    }

    dot_pos = sci_exp + 1;

    if (prec <= dot_pos) {
        (void)cm_dec4_round_to_text(dec, max_len - dec->sign, &cell_text);  // subtract sign
        cm_concat_text(text, max_len, &cell_text);
        cm_text_appendc(text, dot_pos - prec, '0');
        return GS_SUCCESS;
    }

    /* get the position of dot w.r.t. the first significant digit */
    if (dot_pos == max_len - dec->sign) {
        /* handle the border case with dot at the max_len position,
        * then the dot is not outputted. Suppose max_len = 10,
        *  (1). 1234567890.222 --> 1234567890 is outputted
        * If round mode products carry, e.g. the rounded value of
        * 9999999999.9 is 10000000000, whose length is 11 and greater than
        * max_len, then the scientific format is used to print the decimal
        */
        if (cm_dec4_round_to_text(dec, dot_pos, &cell_text) > 0) {
            CM_TEXT_CLEAR(text);
            return cm_dec4_to_sci_text(text, dec, max_len);
        }
        cm_concat_text(text, max_len, &cell_text);
        cm_text_appendc(text, max_len - (int32)text->len, '0');
    } else if (dot_pos == max_len - dec->sign - 1) {
        /* handle the border case with dot at the max_len - 1 position,
        * then only max_len-1 is print but the dot is emitted. Assume
        * max_len = 10, the following cases output:
        *  (1). 123456789.2345 ==> 123456789  (.2345 is abandoned)
        *  (2). 987654321.56   ==> 987654322  (.56 is rounded to 1)
        * If a carry happens, e.g., 999999999.6 ==> 1000000000, max_len
        * number of digits will be printed.
        * */
        int32 change = cm_dec4_round_to_text(dec, dot_pos, &cell_text);
        cm_concat_text(text, max_len, &cell_text);
        cm_text_appendc(text, max_len + change - ((int32)text->len + 1), '0');
    } else if (dot_pos >= 0) { /* dot is inside of cell_text and may be output */
        // round mode may product carry, and thus may affect the dot_pos
        dot_pos += cm_dec4_round_to_text(dec, max_len - dec->sign - 1, &cell_text);  // subtract sign & dot
        if ((int32)cell_text.len <= dot_pos) {
            cm_concat_text(text, max_len, &cell_text);
            cm_text_appendc(text, dot_pos - (int32)cell_text.len, '0');
        } else {
            GS_RETURN_IFERR(cm_concat_ntext(text, &cell_text, dot_pos));
            CM_TEXT_APPEND(text, '.');
            // copy remaining digits
            cell_text.str += (uint32)dot_pos;
            cell_text.len -= (uint32)dot_pos;
            cm_concat_text(text, max_len, &cell_text);
        }
    } else {  // dot_pos is less than 0
        /* dot is in the most left & add |dot_pos| zeros between dot and cell_text
        * Thus, the maxi_len should consider sign, dot, and the adding zeros */
        dot_pos += cm_dec4_round_to_text(dec, max_len - dec->sign - 1 + dot_pos, &cell_text);
        CM_TEXT_APPEND(text, '.');
        cm_text_appendc(text, -dot_pos, '0');
        GS_RETURN_IFERR(cm_concat_ntext(text, &cell_text, max_len - (int32)text->len));
    }

    return GS_SUCCESS;
}

/**
* Convert a decimal into a text with a given maximal precision
* @note
* Performance sensitivity.CM_ASSERT should be guaranteed by caller,
* i.g. 1.dec->sign == DEC_SIGN_PLUS    2.dec->expn == 0    3.dec->cells[0] > 0
* Output is text, text->str is not end with '\0' and text->len can be max_len
*/
status_t cm_dec4_to_text(const dec4_t *dec, int32 max_len, text_t *text)
{
    int32 sci_exp; /** The scientific scale of the dec */
    int32 prec;

    CM_POINTER2(dec, text);
    max_len = MIN(max_len, (int32)(GS_NUMBER_BUFFER_SIZE - 1));

    if (dec->ncells == 0) {
        text->str[0] = '0';
        text->len = 1;
        return GS_SUCCESS;
    }

    // Compute the final scientific scale of the dec, i.e., format of d.xxxx , d > 0.
    // Each decimal has an unique scientific representation.
    sci_exp = DEC4_GET_SEXP(dec);
    // get the total precision of the decimal
    prec = cm_dec4_calc_prec(dec);
    // Scientific representation when the scale exceeds the maximal precision
    // or have many leading zeros and have many significant digits
    // When sci_exp < 0, the length for '.' should be considered
    if ((sci_exp < -6 && -sci_exp + prec + (int32)dec->sign > max_len)
        || (sci_exp > 0 && sci_exp + 1 + (int32)dec->sign > max_len)) {
        return cm_dec4_to_sci_text(text, dec, max_len);
    }

    // output plain text
    return cm_dec4_to_plain_text(text, dec, max_len, sci_exp, prec);
}

/**
* Convert a decimal into C-string, and return the ac
* @note
* Output is str and end with '\0' and max write size is max_len-1
*/
status_t cm_dec4_to_str(const dec4_t *dec, int max_len, char *str)
{
    text_t text;
    text.str = str;
    text.len = 0;

    if (max_len <= 1) {
        return GS_ERROR;
    }

    GS_RETURN_IFERR(cm_dec4_to_text(dec, max_len - 1, &text));
    str[text.len] = '\0';
    return GS_SUCCESS;
}

status_t cm_str_to_dec4(const char *str, dec4_t *dec)
{
    text_t text;
    cm_str2text((char *)str, &text);
    return cm_text_to_dec4(&text, dec);
}

static inline void cm_do_numpart_round4(const num_part_t *np, dec4_t *dec, uint32 prec0)
{
    c4typ_t   carry = g_1ten_powers[prec0 % DEC4_CELL_DIGIT];
    uint32   i = dec->ncells;

    while (i-- > 0) {
        dec->cells[i] += carry;
        carry = (dec->cells[i] >= DEC4_CELL_MASK);
        if (carry == 0) {
            return;
        }
        dec->cells[i] -= DEC4_CELL_MASK;
    }

    if (carry > 0) {
        cm_dec4_rebuild(dec, 1);
    }
}

num_errno_t cm_numpart_to_dec4(num_part_t *np, dec4_t *dec)
{
    if (NUMPART_IS_ZERO(np)) {
        cm_zero_dec4(dec);
        return NERR_SUCCESS;
    }

    // Step 3.2. check overflow by comparing scientific scale and MAX_NUMERIC_EXPN
    if (np->sci_expn > MAX_NUMERIC_EXPN) {  // overflow return Error
        return NERR_OVERFLOW;
    } else if (np->sci_expn < MIN_NUMERIC_EXPN) {  // underflow return 0
        cm_zero_dec4(dec);
        return NERR_SUCCESS;
    }

    // Step 4: make the final decimal value
    dec->sign = (uint8)np->is_neg;
    int32 prec0 = cm_digitext_to_dec4(dec, &np->digit_text, np->sci_expn);

    if (np->do_round) {  // when round happens, the dec->cells should increase 1
        cm_do_numpart_round4(np, dec, (uint32)prec0);
        cm_dec4_trim_zeros(dec);  // rounding may change the precision
    }

    return NERR_SUCCESS;
}

/**
* Translates a text_t representation of a decimal into a decimal
* @param
* -- precision: records the precision of the decimal text. The initial value
*               is -1, indicating no significant digit found. When a leading zero
*               is found, the precision is set to 0, it means the merely
*               significant digit is zero. precision > 0 represents the
*               number of significant digits in the decimal text.
*/
status_t cm_text_to_dec4(const text_t *dec_text, dec4_t *dec)
{
    num_errno_t err_no;
    num_part_t np;
    np.excl_flag = NF_NONE;

    err_no = cm_split_num_text(dec_text, &np);
    if (err_no != NERR_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no));
        return GS_ERROR;
    }

    err_no = cm_numpart_to_dec4(&np, dec);
    if (err_no != NERR_SUCCESS) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER, cm_get_num_errinfo(err_no));
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/**
* Fill a non-zero uint32 into decimal
* @note u64 > 0
*/
static inline void cm_fill_uint32_to_dec4(uint32 u32, dec4_t *dec)
{
    if (u32 < DEC_POW2_MASK) {
        if (u32 < DEC4_CELL_MASK) { // u32 less than 10^4
            dec->expn = SEXP_2_D4EXP(0);
            dec->ncells = 1;
            dec->cells[0] = (c4typ_t)u32;
            return;
        }
        // u32 is less than 10^8
        dec->expn = SEXP_2_D4EXP(DEC4_CELL_DIGIT);
        dec->cells[0] = (c4typ_t)(u32 / DEC4_CELL_MASK);
        dec->cells[1] = (c4typ_t)(u32 % DEC4_CELL_MASK);
        dec->ncells = (dec->cells[1] > 0) ? 2 : 1;
        return;
    } else {
        // u32 is greater than or equal to 10^8
        dec->expn = SEXP_2_D4EXP(DEC4_CELL_DIGIT * 2);
        dec->cells[0] = (c4typ_t)(u32 / DEC_POW2_MASK);
        u32 %= DEC_POW2_MASK;
        dec->cells[1] = (c4typ_t)(u32 / DEC4_CELL_MASK);
        dec->cells[2] = (c4typ_t)(u32 % DEC4_CELL_MASK);

        // removing tailing zero cells
        dec->ncells = (dec->cells[2] > 0) ? 3 : (dec->cells[1] > 0 ? 2 : 1);
    }
}

/**
* Convert an integer32 into a decimal
*/
void cm_int32_to_dec4(int32 i32, dec4_t *dec)
{
    if (i32 > 0) {
        dec->sign = DEC_SIGN_PLUS;
    } else if (i32 < 0) {
        if (i32 == GS_MIN_INT32) {
            cm_dec4_copy(dec, &DEC8_MIN_INT32);
            return;
        }
        dec->sign = DEC_SIGN_MINUS;
        i32 = -i32;
    } else {
        cm_zero_dec4(dec);
        return;
    }

    cm_fill_uint32_to_dec4((uint32)i32, dec);
}

void cm_uint32_to_dec4(uint32 i32, dec4_t *dec)
{
    if (i32 == 0) {
        cm_zero_dec4(dec);
        return;
    }

    dec->sign = DEC_SIGN_PLUS;
    cm_fill_uint32_to_dec4(i32, dec);
}


/** The buffer size to covert an int64 to dec->cells. It must be greater
** max_digits(int64) + DEC4_CELL_DIGIT + 1  than */
#define INT64_BUFF 32

/*
 * Fill a non-zero uint64(u64 > 0) into decimal
 */
static inline void cm_fill_uint64_to_dec4(uint64 u64, dec4_t *dec)
{
    if (u64 < DEC_POW3_MASK) {
        if (u64 < DEC4_CELL_MASK) {
            dec->expn = SEXP_2_D4EXP(0);
            dec->ncells = 1;
            dec->cells[0] = (c4typ_t)u64;
        } else if (u64 < DEC_POW2_MASK) {
            dec->expn = SEXP_2_D4EXP(DEC4_CELL_DIGIT);
            dec->cells[0] = (c4typ_t)(u64 / DEC4_CELL_MASK);
            dec->cells[1] = (c4typ_t)(u64 % DEC4_CELL_MASK);
            dec->ncells = (dec->cells[1] > 0) ? 2 : 1;
        } else {
            dec->expn = SEXP_2_D4EXP(DEC4_CELL_DIGIT * 2);
            dec->cells[0] = (c4typ_t)(u64 / DEC_POW2_MASK);
            u64 %= DEC_POW2_MASK;
            dec->cells[1] = (c4typ_t)(u64 / DEC4_CELL_MASK);
            dec->cells[2] = (c4typ_t)(u64 % DEC4_CELL_MASK);
            dec->ncells = (dec->cells[2] > 0) ? 3 : (dec->cells[1] > 0 ? 2 : 1);
        }
        return;
    }

    if (u64 < DEC_POW4_MASK) {
        dec->expn = SEXP_2_D4EXP(DEC4_CELL_DIGIT * 3);
        dec->ncells = 4;
        dec->cells[0] = (c4typ_t)(u64 / DEC_POW3_MASK);
        u64 %= DEC_POW3_MASK;
        dec->cells[1] = (c4typ_t)(u64 / DEC_POW2_MASK);
        u64 %= DEC_POW2_MASK;
        dec->cells[2] = (c4typ_t)(u64 / DEC4_CELL_MASK);
        dec->cells[3] = (c4typ_t)(u64 % DEC4_CELL_MASK);
    } else {
        dec->expn = SEXP_2_D4EXP(DEC4_CELL_DIGIT * 4);
        dec->ncells = 5;
        dec->cells[0] = (c4typ_t)(u64 / DEC_POW4_MASK);
        u64 %= DEC_POW4_MASK;
        dec->cells[1] = (c4typ_t)(u64 / DEC_POW3_MASK);
        u64 %= DEC_POW3_MASK;
        dec->cells[2] = (c4typ_t)(u64 / DEC_POW2_MASK);
        u64 %= DEC_POW2_MASK;
        dec->cells[3] = (c4typ_t)(u64 / DEC4_CELL_MASK);
        dec->cells[4] = (c4typ_t)(u64 % DEC4_CELL_MASK);
    }

    // removing tailing zero cells
    while (dec->cells[dec->ncells - 1] == 0) {
        --dec->ncells;
    }
}

/**
* Convert an integer64 into a decimal
*/
void cm_int64_to_dec4(int64 i64, dec4_t *dec)
{
    if (i64 > 0) {
        dec->sign = DEC_SIGN_PLUS;
    } else if (i64 < 0) {
        if (i64 == GS_MIN_INT64) {
            cm_dec4_copy(dec, &DEC4_MIN_INT64);
            return;
        }
        dec->sign = DEC_SIGN_MINUS;
        i64 = -i64;
    } else {
        cm_zero_dec4(dec);
        return;
    }

    cm_fill_uint64_to_dec4((uint64)i64, dec);
}

#define cm_int64_to_dec(i64, dec) cm_int64_to_dec4((i64), (dec))

static const double g_pos_pow4[] = {
    1.0,
    1.0e4,
    1.0e8,
    1.0e12,
    1.0e16,
    1.0e20,
    1.0e24,
    1.0e28,
    1.0e32,
    1.0e36,
    1.0e40,
    1.0e44,
    1.0e48,
    1.0e52,
    1.0e56,
    1.0e60,
    1.0e64,
    1.0e68,
    1.0e72,
    1.0e76,
    1.0e80,
    1.0e84,
    1.0e88,
    1.0e92,
    1.0e96,
    1.0e100,
    1.0e104,
    1.0e108,
    1.0e112,
    1.0e116,
    1.0e120,
    1.0e124,
    1.0e128,
    1.0e132,
    1.0e136,
    1.0e140,
    1.0e144,
    1.0e148,
    1.0e152,
    1.0e156,
};

/**
 * compute 10000^x, x should be between -40 and 40
 */
static inline double cm_pow4(int32 x)
{
    int32 y = abs(x);
    double r = (y < 40) ? g_pos_pow4[y] : pow(10e4, y);
    if (x < 0) {
        r = 1.0 / r;
    }
    return r;
}

static status_t cm_real_to_dec4_inexac(double r, dec4_t *dec);

/**
* Convert real value into a decimal type
*/
status_t cm_real_to_dec4(double real, dec4_t *dec)
{
    GS_RETURN_IFERR(cm_real_to_dec4_inexac(real, dec));
    // reserving at most GS_MAX_REAL_PREC precisions
    return cm_dec4_finalise(dec, GS_MAX_REAL_PREC, GS_FALSE);
}

/**
 * Convert real value into a decimal. It is similar with the function cm_real_to_dec4.
 * This function may be more efficient than cm_real_to_dec4, but may lose precision.
 * It is suitable for an algorithm which needs an inexact initial value.
 */
static status_t cm_real_to_dec4_inexac(double r, dec4_t *dec)
{
    if (!CM_DBL_IS_FINITE(r)) {
        GS_THROW_ERROR(ERR_INVALID_NUMBER, "");
        return GS_ERROR;
    }

    if (r == 0.0) {
        cm_zero_dec4(dec);
        return GS_SUCCESS;
    }

    double int_r;
    int32 dexp;

    bool32 is_neg = (r < 0);
    if (is_neg) {
        r = -r;
    }

    // compute an approximate scientific exponent
    (void)frexp(r, &dexp);
    dexp = (int32)((double)dexp * (double)GS_LOG10_2);
    dexp &= 0xFFFFFFFC;

    // Set a decimal
    dec->expn = SEXP_2_D4EXP(dexp);
    dec->sign = is_neg ? DEC_SIGN_MINUS : DEC_SIGN_PLUS;

    r *= cm_pow4(-dec->expn);
    // now, int_r is used as the integer part of r
    if (r >= 1.0) {
        r = modf(r, &int_r);
        dec->cells[0] = (c4typ_t)int_r;
        dec->ncells = 1;
    } else {
        dec->ncells = 0;
        --dec->expn;
    }

    while (dec->ncells < 5) {
        if (r == 0) {
            break;
        }
        r = modf(r * (double)DEC4_CELL_MASK, &int_r);
        dec->cells[dec->ncells++] = (c4typ_t)int_r;
    }
    cm_dec4_trim_zeros(dec);
    return GS_SUCCESS;
}

/**
 * NOTE THAT: convert a signed integer into DOUBLE is faster than unsigned integer,
 * therefore, These codes use signed integer for conversation to DOUBLE as much as
 * possible. The following SWITCH..CASE is faster than the loop implementation.
 */
double cm_dec4_to_real(const dec4_t *dec)
{
    if (DECIMAL_IS_ZERO(dec)) {
        return 0.0;
    }

    double dval;
    int32 i = MIN(dec->ncells, 5);
    uint64 u64;

    if (i >= 4) {
        u64 = (uint64)dec->cells[0] * DEC_POW3_MASK
            + (uint64)dec->cells[1] * DEC_POW2_MASK
            + (uint64)dec->cells[2] * DEC4_CELL_MASK
            + (uint64)dec->cells[3];
        dval = (double)(int64)u64;
        if (i > 4) {
            dval = dval * (double)DEC4_CELL_MASK + dec->cells[4];
        }
    } else if (i == 3) {
        u64 = (uint64)dec->cells[0] * DEC_POW2_MASK
            + (uint64)dec->cells[1] * DEC4_CELL_MASK
            + (uint64)dec->cells[2];
        dval = (double)((int64)u64);
    } else if (i == 2) {
        dval = (int32)((uint32)dec->cells[0] * DEC4_CELL_MASK + dec->cells[1]);
    } else {
        dval = (int32)dec->cells[0];
    }

    int32 dexpn = (int32)dec->expn - i + 1;

    /* the maximal expn of a decimal can not exceed 40 */
    if (dexpn >= 0) {
        dval *= g_pos_pow4[dexpn];
    } else {
        dval /= g_pos_pow4[-dexpn];
    }
    return DEC_IS_NEGATIVE(dec) ? -dval : dval;
}

/**
* Get the carry of a decimal with negative expn when convert decimal into integer
* @note Required: dec->expn < 0
* @author Added 2019/02/12
*/
static inline int32 dec4_make_negexpn_round_value(const dec4_t *dec, round_mode_t rnd_mode)
{
    switch (rnd_mode) {
        case ROUND_FLOOR:
            return DEC_IS_NEGATIVE(dec) ? -1 : 0;

        case ROUND_HALF_UP: {
            // e.g., 0.5 ==> 1, 0.499 ==> 0
            int32 val = ((dec->expn == -1) && (dec->cells[0] >= DEC4_HALF_MASK)) ? 1 : 0;
            return DEC_IS_NEGATIVE(dec) ? -val : val;
        }

        case ROUND_CEILING:
            return DEC_IS_NEGATIVE(dec) ? 0 : 1;

        case ROUND_TRUNC:
        default:
            return 0;
    }
}

/** Round a positive and non-zero decimal into uint64 */
/* @author Added 2019/02/12 */
static inline uint64 dec4_make_negexpn_round_value2(const dec4_t *dec, round_mode_t rnd_mode)
{
    switch (rnd_mode) {
        case ROUND_HALF_UP:
            // e.g., 0.5 ==> 1, 0.499 ==> 0
            return ((dec->expn == -1) && (dec->cells[0] >= DEC4_HALF_MASK)) ? 1 : 0;

        case ROUND_CEILING:
            return 1;

        case ROUND_TRUNC:
        case ROUND_FLOOR:
        default:
            return 0;
    }
}

status_t cm_dec4_to_uint64(const dec4_t *dec, uint64 *u64, round_mode_t rnd_mode)
{
    if (DEC_IS_NEGATIVE(dec)) {
        GS_THROW_ERROR(ERR_VALUE_ERROR, "convert NUMBER into UINT64 failed");
        return GS_ERROR;
    }

    if (DECIMAL_IS_ZERO(dec)) {
        *u64 = 0;
        return GS_SUCCESS;
    }

    if (dec->expn < 0) {
        *u64 = dec4_make_negexpn_round_value2(dec, rnd_mode);
        return GS_SUCCESS;
    }

    // the maximal UINT64 is 1844 6744 0737 0955 1615
    if (dec->expn > 4 || (dec->expn == 4 && dec->cells[0] > 1844)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UINT64");
        return GS_ERROR;
    }

    uint32 i;
    uint64 u64h = dec->cells[0];  // the highest cell
    uint64 u64l = 0;              // the tailing cells

    for (i = 1; i <= (uint32)dec->expn && i < (uint32)dec->ncells; i++) {
        u64l = u64l * DEC4_CELL_MASK + dec->cells[i];
    }

    // here expn must be in [0, 4]
    u64h *= g_pow10000_u64[(uint32)dec->expn];
    if (i <= (uint32)dec->expn) {
        u64l *= g_pow10000_u64[(uint32)(dec->expn + 1) - i];
        i = dec->expn + 1;
    }

    // do round
    if (i < (uint32)dec->ncells) {  // here i is dec->expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64l += DEC_IS_NEGATIVE(dec) ? 0 : 1;
                break;

            case ROUND_FLOOR:
                u64l += DEC_IS_NEGATIVE(dec) ? 1 : 0;
                break;

            case ROUND_HALF_UP:
                u64l += (dec->cells[i] >= DEC4_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_TRUNC:
            default:
                break;
        }
    }

    // overflow check
    if (u64h == 18440000000000000000ull && u64l > 6744073709551615ull) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UINT64");
        return GS_ERROR;
    }

    *u64 = u64h + u64l;

    return GS_SUCCESS;
}

status_t cm_dec4_to_int64(const dec4_t *dec, int64 *val, round_mode_t rnd_mode)
{
    CM_POINTER(dec);

    if (DECIMAL_IS_ZERO(dec)) {
        *val = 0;
        return GS_SUCCESS;
    }

    if (dec->expn < 0) {
        *val = dec4_make_negexpn_round_value(dec, rnd_mode);
        return GS_SUCCESS;
    }

    // the maximal BIGINT is 922 3372 0368 5477 5807
    if (dec->expn > 4 || (dec->expn == 4 && dec->cells[0] > 922)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return GS_ERROR;
    }

    uint32 i;
    uint64 u64_val = dec->cells[0];

    for (i = 1; i <= (uint32)dec->expn && i < (uint32)dec->ncells; i++) {
        u64_val = u64_val * DEC4_CELL_MASK + dec->cells[i];
    }
    if (i <= (uint32)dec->expn) {
        u64_val *= g_pow10000_u64[(uint32)(dec->expn + 1) - i];
        i = dec->expn + 1;
    }

    // do round
    if (i < (uint32)dec->ncells) {  // here i is equal to dec->expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64_val += DEC_IS_NEGATIVE(dec) ? 0 : 1;
                break;

            case ROUND_FLOOR:
                u64_val += DEC_IS_NEGATIVE(dec) ? 1 : 0;
                break;

            case ROUND_HALF_UP:
                u64_val += (dec->cells[i] >= DEC4_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_TRUNC:
            default:
                break;
        }
    }

    // overflow check
    if (u64_val > 9223372036854775807ull) {
        if (DEC_IS_NEGATIVE(dec) && u64_val == 9223372036854775808ull) {
            *val = GS_MIN_INT64;
            return GS_SUCCESS;
        }

        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "BIGINT");
        return GS_ERROR;
    }

    *val = DEC_IS_NEGATIVE(dec) ? -(int64)u64_val : (int64)u64_val;

    return GS_SUCCESS;
}

/**
* Convert a decimal into uint32. if overflow happened, return ERROR
*/
status_t cm_dec4_to_uint32(const dec4_t *dec, uint32 *i32, round_mode_t rnd_mode)
{
    if (DECIMAL_IS_ZERO(dec)) {
        *i32 = 0;
        return GS_SUCCESS;
    }

    // the maximal UINT32 42 9496 7295
    if (dec->expn > 2 || DEC_IS_NEGATIVE(dec)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED INTEGER");
        return GS_ERROR;
    }

    if (dec->expn < 0) {
        *i32 = (uint32)dec4_make_negexpn_round_value(dec, rnd_mode);
        return GS_SUCCESS;
    }

    uint32   i;
    uint64   u64_val = dec->cells[0];
    for (i = 1; i <= (uint32)dec->expn && i < (uint32)dec->ncells; i++) {
        u64_val = u64_val * DEC4_CELL_MASK + dec->cells[i];
    }

    while (i <= (uint32)dec->expn) {
        u64_val *= DEC4_CELL_MASK;
        ++i;
    }

    if (i < (uint32)dec->ncells) {
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64_val += 1;
                break;

            case ROUND_HALF_UP:
                u64_val += (dec->cells[i] >= DEC4_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_FLOOR:
            case ROUND_TRUNC:
            default:
                break;
        }
    }

    TO_UINT32_OVERFLOW_CHECK(u64_val, uint64);

    *i32 = (uint32)u64_val;
    return GS_SUCCESS;
}


/**
* Convert a decimal into int32. if overflow happened, return ERROR
*/
status_t cm_dec4_to_int32(const dec4_t *dec, int32 *i32, round_mode_t rnd_mode)
{
    if (DECIMAL_IS_ZERO(dec)) {
        *i32 = 0;
        return GS_SUCCESS;
    }

    if (dec->expn < 0) {
        *i32 = dec4_make_negexpn_round_value(dec, rnd_mode);
        return GS_SUCCESS;
    }

    // the maximal INTEGER 21 4748 3648
    if (dec->expn > 2) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "INTEGER");
        return GS_ERROR;
    }

    uint32 i;
    int64 i64_val = dec->cells[0];
    for (i = 1; i <= (uint32)dec->expn && i < (uint32)dec->ncells; i++) {
        i64_val = i64_val * DEC4_CELL_MASK + dec->cells[i];
    }

    while (i <= (uint32)dec->expn) {
        i64_val *= DEC4_CELL_MASK;
        ++i;
    }

    if (i < (uint32)dec->ncells) {  // here i is equal to dec->expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                i64_val += DEC_IS_NEGATIVE(dec) ? 0 : 1;
                break;

            case ROUND_FLOOR:
                i64_val += DEC_IS_NEGATIVE(dec) ? 1 : 0;
                break;

            case ROUND_HALF_UP:
                i64_val += (dec->cells[i] >= DEC4_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_TRUNC:
            default:
                break;
        }
    }

    if (DEC_IS_NEGATIVE(dec)) {
        i64_val = -i64_val;
    }

    INT32_OVERFLOW_CHECK(i64_val);

    *i32 = (int32)i64_val;
    return GS_SUCCESS;
}

/**
* Convert a decimal into uint16. if overflow happened, return ERROR
*/
status_t cm_dec4_to_uint16(const dec4_t *dec, uint16 *i16, round_mode_t rnd_mode)
{
    if (DECIMAL_IS_ZERO(dec)) {
        *i16 = 0;
        return GS_SUCCESS;
    }

    // the maximal UNSIGNED SHORT 6 5536
    if (dec->expn > 1 || DEC_IS_NEGATIVE(dec)) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED SHORT");
        return GS_ERROR;
    }

    if (dec->expn < 0) {
        *i16 = (uint16)dec4_make_negexpn_round_value(dec, rnd_mode);
        return GS_SUCCESS;
    }

    uint32   i;
    uint64   u64_val = dec->cells[0];
    for (i = 1; i <= (uint32)dec->expn && i < (uint32)dec->ncells; i++) {
        u64_val = u64_val * DEC4_CELL_MASK + dec->cells[i];
    }

    while (i <= (uint32)dec->expn) {
        u64_val *= DEC4_CELL_MASK;
        ++i;
    }

    if (i < (uint32)dec->ncells) {
        switch (rnd_mode) {
            case ROUND_CEILING:
                u64_val += 1;
                break;

            case ROUND_HALF_UP:
                u64_val += (dec->cells[i] >= DEC4_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_FLOOR:
            case ROUND_TRUNC:
            default:
                break;
        }
    }

    if ((uint64)u64_val < (uint64)GS_MIN_UINT16 || (uint64)u64_val > (uint64)GS_MAX_UINT16) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "UNSIGNED SHORT");
        return GS_ERROR;
    }

    *i16 = (uint16)u64_val;
    return GS_SUCCESS;
}

/**
* Convert a decimal into int16. if overflow happened, return ERROR
*/
status_t cm_dec4_to_int16(const dec4_t *dec, int16 *i16, round_mode_t rnd_mode)
{
    if (DECIMAL_IS_ZERO(dec)) {
        *i16 = 0;
        return GS_SUCCESS;
    }

    if (dec->expn < 0) {
        *i16 = (int16)dec4_make_negexpn_round_value(dec, rnd_mode);
        return GS_SUCCESS;
    }

    // the maximal SHORT 3 2767
    if (dec->expn > 1) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "SHORT");
        return GS_ERROR;
    }

    uint32 i;
    int64 i64_val = dec->cells[0];
    for (i = 1; i <= (uint32)dec->expn && i < (uint32)dec->ncells; i++) {
        i64_val = i64_val * DEC4_CELL_MASK + dec->cells[i];
    }

    while (i <= (uint32)dec->expn) {
        i64_val *= DEC4_CELL_MASK;
        ++i;
    }

    if (i < (uint32)dec->ncells) {  // here i is equal to dec->expn + 1
        switch (rnd_mode) {
            case ROUND_CEILING:
                i64_val += DEC_IS_NEGATIVE(dec) ? 0 : 1;
                break;

            case ROUND_FLOOR:
                i64_val += DEC_IS_NEGATIVE(dec) ? 1 : 0;
                break;

            case ROUND_HALF_UP:
                i64_val += (dec->cells[i] >= DEC4_HALF_MASK) ? 1 : 0;
                break;

            case ROUND_TRUNC:
            default:
                break;
        }
    }

    if (DEC_IS_NEGATIVE(dec)) {
        i64_val = -i64_val;
    }

    if (i64_val > GS_MAX_INT16 || i64_val < GS_MIN_INT16) {
        GS_THROW_ERROR(ERR_TYPE_OVERFLOW, "SHORT");
        return GS_ERROR;
    }

    *i16 = (int16)i64_val;
    return GS_SUCCESS;
}

/**
 * To decide whether a decimal is an integer
 * @author Added 2018/06/04
 */
bool32 cm_dec4_is_integer(const dec4_t *dec)
{
    uint32 i;

    if (DECIMAL_IS_ZERO(dec)) {
        return GS_TRUE;
    }

    if (dec->expn < 0) {
        return GS_FALSE;
    }

    i = dec->expn + 1;
    for (; i < (uint32)dec->ncells; i++) {
        if (dec->cells[i] > 0) {
            return GS_FALSE;
        }
    }
    return GS_TRUE;
}

#define MAX_RANGE_PREC (MAX_NUM_CMP_PREC - DEC4_CELL_DIGIT)

#ifdef __cplusplus
}
#endif

