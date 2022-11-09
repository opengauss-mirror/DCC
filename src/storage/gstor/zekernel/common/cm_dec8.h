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
 * cm_dec8.h
 *    The head file of two DECIMAL types: dec4_t and dec8_t. The former
 * has a compact format, and is designed for storage. Whereas the latter has an
 * efficient structure, and thus can be applied for numeric computation.
 *
 * IDENTIFICATION
 *    src/storage/gstor/zekernel/common/cm_dec8.h
 *
 * -------------------------------------------------------------------------
 */

#include "cm_dec4.h"

/* The number of cells (an uint32) used to store the decimal type. */
#define DEC8_CELL_SIZE (uint8)7

/* The number of digits that an element of an int256, i.e., an uint32
can encode. This indicates each uint32 can record at most DEC_ELEM_DIGIT
digits. Its value 9 is the upper, since 10^(9+1) < 2^32 < 10^11  */
#define DEC8_CELL_DIGIT 8

#define DEC8_EXPN_UNIT 8

#define SEXP_2_D8EXP(sci_exp) (int16)((sci_exp) / DEC8_EXPN_UNIT)

#define D8EXP_2_SEXP(dexp) ((dexp)*DEC8_EXPN_UNIT)

/* The the mask used to handle each cell. It is equal to 10^DEC_CELL_DIGIT */
#define DEC8_CELL_MASK 100000000U

/* Half of DEC_CELL_MASK */
#define DEC8_HALF_MASK 50000000U

/** The format to print a cell */
#define DEC8_CELL_FMT "%08u"

/* DEC_MAX_ALLOWED_PREC = DEC_CELL_SIZE * DEC_CELL_DIGIT indicates the maximal
precision that a decimal can capture at most */
#define DEC8_MAX_ALLOWED_PREC (DEC8_CELL_SIZE * DEC8_CELL_DIGIT)

#define DEC8_MAX_EXP_OFFSET DEC8_CELL_SIZE

typedef uint32 c8typ_t;
typedef uint64 cc8typ_t;
typedef c8typ_t cell8_t[DEC8_CELL_SIZE];

typedef struct st_dec8 {
    union {
        struct {
            uint8 sign;   /* 0: for positive integer; 1: for negative integer */
            uint8 ncells; /* number of cells, 0: for unspecified precision */
            int16 expn;   /* the exponent of the number */
        };
        c8typ_t head;
    };

    cell8_t cells;
} dec8_t;

extern const dec8_t DEC8_MIN_INT64;
extern const dec8_t DEC8_ONE;

/* == sizeof(expn & sign & ncells) */
#define DEC8_HEAD_SIZE sizeof(c8typ_t)

#define DEC8_NCELLS(precision) (((precision) + DEC8_CELL_DIGIT - 2) / DEC8_CELL_DIGIT + 1)

/* Get the scientific exponent of a decimal when given its exponent and precision */
#define DEC8_GET_SEXP_BY_PREC0(sexp, prec0) ((int32)(sexp) + (int32)(prec0)-1)
/* Get the scientific exponent of a decimal when given its exponent and cell0 */
#define DEC8_GET_SEXP_BY_CELL0(sexp, c8_0) DEC8_GET_SEXP_BY_PREC0(sexp, cm_count_u32digits(c8_0))
/* Get the scientific exponent of a decimal6 */
#define DEC8_GET_SEXP(dec) DEC8_GET_SEXP_BY_CELL0(D8EXP_2_SEXP((dec)->expn), ((dec)->cells[0]))

/* overflow check */
#define DEC8_OVERFLOW_CHECK(dec) DEC_OVERFLOW_CHECK_BY_SCIEXP(DEC8_GET_SEXP(dec))

/* Get the position of n-th digit of an dec8, when given precision
 * of cell0 (i.e., the position of the dot).
 * @note Both n and the pos begin with 0 */
#define DEC8_POS_N_BY_PREC0(n, prec0) ((n) + (int32)DEC8_CELL_DIGIT - (int32)(prec0))
#define DEC8_POS_N_BY_CELL0(n, cells) ((n) + (int32)DEC8_CELL_DIGIT - cm_count_u32digits((cells)[0]))


#ifdef __cplusplus
extern "C" {
#endif

void cm_dec8_print(const dec8_t *dec, const char *file, uint32 line, const char *func_name, const char *fmt, ...);

/* open debug mode #define  DEBUG_DEC8 */
#ifdef DEBUG_DEC8
#define DEC8_DEBUG_PRINT(dec, fmt, ...) \
    cm_dec8_print(dec, (char *)__FILE_NAME__, (uint32)__LINE__, (char *)__FUNCTION__, fmt, ##__VA_ARGS__)
#else
#define DEC8_DEBUG_PRINT(dec, fmt, ...)
#endif

status_t cm_dec8_finalise(dec8_t *dec, uint32 prec, bool32 allow_overflow);

static inline void cm_zero_dec8(dec8_t *dec)
{
    ZERO_DEC_HEAD(dec);
}

/* Copy the data a decimal */
static inline void cm_dec8_copy(dec8_t *dst, const dec8_t *src)
{
    if (SECUREC_UNLIKELY(dst == src)) {
        return;
    }

    dst->head = src->head;
    /* Another way to Copy the data of decimals is to use loops, for example:
     *    uint32 i = src->ncells;
     *    while (i-- > 0)
     *        dst->cells[i] = src->cells[i];
     * However, this function is performance sensitive, and not too safe when
     * src->ncells is abnormal. By actural testing, using switch..case here
     * the performance can improve at least 1.5%. The testing results are
     *    WHILE LOOP  : 5.64% cm_dec8_copy
     *    SWITCH CASE : 4.14% cm_dec8_copy
     * Another advantage is that the default branch of SWITCH CASE can be used
     * to handle abnormal case, which reduces an IF statement.
     */
    switch (src->ncells) {
        case 7:
            dst->cells[6] = src->cells[6];
            /* fall-through */
        case 6:
            dst->cells[5] = src->cells[5];
            /* fall-through */
        case 5:
            dst->cells[4] = src->cells[4];
            /* fall-through */
        case 4:
            dst->cells[3] = src->cells[3];
            /* fall-through */
        case 3:
            dst->cells[2] = src->cells[2];
            /* fall-through */
        case 2:
            dst->cells[1] = src->cells[1];
            /* fall-through */
        case 1:
            dst->cells[0] = src->cells[0];
            /* fall-through */
        case 0:
            break;
        default:
            /* if error happens, set the error and write the log */
            GS_THROW_ERROR(ERR_ASSERT_ERROR, "copy_dec8: invalid decimal");
            cm_zero_dec8(dst);
            break;
    }
}

/*
 * x1 > x2: return  1
 * x1 = x2: return  0
 * x1 < x2: return -1
 */
static inline int32 cm_dec8_cmp(const dec8_t *x1, const dec8_t *x2)
{
    dec_cmp_diff_sign(x1, x2);
    dec_cmp_same_sign(x1, x2);
    return 0;
}

static inline int32 cm_dec8_cmp_data(const dec8_t *dec1, const dec8_t *dec2, int32 flag)
{
    uint32 cmp_len = MIN(dec1->ncells, dec2->ncells);
    for (uint32 i = 0; i < cmp_len; i++) {
        DECIMAL_TRY_CMP(dec1->cells[i], dec2->cells[i], flag);
    }

    DECIMAL_TRY_CMP(dec1->ncells, dec2->ncells, flag);
    return 0;
}

static inline int32 cm_dec8_simple_cmp(const dec8_t *dec1, const dec8_t *dec2, int32 flag)
{
    DECIMAL_TRY_CMP(dec1->expn, dec2->expn, flag);
    return cm_dec8_cmp_data(dec1, dec2, flag);
}

#define cm_dec8_equal(dec1, dec2) (cm_dec8_cmp(dec1, dec2) == 0)
#define cm_dec8_equal_without_sign(dec1, dec2) (cm_dec8_simple_cmp(dec1, dec2, 1) == 0)

static inline void cm_dec8_trim_zeros(dec8_t *dec)
{
    while (dec->ncells > 0 && dec->cells[dec->ncells - 1] == 0) {
        --dec->ncells;
    }
}

static inline dec8_t *cm_dec8_abs(dec8_t *dec)
{
    dec->sign = DEC_SIGN_PLUS;
    return dec;
}

status_t cm_dec8_to_text(const dec8_t *dec, int32 max_len, text_t *text);

/*
 * Convert a decimal into a text with all precisions
 */
static inline status_t cm_dec8_to_text_all(const dec8_t *dec, text_t *text)
{
    return cm_dec8_to_text(dec, GS_MAX_DEC_OUTPUT_ALL_PREC, text);
}

static inline status_t cm_dec8_to_str_all(const dec8_t *dec, char *str, uint32 str_len)
{
    text_t text;
    text.str = str;
    text.len = 0;

    GS_RETURN_IFERR(cm_dec8_to_text_all(dec, &text));
    if (text.len >= str_len) {
        return GS_ERROR;
    }
    str[text.len] = '\0';
    return GS_SUCCESS;
}

status_t cm_str_to_dec8(const char *str, dec8_t *dec);
num_errno_t cm_numpart_to_dec8(num_part_t *np, dec8_t *dec);
status_t cm_text_to_dec8(const text_t *text, dec8_t *dec);
status_t cm_hext_to_dec8(const text_t *hex_text, dec8_t *dec);
void cm_uint32_to_dec8(uint32 i32, dec8_t *dec);
void cm_int32_to_dec8(int32 i32, dec8_t *dec);
void cm_int64_to_dec8(int64 i64, dec8_t *dec);
status_t cm_real_to_dec8(double real, dec8_t *dec);
status_t cm_real_to_dec8_prec10(double real, dec8_t *dec);
double cm_dec8_to_real(const dec8_t *dec);
status_t cm_dec8_divide(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result);
status_t cm_adjust_dec8(dec8_t *dec, int32 precision, int32 scale);
status_t cm_dec8_to_uint64(const dec8_t *dec, uint64 *u64, round_mode_t rnd_mode);
status_t cm_dec8_to_int64(const dec8_t *dec, int64 *val, round_mode_t rnd_mode);
int32 cm_dec8_to_int64_range(const dec8_t *dec, int64 *i64, round_mode_t rnd_mode);
status_t cm_dec8_to_uint32(const dec8_t *dec, uint32 *i32, round_mode_t rnd_mode);
status_t cm_dec8_to_int32(const dec8_t *dec, int32 *i32, round_mode_t rnd_mode);
status_t cm_dec8_floor(dec8_t *dec);
status_t cm_dec8_ceil(dec8_t *dec);
bool32 cm_dec8_is_integer(const dec8_t *dec);
void cm_uint64_to_dec8(uint64 u64, dec8_t *dec);
status_t cm_dec8_scale(dec8_t *dec, int32 scale, round_mode_t rnd_mode);
status_t cm_dec8_sqrt(const dec8_t *d, dec8_t *r);
status_t cm_dec8_sin(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_cos(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_tan(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_asin(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_acos(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_atan(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_atan2(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result);
status_t cm_dec8_tanh(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_exp(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_ln(const dec8_t *dec, dec8_t *result);
status_t cm_dec8_log(const dec8_t *n2, const dec8_t *n1, dec8_t *result);
status_t cm_dec8_power(const dec8_t *a, const dec8_t *b, dec8_t *y);
status_t cm_dec8_mod(const dec8_t *n2, const dec8_t *n1, dec8_t *y);
void cm_dec8_sign(const dec8_t *dec, dec8_t *result);

/*
 * The core algorithm for addition/substruction/multiplication of two decimals,
 * without truncating the result.
 */
status_t cm_dec8_add_op(const dec8_t *d1, const dec8_t *d2, dec8_t *rs);
status_t cm_dec8_sub_op(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result);
status_t cm_dec8_mul_op(const dec8_t *d1, const dec8_t *d2, dec8_t *rs);

/*
 * Adds two decimal variables and returns a truncated result which precision can not
 * exceed MAX_NUMERIC_BUFF
 */
static inline status_t cm_dec8_add(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result)
{
    if (cm_dec8_add_op(dec1, dec2, result) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, GS_FALSE);
}

/*
 * Subtraction of two decimals, dec1 - dec2 and returns a truncated result
 * which precision can not exceed MAX_NUMERIC_BUFF
 */
static inline status_t cm_dec8_subtract(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result)
{
    if (cm_dec8_sub_op(dec1, dec2, result) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, GS_FALSE);
}

/*
 * multiplication of two decimal
 */
static inline status_t cm_dec8_multiply(const dec8_t *dec1, const dec8_t *dec2, dec8_t *result)
{
    if (cm_dec8_mul_op(dec1, dec2, result) != GS_SUCCESS) {
        return GS_ERROR;
    }
    return cm_dec8_finalise(result, MAX_NUMERIC_BUFF, GS_FALSE);
}

#ifdef __cplusplus
}
#endif
