#include "leptjson.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>

#define EXPECT(c, ch) do { assert(*(c)->json == (ch)); (c)->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')
#define PASS_DIGITS(c) do { while (ISDIGIT(*(c)->json)) { (c)->json++;} } while(0)

typedef struct {
    const char *json;
} lept_context;

/* ws = *(%x20 / %x09 / %x0A / %x0D) */
static void lept_parse_whitespace(lept_context *c) {
    const char *p = c->json;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') {
        p++;
    }
    c->json = p;
}

/* "null" / "true" / "false" */
static int lept_parse_literal(lept_context *c, lept_value *v, const char *literal, lept_type t) {
    EXPECT(c, literal[0]);
    literal++;
    int i;
    for (i = 0; literal[i]; ++i) {
        if (literal[i] != c->json[i]) {
            return LEPT_PARSE_INVALID_VALUE;
        }
    }
    c->json += i;
    v->type = t;
    return LEPT_PARSE_OK;
}

/*
 * number = [ "-" ] int [ frac ] [ exp ]
 * int = "0" / digit1-9 *digit
 * frac = "." 1*digit
 * exp = ("e" / "E") ["-" / "+"] 1*digit
 * */
static int lept_parse_number(lept_context *c, lept_value *v) {
    const char *start = c->json;

    /* validate number begin */
    /* negative */
    if (*c->json == '-') {
        c->json++;
    }

    /* int part */
    if (ISDIGIT1TO9(*c->json)) {
        c->json++;
        PASS_DIGITS(c);
    } else if (*c->json == '0') {
        c->json++;
    } else {
        return LEPT_PARSE_INVALID_VALUE;
    }

    /* frac part */
    if (*c->json == '.') {
        c->json++;
        if (!ISDIGIT(*c->json)) {
            return LEPT_PARSE_INVALID_VALUE;
        }
        c->json++;
        PASS_DIGITS(c);
    }

    /* exp part */
    if (*c->json == 'e' || *c->json == 'E') {
        c->json++;
        if (*c->json == '+' || *c->json == '-') {
            c->json++;
        }
        if (!ISDIGIT(*c->json)) {
            return LEPT_PARSE_INVALID_VALUE;
        }
        c->json++;
        PASS_DIGITS(c);
    }
    /* validate number end */

    v->n = strtod(start, NULL);
    if (errno == ERANGE && (v->n == HUGE_VAL || v->n == -HUGE_VAL)) {
        v->type = LEPT_NULL;
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

/* value = null / false / true / number */
static int lept_parse_value(lept_context *c, lept_value *v) {
    switch (*c->json) {
        case 'n' :
            return lept_parse_literal(c, v, "null", LEPT_NULL);
        case 't' :
            return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f' :
            return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case '\0' :
            return LEPT_PARSE_EXPECT_VALUE;
        default:
            return lept_parse_number(c, v);
    }
}

/* json-text = ws value ws */
int lept_parse(lept_value *v, const char *json) {
    lept_context c;
    int ret;

    assert(v != NULL);
    assert(json != NULL);
    c.json = json;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json) {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    return ret;
}

lept_type lept_get_type(const lept_value *v) {
    assert(v != NULL);
    return v->type;
}

double lept_get_number(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->n;
}


