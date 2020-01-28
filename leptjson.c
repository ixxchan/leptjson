#include "leptjson.h"
#include <stdio.h>
#include <assert.h>

#define EXPECT(c, ch) do { assert(*(c)->json == (ch)); (c)->json++; } while(0)

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

/* value = null / false / true */
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
            return LEPT_PARSE_INVALID_VALUE;
    }
}

/* json-text = ws value ws */
int lept_parse(lept_value *v, const char *json) {
    lept_context c;
    int ret;

    assert(v != NULL);
    c.json = json;
    v->type = LEPT_NULL;
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json) {
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


