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

/* null = "null" */
static int lept_parse_null(lept_context *c, lept_value *v) {
    EXPECT(c, 'n');
    const char *p = c->json;
    if (p[0] != 'u' || p[1] != 'l' || p[2] != 'l') {
        return LEPT_PARSE_INVALID_VALUE;
    }
    c->json += 3;
    v->type = LEPT_NULL;
    return LEPT_PARSE_OK;
}

/* true = "true" */
static int lept_parse_true(lept_context *c, lept_value *v) {
    EXPECT(c, 't');
    const char *p = c->json;
    if (p[0] != 'r' || p[1] != 'u' || p[2] != 'e') {
        return LEPT_PARSE_INVALID_VALUE;
    }
    c->json += 3;
    v->type = LEPT_TRUE;
    return LEPT_PARSE_OK;
}

/* false = "false" */
static int lept_parse_false(lept_context *c, lept_value *v) {
    EXPECT(c, 'f');
    const char *p = c->json;
    if (p[0] != 'a' || p[1] != 'l' || p[2] != 's' || p[3] != 'e') {
        return LEPT_PARSE_INVALID_VALUE;
    }
    c->json += 4;
    v->type = LEPT_FALSE;
    return LEPT_PARSE_OK;
}

/* value = null / false / true */
static int lept_parse_value(lept_context *c, lept_value *v) {
    switch (*c->json) {
        case 'n' :
            return lept_parse_null(c, v);
        case 't' :
            return lept_parse_true(c, v);
        case 'f' :
            return lept_parse_false(c, v);
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
    ret = lept_parse_value(&c, v);
    if (ret != LEPT_PARSE_OK) {
        return ret;
    }
    lept_parse_whitespace(&c);
    if (*c.json) {
        return LEPT_PARSE_ROOT_NOT_SINGULAR;
    }
}

lept_type lept_get_type(const lept_value *v) {
    return v->type;
}

