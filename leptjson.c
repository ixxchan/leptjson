#include "leptjson.h"
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <math.h>
#include <string.h>

#ifndef LEPT_PARSE_STACK_INIT_SIZE
#define LEPT_PARSE_STACK_INIT_SIZE 256
#endif

#ifndef LEPT_PARSE_STRINGIFY_INIT_SIZE
#define LEPT_PARSE_STRINGIFY_INIT_SIZE 256
#endif

#define EXPECT(c, ch) do { assert(*(c)->json == (ch)); (c)->json++; } while(0)
#define ISDIGIT(ch)         ((ch) >= '0' && (ch) <= '9')
#define ISDIGIT1TO9(ch)     ((ch) >= '1' && (ch) <= '9')
#define PASS_DIGITS(p) while (ISDIGIT(*(p))) { (p)++;}

#define PUTF(c, format, len, ...) sprintf(lept_context_push(c, len), format, ##__VA_ARGS__)
#define PUTS(c, s, len) memcpy(lept_context_push((c), len), s, len)
#define PUTC(c, ch) do { *(char *)lept_context_push((c), 1) = (ch);} while(0)

typedef struct {
    const char *json;
    char *stack;
    size_t size, top;
} lept_context;

static void *lept_context_push(lept_context *c, size_t size) {
    void *ret;
    assert(size > 0);
    if (c->top + size >= c->size) {
        if (c->size == 0)
            c->size = LEPT_PARSE_STACK_INIT_SIZE;
        while (c->top + size >= c->size)
            c->size += c->size >> 1U;  /* c->size * 1.5 */
        c->stack = (char *) realloc(c->stack, c->size);
    }
    ret = c->stack + c->top;
    c->top += size;
    return ret;
}

static void *lept_context_pop(lept_context *c, size_t size) {
    assert(c->top >= size);
    return c->stack + (c->top -= size);
}

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
    const char *p = c->json;

    /* validate number begin */
    /* negative */
    if (*p == '-') {
        p++;
    }

    /* int part */
    if (ISDIGIT1TO9(*p)) {
        p++;
        PASS_DIGITS(p);
    } else if (*p == '0') {
        p++;
    } else {
        return LEPT_PARSE_INVALID_VALUE;
    }

    /* frac part */
    if (*p == '.') {
        p++;
        if (!ISDIGIT(*p)) {
            return LEPT_PARSE_INVALID_VALUE;
        }
        p++;
        PASS_DIGITS(p);
    }

    /* exp part */
    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') {
            p++;
        }
        if (!ISDIGIT(*p)) {
            return LEPT_PARSE_INVALID_VALUE;
        }
        p++;
        PASS_DIGITS(p);
    }
    /* validate number end */

    v->u.n = strtod(c->json, NULL);
    c->json = p;
    if (errno == ERANGE && (v->u.n == HUGE_VAL || v->u.n == -HUGE_VAL)) {
        v->type = LEPT_NULL;
        return LEPT_PARSE_NUMBER_TOO_BIG;
    }
    v->type = LEPT_NUMBER;
    return LEPT_PARSE_OK;
}

static const char *lept_parse_hex4(const char *p, unsigned *u) {
    char ch;
    *u = 0;
    for (int _i = 0; _i < 4; ++_i) {
        ch = *p++;
        if (ISDIGIT(ch)) {
            *u = *u * 16 + ch - '0';
        } else if ('A' <= ch && ch <= 'F') {
            *u = *u * 16 + ch - 'A' + 10;
        } else if ('a' <= ch && ch <= 'f') {
            *u = *u * 16 + ch - 'a' + 10;
        } else {
            return NULL;
        }
    }
    return p;
}

static void lept_encode_utf8(lept_context *c, unsigned u) {
    assert(u <= 0x10FFFF);
    if (u <= 0x007F) {
        PUTC(c, (char) u);
    } else if (u <= 0x07FF) {
        PUTC(c, 0xC0u | (u >> 6u)); /* 0xC0 = 11000000 */
        PUTC(c, 0x80u | (u & 0x3Fu)); /* 0x80 = 10000000, 0x3F = 00111111 */
    } else if (u <= 0xFFFF) {
        PUTC(c, 0xE0u | (u >> 12u)); /* 0xE0 = 11100000 */
        PUTC(c, 0x80u | ((u >> 6u) & 0x3Fu));
        PUTC(c, 0x80u | (u & 0x3Fu));
    } else {
        PUTC(c, 0xF0u | (u >> 18u)); /* 0xF0 = 11110000 */
        PUTC(c, 0x80u | ((u >> 12u) & 0x3Fu));
        PUTC(c, 0x80u | ((u >> 6u) & 0x3Fu));
        PUTC(c, 0x80u | (u & 0x3Fu));
    }
}

#define RET_STRING_ERROR(ret) do { c->top = head; return ret; } while(0)
#define IS_SURROGATE_H(u) ((u) >= 0xD800 && (u) <= 0xDBFF)
#define IS_SURROGATE_L(u) ((u) >= 0xDC00 && (u) <= 0xDFFF)

static int lept_parse_string_raw(lept_context *c, char **str, size_t *len) {
    size_t head = c->top;
    unsigned u, H, L;
    const char *p;
    EXPECT(c, '\"');
    p = c->json;
    while (1) {
        char ch = *p++;
        switch (ch) {
            case '\"':
                *len = c->top - head;
                *str = (char *) malloc(*len + 1);
                memcpy(*str, lept_context_pop(c, *len), *len);
                (*str)[*len] = '\0';
                c->json = p;
                return LEPT_PARSE_OK;
            case '\0':
                RET_STRING_ERROR(LEPT_PARSE_MISS_QUOTATION_MARK);
            case '\\': // escape
                switch (*p++) {
                    case '"':
                        PUTC(c, '\"');
                        break;
                    case '\\':
                        PUTC(c, '\\');
                        break;
                    case '/':
                        PUTC(c, '/');
                        break;
                    case 'b':
                        PUTC(c, '\b');
                        break;
                    case 'f':
                        PUTC(c, '\f');
                        break;
                    case 'n':
                        PUTC(c, '\n');
                        break;
                    case 'r':
                        PUTC(c, '\r');
                        break;
                    case 't':
                        PUTC(c, '\t');
                        break;
                    case 'u':
                        if ((p = lept_parse_hex4(p, &u)) == NULL) {
                            RET_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                        }
                        if (IS_SURROGATE_H(u)) {
                            H = u;
                            if (*p++ != '\\' || *p++ != 'u') { /* expect low surrogate, but it ends */
                                RET_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }
                            if ((p = lept_parse_hex4(p, &L)) == NULL) {
                                RET_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_HEX);
                            }
                            if (!IS_SURROGATE_L(L)) {
                                RET_STRING_ERROR(LEPT_PARSE_INVALID_UNICODE_SURROGATE);
                            }
                            u = 0x10000 + (H - 0xD800) * 0x400 + (L - 0xDC00);
                        }
                        lept_encode_utf8(c, u);
                        break;
                    default:
                        RET_STRING_ERROR(LEPT_PARSE_INVALID_STRING_ESCAPE);
                }
                break;
            default: // unescaped
                if (ch >= '\x20') {
                    PUTC(c, ch);
                } else {
                    RET_STRING_ERROR(LEPT_PARSE_INVALID_STRING_CHAR);
                }
        }
    }
}

static int lept_parse_string(lept_context *c, lept_value *v) {
    int ret;
    char *str;
    size_t len;
    if ((ret = lept_parse_string_raw(c, &str, &len)) == LEPT_PARSE_OK) {
//        lept_set_string(v, str, len);
        /* lept_set_string will copy string, so simply transfer ownership may be better */
        v->u.s.s = str;
        v->u.s.len = len;
        v->type = LEPT_STRING;
    }
    return ret;
}

static int lept_parse_value(lept_context *c, lept_value *v);

#define RET_ARRAY_ERROR(ret)\
    do {\
        assert((c->top - head) % sizeof(lept_value) == 0);\
        while(c->top != head) lept_free((lept_value *)lept_context_pop(c, sizeof(lept_value)));\
        return ret;\
    } while(0)

static int lept_parse_array(lept_context *c, lept_value *v) {
    size_t size = 0, head = c->top;
    int ret;
    EXPECT(c, '[');
    lept_parse_whitespace(c);
    if (*c->json == ']') {
        c->json++;
        v->type = LEPT_ARRAY;
        v->u.a.size = 0;
        v->u.a.e = NULL;
        return LEPT_PARSE_OK;
    }
    while (1) {
        lept_value e;
        lept_init(&e);
        if ((ret = lept_parse_value(c, &e)) != LEPT_PARSE_OK) {
            RET_ARRAY_ERROR(ret);
        }
        memcpy(lept_context_push(c, sizeof(lept_value)), &e, sizeof(lept_value));
        size++;
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else if (*c->json == ']') {
            c->json++;
            v->type = LEPT_ARRAY;
            v->u.a.size = size;
            v->u.a.e = (lept_value *) malloc(size * sizeof(lept_value));
            memcpy(v->u.a.e, lept_context_pop(c, size * sizeof(lept_value)), size * sizeof(lept_value));
            return LEPT_PARSE_OK;
        } else {
            RET_ARRAY_ERROR(LEPT_PARSE_MISS_COMMA_OR_SQUARE_BRACKET);
        }
    }
}

static void lept_free_member(lept_member *m);

#define RET_OBJ_ERROR(ret)\
    do {\
        assert((c->top - head) % sizeof(lept_member) == 0);\
        while(c->top != head) lept_free_member((lept_member *)lept_context_pop(c, sizeof(lept_member)));\
        return ret;\
    } while(0)

static int lept_parse_object(lept_context *c, lept_value *v) {
    size_t size = 0, head = c->top;
    int ret;
    EXPECT(c, '{');
    lept_parse_whitespace(c);
    if (*c->json == '}') {
        c->json++;
        v->type = LEPT_OBJECT;
        v->u.o.size = 0;
        v->u.o.m = NULL;
        return LEPT_PARSE_OK;
    }
    while (1) {
        lept_member m;
        m.k = NULL;
        lept_init(&m.v);
        if (*c->json != '\"') {
            RET_OBJ_ERROR(LEPT_PARSE_MISS_KEY);
        }
        if ((ret = lept_parse_string_raw(c, &m.k, &m.klen)) != LEPT_PARSE_OK) {
            RET_OBJ_ERROR(ret);
        }
        lept_parse_whitespace(c);
        if (*c->json != ':') {
            /* should clean parsed string first */
            free(m.k);
            RET_OBJ_ERROR(LEPT_PARSE_MISS_COLON);
        }
        c->json++;
        lept_parse_whitespace(c);
        if ((ret = lept_parse_value(c, &m.v)) != LEPT_PARSE_OK) {
            RET_OBJ_ERROR(ret);
        }
        memcpy(lept_context_push(c, sizeof(lept_member)), &m, sizeof(lept_member));
        size++;
        m.k = NULL; /* ownership is transferred to member on stack */
        lept_parse_whitespace(c);
        if (*c->json == ',') {
            c->json++;
            lept_parse_whitespace(c);
        } else if (*c->json == '}') {
            c->json++;
            v->type = LEPT_OBJECT;
            v->u.o.size = size;
            v->u.o.m = (lept_member *) malloc(size * sizeof(lept_member));
            memcpy(v->u.o.m, lept_context_pop(c, size * sizeof(lept_member)), size * sizeof(lept_member));
            return LEPT_PARSE_OK;
        } else {
            RET_OBJ_ERROR(LEPT_PARSE_MISS_COMMA_OR_CURLY_BRACKET);
        }
    }
}

/* value = null / false / true / number / string / array / object */
static int lept_parse_value(lept_context *c, lept_value *v) {
    switch (*c->json) {
        case 'n' :
            return lept_parse_literal(c, v, "null", LEPT_NULL);
        case 't' :
            return lept_parse_literal(c, v, "true", LEPT_TRUE);
        case 'f' :
            return lept_parse_literal(c, v, "false", LEPT_FALSE);
        case '\"' :
            return lept_parse_string(c, v);
        case '[' :
            return lept_parse_array(c, v);
        case '{':
            return lept_parse_object(c, v);
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
    c.stack = NULL;
    c.size = c.top = 0;
    lept_init(v);
    lept_parse_whitespace(&c);
    if ((ret = lept_parse_value(&c, v)) == LEPT_PARSE_OK) {
        lept_parse_whitespace(&c);
        if (*c.json) {
            v->type = LEPT_NULL;
            ret = LEPT_PARSE_ROOT_NOT_SINGULAR;
        }
    }
    assert(c.top == 0);
    free(c.stack);
    return ret;
}

lept_type lept_get_type(const lept_value *v) {
    assert(v != NULL);
    return v->type;
}

static void lept_free_member(lept_member *m) {
    if (m->k) free(m->k);
    lept_free(&m->v);
}

void lept_free(lept_value *v) {
    assert(v != NULL);
    if (v->type == LEPT_STRING) {
        free(v->u.s.s);
    } else if (v->type == LEPT_ARRAY) {
        for (int i = 0; i < v->u.a.size; ++i) {
            lept_free(&v->u.a.e[i]);
        }
        free(v->u.a.e);
    } else if (v->type == LEPT_OBJECT) {
        for (int i = 0; i < v->u.o.size; ++i) {
            lept_free_member(&v->u.o.m[i]);
        }
        free(v->u.o.m);
    }
    v->type = LEPT_NULL;
}

int lept_get_boolean(const lept_value *v) {
    assert(v != NULL);
    if (v->type == LEPT_TRUE) {
        return 1;
    } else if (v->type == LEPT_FALSE) {
        return 0;
    } else {
        assert(0);
    }
}

void lept_set_boolean(lept_value *v, int b) {
    assert(v != NULL);
    lept_free(v);
    v->type = b ? LEPT_TRUE : LEPT_FALSE;
}

double lept_get_number(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_NUMBER);
    return v->u.n;
}

void lept_set_number(lept_value *v, double n) {
    assert(v != NULL);
    lept_free(v);
    v->u.n = n;
    v->type = LEPT_NUMBER;
}

const char *lept_get_string(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.s;
}

size_t lept_get_string_length(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_STRING);
    return v->u.s.len;
}

void lept_set_string(lept_value *v, const char *s, size_t len) {
    assert(v != NULL && (s != NULL || len == 0));
    lept_free(v);
    v->u.s.s = (char *) malloc(len + 1);
    memcpy(v->u.s.s, s, len);
    v->u.s.s[len] = '\0';
    v->u.s.len = len;
    v->type = LEPT_STRING;
}

size_t lept_get_array_size(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    return v->u.a.size;
}

lept_value *lept_get_array_element(const lept_value *v, size_t index) {
    assert(v != NULL && v->type == LEPT_ARRAY);
    assert(index < v->u.a.size);
    return &v->u.a.e[index];
}

size_t lept_get_object_size(const lept_value *v) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    return v->u.o.size;
}

const char *lept_get_object_key(const lept_value *v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].k;
}

size_t lept_get_object_key_length(const lept_value *v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return v->u.o.m[index].klen;
}

lept_value *lept_get_object_value(const lept_value *v, size_t index) {
    assert(v != NULL && v->type == LEPT_OBJECT);
    assert(index < v->u.o.size);
    return &v->u.o.m[index].v;
}

size_t lept_find_object_index(const lept_value *v, const char *key, size_t klen) {
    size_t i;
    assert(v != NULL && v->type == LEPT_OBJECT && key != NULL);
    for (i = 0; i < v->u.o.size; i++)
        if (v->u.o.m[i].klen == klen && memcmp(v->u.o.m[i].k, key, klen) == 0)
            return i;
    return LEPT_KEY_NOT_EXIST;
}

lept_value *lept_find_object_value(const lept_value *v, const char *key, size_t klen) {
    size_t index = lept_find_object_index(v, key, klen);
    return index != LEPT_KEY_NOT_EXIST ? &v->u.o.m[index].v : NULL;
}

#if 0
/* stringify one utf-8 encoded unicode character */
static void lept_stringify_utf8(lept_context *c, char **s) {
    unsigned u, H, L;
    unsigned char ch = **s;
    if (ch < 0x20) { /* \u00xx */
        sprintf(lept_context_push(c, 6), "\\u%04X", ch);
    } else if (ch < 0x007f) {
        PUTC(c, ch);
    } else if (ch >> 5u == 6) { /* U+0080 ~ U+07FF, 110xxxxx 10xxxxxx */
        u = ch & 0x3Fu; /* 0x1F = 00011111 */
        ch = *(*s)++;
        u = (u << 6u) | (0x3Fu & ch); /* 0x3F = 00111111 */
        PUTF(c, "\\u%04X", 6, u);
    } else if (ch >> 4u == 14) { /* U+0800 ~ U+FFFF, 1110xxxx 10xxxxxx 10xxxxxx */
        u = ch & 0xFu;
        ch = *(*s)++;
        u = (u << 4u) | (0x3Fu & ch);
        ch = *(*s)++;
        u = (u << 6u) | (0x3Fu & ch);
        PUTF(c, "\\u%04X", 6, u);
    } else { /* U+10000 ~ U+10FFFF, 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx */
        u = ch & 0x7u;
        ch = *(*s)++;
        u = (u << 3u) | (0x3Fu & ch);
        ch = *(*s)++;
        u = (u << 6u) | (0x3Fu & ch);
        ch = *(*s)++;
        u = (u << 6u) | (0x3Fu & ch);
        u -= 0x10000;
        H = ((u >> 10u) & 0x3FFu) + 0xD800; /* 0x3FF = 1111111111, 10bits */
        L = (u & 0x3FFu) + 0xDC00;
        PUTF(c, "\\u%04X\\u%04X", 12, H, L);
    }
}
#endif

static void lept_stringify_string(lept_context *c, char *s, size_t len) {
    PUTC(c, '\"');
    for (char *p = s; p - s < len; ++p) {
        char ch = *p;
        switch (ch) {
            case '\"':
                PUTS(c, "\\\"", 2);
                break;
            case '\\':
                PUTS(c, "\\\\", 2);
                break;
            case '\b':
                PUTS(c, "\\b", 2);
                break;
            case '\f':
                PUTS(c, "\\f", 2);
                break;
            case '\n':
                PUTS(c, "\\n", 2);
                break;
            case '\r':
                PUTS(c, "\\r", 2);
                break;
            case '\t':
                PUTS(c, "\\t", 2);
                break;
            default:
//                lept_stringify_utf8(c, &p);
                /* output UTF-8 bytes, do not decode */
                if (ch < 0x20) { /* \u00xx */
                    sprintf(lept_context_push(c, 6), "\\u%04X", ch);
                } else {
                    PUTC(c, ch);
                }
        }
    }
    PUTC(c, '\"');
}

static void lept_stringify_value(lept_context *c, const lept_value *v) {
    switch (v->type) {
        case LEPT_NULL:
            PUTS(c, "null", 4);
            break;
        case LEPT_FALSE:
            PUTS(c, "false", 5);
            break;
        case LEPT_TRUE:
            PUTS(c, "true", 4);
            break;
        case LEPT_NUMBER:
            c->top -= 32 - PUTF(c, "%.17g", 32, v->u.n);
            break;
        case LEPT_STRING:
            lept_stringify_string(c, v->u.s.s, v->u.s.len);
            break;
        case LEPT_ARRAY:
            PUTC(c, '[');
            for (int i = 0; i < v->u.a.size; ++i) {
                if (i != 0)PUTC(c, ',');
                lept_stringify_value(c, &v->u.a.e[i]);
            }
            PUTC(c, ']');
            break;
        case LEPT_OBJECT:
            PUTC(c, '{');
            for (int i = 0; i < v->u.o.size; ++i) {
                if (i != 0)PUTC(c, ',');
                lept_member *m = &v->u.o.m[i];
                lept_stringify_string(c, m->k, m->klen);
                PUTC(c, ':');
                lept_stringify_value(c, &m->v);
            }
            PUTC(c, '}');
            break;
    }
}

char *lept_stringify(const lept_value *v, size_t *length) {
    lept_context c;
    assert(v != NULL);
    c.stack = (char *) malloc(c.size = LEPT_PARSE_STRINGIFY_INIT_SIZE);
    c.top = 0;
    lept_stringify_value(&c, v);
    if (length)
        *length = c.top;
    PUTC(&c, '\0');
    return c.stack;
}

int lept_is_equal(const lept_value *lhs, const lept_value *rhs) {
    assert(lhs && rhs);
    if (lhs->type != rhs->type)
        return 0;
    switch (lhs->type) {
        case LEPT_NUMBER:
            return lhs->u.n == rhs->u.n;
        case LEPT_STRING:
            return lhs->u.s.len == rhs->u.s.len && 0 == memcmp(lhs->u.s.s, rhs->u.s.s, lhs->u.s.len);
        case LEPT_ARRAY:
            if (lhs->u.a.size != rhs->u.a.size) {
                return 0;
            }
            for (size_t i = 0; i < lhs->u.a.size; ++i) {
                if (!lept_is_equal(&lhs->u.a.e[i], &rhs->u.a.e[i])) {
                    return 0;
                }
            }
            return 1;
        case LEPT_OBJECT:
            if (lhs->u.o.size != rhs->u.o.size) {
                return 0;
            }
            for (size_t i = 0; i < lhs->u.o.size; ++i) {
                lept_member *ml = &lhs->u.o.m[i];
                lept_value *vr = lept_find_object_value(rhs, ml->k, ml->klen);
                if (vr == NULL || !lept_is_equal(&ml->v, vr)) {
                    return 0;
                }
            }
            return 1;
        default:
            return 1;
    }
}