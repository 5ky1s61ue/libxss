
#include "libinjection.h"
#include "libinjection_xss.h"
#include "libinjection_html5.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef enum attribute {
    TYPE_NONE
    , TYPE_BLACK     /* ban always */
    , TYPE_ATTR_URL   /* attribute value takes a URL-like object */
    , TYPE_STYLE
    , TYPE_ATTR_INDIRECT  /* attribute *name* is given in *value* */
} attribute_t;


static attribute_t is_black_attr(const char* s, size_t len, char fingerprint[], int flag);
static int is_black_tag(const char* s, size_t len, char fingerprint[]);
static int is_black_url(const char* s, size_t len, char fingerprint[]);
static int cstrcasecmp_with_null(const char *a, const char *b, size_t n);
static int html_decode_char_at(const char* src, size_t len, size_t* consumed);
static int htmlencode_startswith(const char* prefix, const char *src, size_t n);


typedef struct stringtype {
    const char* name;
    attribute_t atype;
    const char* id;
} stringtype_t;

typedef struct oymap{
 const char* name;
 const char* id;   
}oymap_t;


static const int gsHexDecodeMap[256] = {
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    0,   1,   2,   3,   4,   5,   6,   7,   8,   9, 256, 256,
    256, 256, 256, 256, 256,  10,  11,  12,  13,  14,  15, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256,  10,  11,  12,  13,  14,  15, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256, 256,
    256, 256, 256, 256
};

static int html_decode_char_at(const char* src, size_t len, size_t* consumed)
{
    int val = 0;
    size_t i;
    int ch;

    if (len == 0 || src == NULL) {
        *consumed = 0;
        return -1;
    }

    *consumed = 1;
    if (*src != '&' || len < 2) {
        return (unsigned char)(*src);
    }


    if (*(src+1) != '#') {
        /* normally this would be for named entities
         * but for this case we don't actually care
         */
        return '&';
    }

    if (*(src+2) == 'x' || *(src+2) == 'X') {
        ch = (unsigned char) (*(src+3));
        ch = gsHexDecodeMap[ch];
        if (ch == 256) {
            /* degenerate case  '&#[?]' */
            return '&';
        }
        val = ch;
        i = 4;
        while (i < len) {
            ch = (unsigned char) src[i];
            if (ch == ';') {
                *consumed = i + 1;
                return val;
            }
            ch = gsHexDecodeMap[ch];
            if (ch == 256) {
                *consumed = i;
                return val;
            }
            val = (val * 16) + ch;
            if (val > 0x1000FF) {
                return '&';
            }
            ++i;
        }
        *consumed = i;
        return val;
    } else {
        i = 2;
        ch = (unsigned char) src[i];
        if (ch < '0' || ch > '9') {
            return '&';
        }
        val = ch - '0';
        i += 1;
        while (i < len) {
            ch = (unsigned char) src[i];
            if (ch == ';') {
                *consumed = i + 1;
                return val;
            }
            if (ch < '0' || ch > '9') {
                *consumed = i;
                return val;
            }
            val = (val * 10) + (ch - '0');
            if (val > 0x1000FF) {
                return '&';
            }
            ++i;
        }
        *consumed = i;
        return val;
    }
}


/*
 * view-source:
 * data:
 * javascript:
 */
static stringtype_t BLACKATTR[] = {
    { "ACTION", TYPE_ATTR_URL, "^01" }     /* form */
    , { "ATTRIBUTENAME", TYPE_ATTR_INDIRECT, "*01" } /* SVG allow indirection of attribute names */
    , { "BY", TYPE_ATTR_URL, "^02" }         /* SVG */
    , { "BACKGROUND", TYPE_ATTR_URL, "^03" } /* IE6, O11 */
    , { "DATAFORMATAS", TYPE_BLACK, "%01" }  /* IE */
    , { "DATASRC", TYPE_BLACK, "%02" }       /* IE */
    , { "DYNSRC", TYPE_ATTR_URL, "^04" }     /* Obsolete img attribute */
    , { "FILTER", TYPE_STYLE, "&01" }        /* Opera, SVG inline style */
    , { "FORMACTION", TYPE_ATTR_URL, "^05" } /* HTML 5 */
    , { "FOLDER", TYPE_ATTR_URL, "^06" }     /* Only on A tags, IE-only */
    , { "FROM", TYPE_ATTR_URL, "^07" }       /* SVG */
    , { "HANDLER", TYPE_ATTR_URL, "^08" }    /* SVG Tiny, Opera */
    , { "HREF", TYPE_ATTR_URL, "^09" }
    , { "LOWSRC", TYPE_ATTR_URL, "^10" }     /* Obsolete img attribute */
    , { "POSTER", TYPE_ATTR_URL, "^11" }     /* Opera 10,11 */
    , { "SRC", TYPE_ATTR_URL, "^12" }
    , { "STYLE", TYPE_STYLE, "&02" }
    , { "TO", TYPE_ATTR_URL, "^13" }         /* SVG */
    , { "VALUES", TYPE_ATTR_URL, "^14" }     /* SVG */
    , { "XLINK:HREF", TYPE_ATTR_URL, "^15" }
    , { NULL, TYPE_NONE, "01" }
};

/* xmlns */
/* `xml-stylesheet` > <eval>, <if expr=> */

/*
  static const char* BLACKATTR[] = {
  "ATTRIBUTENAME",
  "BACKGROUND",
  "DATAFORMATAS",
  "HREF",
  "SCROLL",
  "SRC",
  "STYLE",
  "SRCDOC",
  NULL
  };
*/


static oymap_t BLACKTAGMAP[] = {
    { "APPLET", "01" },
    { "AUDIO", "02" },
    { "BASE", "03" },
    { "COMMENT", "04" },
    { "EMBED", "05" },
    { "FRAME", "06" },
    { "FRAMESET", "07" },
    { "HANDLER", "08" },
    { "IFRAME", "09" },
    { "IMPORT", "10" },
    { "ISINDEX", "11" },
    { "LINK", "12" },
    { "LISTENER", "13" },
    { "META", "14" },
    { "NOSCRIPT", "15" },
    { "OBJECT", "16" },
    { "SCRIPT", "17" },
    { "STYLE", "18" },
    { "VMLFRAME", "19" },
    { "XML", "20" },
    { "XSS", "21" },
    { NULL , "00"}
};


static int cstrcasecmp_with_null(const char *a, const char *b, size_t n)
{
    char ca;
    char cb;
    /* printf("Comparing to %s %.*s\n", a, (int)n, b); */
    while (n-- > 0) {
        cb = *b++;
        if (cb == '\0') continue;

        ca = *a++;

        if (cb >= 'a' && cb <= 'z') {
            cb -= 0x20;
        }
        /* printf("Comparing %c vs %c with %d left\n", ca, cb, (int)n); */
        if (ca != cb) {
            return 1;
        }
    }

    if (*a == 0) {
        /* printf(" MATCH \n"); */
        return 0;
    } else {
        return 1;
    }
}

/*
 * Does an HTML encoded  binary string (const char*, length) start with
 * a all uppercase c-string (null terminated), case insensitive!
 *
 * also ignore any embedded nulls in the HTML string!
 *
 * return 1 if match / starts with
 * return 0 if not
 */
static int htmlencode_startswith(const char *a, const char *b, size_t n)
{
    size_t consumed;
    int cb;
    int first = 1;
    /* printf("Comparing %s with %.*s\n", a,(int)n,b); */
    while (n > 0) {
        if (*a == 0) {
            /* printf("Match EOL!\n"); */
            return 1;
        }
        cb = html_decode_char_at(b, n, &consumed);
        b += consumed;
        n -= consumed;

        if (first && cb <= 32) {
            /* ignore all leading whitespace and control characters */
            continue;
        }
        first = 0;

        if (cb == 0) {
            /* always ignore null characters in user input */
            continue;
        }

        if (cb == 10) {
            /* always ignore vertical tab characters in user input */
            /* who allows this?? */
            continue;
        }

        if (cb >= 'a' && cb <= 'z') {
            /* upcase */
            cb -= 0x20;
        }

        if (*a != (char) cb) {
            /* printf("    %c != %c\n", *a, cb); */
            /* mismatch */
            return 0;
        }
        a++;
    }

    return (*a == 0) ? 1 : 0;
}

static int is_black_tag(const char* s, size_t len, char fingerprint[])
{
    /* const char** black; */
    oymap_t* black;
    if (len < 3) {
        return 0;
    }

    black = BLACKTAGMAP;
    while (black->name != NULL) {
        if (cstrcasecmp_with_null(black->name, s, len) == 0) {
            /* printf("Got black tag %s\n", *black); */
            strcat(fingerprint, "@BT");
            strcat(fingerprint, black->id);
            return 1;
        }
        black += 1;
    }

    /* anything SVG related */
    if ((s[0] == 's' || s[0] == 'S') &&
        (s[1] == 'v' || s[1] == 'V') &&
        (s[2] == 'g' || s[2] == 'G')) {
        /*        printf("Got SVG tag \n"); */
        strcat(fingerprint, "@BT21");
        return 1;
    }

    /* Anything XSL(t) related */
    if ((s[0] == 'x' || s[0] == 'X') &&
        (s[1] == 's' || s[1] == 'S') &&
        (s[2] == 'l' || s[2] == 'L')) {
        /*      printf("Got XSL tag\n"); */
        strcat(fingerprint, "@BT22");
        return 1;
    }

    return 0;
}

static attribute_t is_black_attr(const char* s, size_t len, char fingerprint[], int flag)
{
    stringtype_t* black;

    if (len < 2) {
        return TYPE_NONE;
    }

    if (len >= 5) {
        /* JavaScript on.* */
        if ((s[0] == 'o' || s[0] == 'O') && (s[1] == 'n' || s[1] == 'N')) {
            /* printf("Got JavaScript on- attribute name\n"); */
            if(flag == 0){
                strcpy(fingerprint, "#BA%03");
            }else{
                strcat(fingerprint, "%03");
            }
            return TYPE_BLACK;
        }



        /* XMLNS can be used to create arbitrary tags */
        if (cstrcasecmp_with_null("XMLNS", s, 5) == 0) {
            /*      printf("Got XMLNS and XLINK tags\n"); */
            if(flag == 0){
                strcpy(fingerprint, "#BA%04");
            }else{
                strcat(fingerprint, "%04");
            }
            return TYPE_BLACK;
        }

        if (cstrcasecmp_with_null("XLINK", s, 5) == 0) {
            if(flag == 0){
                strcpy(fingerprint, "#BA%05");
            }else{
                strcat(fingerprint, "%05");
            }
            return TYPE_BLACK;
        }
    }

    black = BLACKATTR;
    while (black->name != NULL) {
        if (cstrcasecmp_with_null(black->name, s, len) == 0) {
            /*      printf("Got banned attribute name %s\n", black->name); */
            if(flag == 0){
                strcpy(fingerprint, "#BA");
            }
            strcat(fingerprint, black->id);
            return black->atype;
        }
        black += 1;
    }

    return TYPE_NONE;
}

static int is_black_url(const char* s, size_t len, char fingerprint[])
{

    static const char* data_url = "DATA";
    static const char* viewsource_url = "VIEW-SOURCE";

    /* obsolete but interesting signal */
    static const char* vbscript_url = "VBSCRIPT";

    /* covers JAVA, JAVASCRIPT, + colon */
    static const char* javascript_url = "JAVA";

    /* skip whitespace */
    while (len > 0 && (*s <= 32 || *s >= 127)) {
        /*
         * HEY: this is a signed character.
         *  We are intentionally skipping high-bit characters too
         *  since they are not ASCII, and Opera sometimes uses UTF-8 whitespace.
         *
         * Also in EUC-JP some of the high bytes are just ignored.
         */
        ++s;
        --len;
    }

    if (htmlencode_startswith(data_url, s, len)) {
        strcat(fingerprint, "BU01");
        return 1;
    }

    if (htmlencode_startswith(viewsource_url, s, len)) {
        strcat(fingerprint, "BU02");
        return 1;
    }

    if (htmlencode_startswith(javascript_url, s, len)) {
        strcat(fingerprint, "BU03");
        return 1;
    }

    if (htmlencode_startswith(vbscript_url, s, len)) {
        strcat(fingerprint, "BU04");
        return 1;
    }
    return 0;
}

int libinjection_is_xss(const char* s, size_t len, char fingerprint[], int flags)
{
    h5_state_t h5;
    attribute_t attr = TYPE_NONE;

    libinjection_h5_init(&h5, s, len, (enum html5_flags) flags);
    while (libinjection_h5_next(&h5)) {
        if (h5.token_type != ATTR_VALUE) {
            attr = TYPE_NONE;
        }

        if (h5.token_type == DOCTYPE) {
            strcpy(fingerprint, "!01"); 
            return 1;
        } else if (h5.token_type == TAG_NAME_OPEN) {
            if (is_black_tag(h5.token_start, h5.token_len, fingerprint)) {
                return 1;
            }
        } else if (h5.token_type == ATTR_NAME) {
            strcpy(fingerprint, "");
            attr = is_black_attr(h5.token_start, h5.token_len, fingerprint, 0);
        } else if (h5.token_type == ATTR_VALUE) {
            /*
             * IE6,7,8 parsing works a bit differently so
             * a whole <script> or other black tag might be hiding
             * inside an attribute value under HTML 5 parsing
             * See http://html5sec.org/#102
             * to avoid doing a full reparse of the value, just
             * look for "<".  This probably need adjusting to
             * handle escaped characters
             */
            /*
              if (memchr(h5.token_start, '<', h5.token_len) != NULL) {
              return 1;
              }
            */

            switch (attr) {
            case TYPE_NONE:
                break;
            case TYPE_BLACK:
                return 1;
            case TYPE_ATTR_URL:
                if (is_black_url(h5.token_start, h5.token_len, fingerprint)) {
                    return 1;
                }
                break;
            case TYPE_STYLE:
                return 1;
            case TYPE_ATTR_INDIRECT:
                /* an attribute name is specified in a _value_ */
                if (is_black_attr(h5.token_start, h5.token_len, fingerprint, 1)) {
                    return 1;
                }
                break;
/*
  default:
  assert(0);
*/
            }
            attr = TYPE_NONE;
        } else if (h5.token_type == TAG_COMMENT) {
            /* IE uses a "`" as a tag ending char */
            if (memchr(h5.token_start, '`', h5.token_len) != NULL) {
                strcpy(fingerprint, "$01");
                return 1;
            }

            /* IE conditional comment */
            if (h5.token_len > 3) {
                if (h5.token_start[0] == '[' &&
                    (h5.token_start[1] == 'i' || h5.token_start[1] == 'I') &&
                    (h5.token_start[2] == 'f' || h5.token_start[2] == 'F')) {
                    strcpy(fingerprint, "$02");
                    return 1;
                }
                if ((h5.token_start[0] == 'x' || h5.token_start[0] == 'X') &&
                    (h5.token_start[1] == 'm' || h5.token_start[1] == 'M') &&
                    (h5.token_start[2] == 'l' || h5.token_start[2] == 'L')) {
                    strcpy(fingerprint, "$03");
                    return 1;
                }
            }

            if (h5.token_len > 5) {
                /*  IE <?import pseudo-tag */
                if (cstrcasecmp_with_null("IMPORT", h5.token_start, 6) == 0) {
                    strcpy(fingerprint, "$04");
                    return 1;
                }

                /*  XML Entity definition */
                if (cstrcasecmp_with_null("ENTITY", h5.token_start, 6) == 0) {
                    strcpy(fingerprint, "$05");
                    return 1;
                }
            }
        }
    }
    return 0;
}


/*
 * wrapper
 */
int libinjection_xss(const char* s, size_t len, char fingerprint[])
{
    if (libinjection_is_xss(s, len, fingerprint, DATA_STATE)) {
        strcat(fingerprint, "\0");
        return 1;
    }
    if (libinjection_is_xss(s, len, fingerprint, VALUE_NO_QUOTE)) {
        strcat(fingerprint, "\0");
        return 1;
    }
    if (libinjection_is_xss(s, len, fingerprint, VALUE_SINGLE_QUOTE)) {
        strcat(fingerprint, "\0");
        return 1;
    }
    if (libinjection_is_xss(s, len, fingerprint, VALUE_DOUBLE_QUOTE)) {
        strcat(fingerprint, "\0");
        return 1;
    }
    if (libinjection_is_xss(s, len, fingerprint, VALUE_BACK_QUOTE)) {
        strcat(fingerprint, "\0");
        return 1;
    }

    return 0;
}
