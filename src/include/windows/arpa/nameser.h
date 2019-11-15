/*
 * @doc
 * @module nameser.h |
 * Copyright (c) 1983, 1989 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)nameser.h	5.25 (Berkeley) 4/3/91
 */

#ifndef _NAMESER_H_
#define	_NAMESER_H_

#include <stdint.h>

#ifndef __P
#  define __P(x) x
#endif

#define dn_skipname            __dn_skipname
int            dn_skipname __P((const u_char *, const u_char *));


/*
 * Define constants based on rfc883
 */
#define PACKETSZ	512		/* maximum packet size */
#define MAXDNAME	256		/* maximum domain name */
#define MAXCDNAME	255		/* maximum compressed domain name */
#define MAXLABEL	63		/* maximum length of domain label */
	/* Number of bytes of fixed size data in query structure */
#define QFIXEDSZ	4
	/* number of bytes of fixed size data in resource record */
#define RRFIXEDSZ	10

#if !defined(MAXHOSTNAME)
#define MAXHOSTNAME MAXCDNAME
#endif

/*
 * Internet nameserver port number
 */
#define NAMESERVER_PORT	53

/*
 * Currently defined opcodes
 */
#define QUERY		0x0		/* standard query */
#define IQUERY		0x1		/* inverse query */
#define STATUS		0x2		/* nameserver status query */
/*#define xxx		0x3		/* 0x3 reserved */
	/* non standard */
#define UPDATEA		0x9		/* add resource record */
#define UPDATED		0xa		/* delete a specific resource record */
#define UPDATEDA	0xb		/* delete all nemed resource record */
#define UPDATEM		0xc		/* modify a specific resource record */
#define UPDATEMA	0xd		/* modify all named resource record */

#define ZONEINIT	0xe		/* initial zone transfer */
#define ZONEREF		0xf		/* incremental zone referesh */

/*
 * Currently defined response codes
 */
#define NOERROR		0		/* no error */
#define FORMERR		1		/* format error */
#define SERVFAIL	2		/* server failure */
#define NXDOMAIN	3		/* non existent domain */
#define NOTIMP		4		/* not implemented */
#define REFUSED		5		/* query refused */
	/* non standard */
#define NOCHANGE	0xf		/* update failed to change db */

/*
 * Type values for resources and queries
 */
#define T_A		1		/* host address */
#define T_NS		2		/* authoritative server */
#define T_MD		3		/* mail destination */
#define T_MF		4		/* mail forwarder */
#define T_CNAME		5		/* connonical name */
#define T_SOA		6		/* start of authority zone */
#define T_MB		7		/* mailbox domain name */
#define T_MG		8		/* mail group member */
#define T_MR		9		/* mail rename name */
#define T_NULL		10		/* null resource record */
#define T_WKS		11		/* well known service */
#define T_PTR		12		/* domain name pointer */
#define T_HINFO		13		/* host information */
#define T_MINFO		14		/* mailbox information */
#define T_MX		15		/* mail routing information */
#define T_TXT		16		/* text strings */
	/* non standard */
#define T_UINFO		100		/* user (finger) information */
#define T_UID		101		/* user ID */
#define T_GID		102		/* group ID */
#define T_UNSPEC	103		/* Unspecified format (binary data) */
	/* Query type values which do not appear in resource records */
#define T_AXFR		252		/* transfer zone of authority */
#define T_MAILB		253		/* transfer mailbox records */
#define T_MAILA		254		/* transfer mail agent records */
#define T_ANY		255		/* wildcard match */

/*
 * Values for class field
 */

#define C_IN		1		/* the arpa internet */
#define C_CHAOS		3		/* for chaos net at MIT */
#define C_HS		4		/* for Hesiod name server at MIT */
	/* Query class values which do not appear in resource records */
#define C_ANY		255		/* wildcard match */

/*
 * Status return codes for T_UNSPEC conversion routines
 */
#define CONV_SUCCESS 0
#define CONV_OVERFLOW -1
#define CONV_BADFMT -2
#define CONV_BADCKSUM -3
#define CONV_BADBUFLEN -4

#ifndef BYTE_ORDER
#define	LITTLE_ENDIAN	1234	/* least-significant byte first (vax) */
#define	BIG_ENDIAN	4321	/* most-significant byte first (IBM, net) */
#define	PDP_ENDIAN	3412	/* LSB first in word, MSW first in long (pdp) */

#if defined(vax) || defined(ns32000) || defined(sun386) || defined(MIPSEL) || \
    defined(BIT_ZERO_ON_RIGHT)
#define BYTE_ORDER	LITTLE_ENDIAN

#endif
#if defined(sel) || defined(pyr) || defined(mc68000) || defined(sparc) || \
    defined(is68k) || defined(tahoe) || defined(ibm032) || defined(ibm370) || \
    defined(MIPSEB) || defined (BIT_ZERO_ON_LEFT)
#define BYTE_ORDER	BIG_ENDIAN
#endif
#endif /* BYTE_ORDER */

#ifndef BYTE_ORDER
	/* you must determine what the correct bit order is for your compiler */
	#define BYTE_ORDER LITTLE_ENDIAN	/* for Intel x86 series */
#endif
/*
 * Structure for query header, the order of the fields is machine and
 * compiler dependent, in our case, the bits within a byte are assignd
 * least significant first, while the order of transmition is most
 * significant first.  This requires a somewhat confusing rearrangement.
 */

#if defined (_WINDLL) || (_WIN32)
/* define UNIX types */
#include <winsock.h>
#endif

typedef struct {
	u_short	id;		/* query identification number */
#if BYTE_ORDER == BIG_ENDIAN
			/* fields in third byte */
	u_char	qr:1;		/* response flag */
	u_char	opcode:4;	/* purpose of message */
	u_char	aa:1;		/* authoritive answer */
	u_char	tc:1;		/* truncated message */
	u_char	rd:1;		/* recursion desired */
			/* fields in fourth byte */
	u_char	ra:1;		/* recursion available */
	u_char	pr:1;		/* primary server required (non standard) */
	u_char	unused:2;	/* unused bits */
	u_char	rcode:4;	/* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
			/* fields in third byte */
	u_char	rd:1;		/* recursion desired */
	u_char	tc:1;		/* truncated message */
	u_char	aa:1;		/* authoritive answer */
	u_char	opcode:4;	/* purpose of message */
	u_char	qr:1;		/* response flag */
			/* fields in fourth byte */
	u_char	rcode:4;	/* response code */
	u_char	unused:2;	/* unused bits */
	u_char	pr:1;		/* primary server required (non standard) */
	u_char	ra:1;		/* recursion available */
#endif
			/* remaining bytes */
	u_short	qdcount;	/* number of question entries */
	u_short	ancount;	/* number of answer entries */
	u_short	nscount;	/* number of authority entries */
	u_short	arcount;	/* number of resource entries */
} HEADER;

/*
 * Defines for handling compressed domain names
 */
#define INDIR_MASK	0xc0

/*
 * Structure for passing resource records around.
 */
struct rrec {
	short	r_zone;			/* zone number */
	short	r_class;		/* class number */
	short	r_type;			/* type number */
	u_long	r_ttl;			/* time to live */
	int	r_size;			/* size of data area */
	char	*r_data;		/* pointer to data */
};

extern	u_short	_getshort();
extern	u_long	_getlong();

/*
 * Inline versions of get/put short/long.
 * Pointer is advanced; we assume that both arguments
 * are lvalues and will already be in registers.
 * cp MUST be u_char *.
 */
#define GETSHORT(s, cp) { \
	(s) = *(cp)++ << 8; \
	(s) |= *(cp)++; \
}

#define GETLONG(l, cp) { \
	(l) = *(cp)++ << 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; (l) <<= 8; \
	(l) |= *(cp)++; \
}


#define PUTSHORT(s, cp) { \
	*(cp)++ = (s) >> 8; \
	*(cp)++ = (s); \
}

/*
 * Warning: PUTLONG destroys its first argument.
 */
#define PUTLONG(l, cp) { \
	(cp)[3] = l; \
	(cp)[2] = (l >>= 8); \
	(cp)[1] = (l >>= 8); \
	(cp)[0] = l >> 8; \
	(cp) += sizeof(u_long); \
}

/*
 * Define constants based on RFC 883, RFC 1034, RFC 1035
 */
#define NS_PACKETSZ        512        /*%< default UDP packet size */
#define NS_MAXDNAME        1025        /*%< maximum domain name */
#define NS_MAXMSG        65535        /*%< maximum message size */
#define NS_MAXCDNAME        255        /*%< maximum compressed domain name */
#define NS_MAXLABEL        63        /*%< maximum length of domain label */
#define NS_HFIXEDSZ        12        /*%< #/bytes of fixed data in header */
#define NS_QFIXEDSZ        4        /*%< #/bytes of fixed data in query */
#define NS_RRFIXEDSZ        10        /*%< #/bytes of fixed data in r record */
#define NS_INT32SZ        4        /*%< #/bytes of data in a uint32_t */
#define NS_INT16SZ        2        /*%< #/bytes of data in a uint16_t */
#define NS_INT8SZ        1        /*%< #/bytes of data in a uint8_t */
#define NS_INADDRSZ        4        /*%< IPv4 T_A */
#define NS_IN6ADDRSZ        16        /*%< IPv6 T_AAAA */
#define NS_CMPRSFLGS        0xc0        /*%< Flag bits indicating name compression. */
#define NS_DEFAULTPORT        53        /*%< For both TCP and UDP. */
/*
 * These can be expanded with synonyms, just keep ns_parse.c:ns_parserecord()
 * in synch with it.
 */
typedef enum __ns_sect {
        ns_s_qd = 0,                /*%< Query: Question. */
        ns_s_zn = 0,                /*%< Update: Zone. */
        ns_s_an = 1,                /*%< Query: Answer. */
        ns_s_pr = 1,                /*%< Update: Prerequisites. */
        ns_s_ns = 2,                /*%< Query: Name servers. */
        ns_s_ud = 2,                /*%< Update: Update. */
        ns_s_ar = 3,                /*%< Query|Update: Additional records. */
        ns_s_max = 4
} ns_sect;
/*%
 * This is a message handle.  It is caller allocated and has no dynamic data.
 * This structure is intended to be opaque to all but ns_parse.c, thus the
 * leading _'s on the member names.  Use the accessor functions, not the _'s.
 */
typedef struct __ns_msg {
        const unsigned char        *_msg, *_eom;
        uint16_t                _id, _flags, _counts[ns_s_max];
        const unsigned char        *_sections[ns_s_max];
        ns_sect                        _sect;
        int                        _rrnum;
        const unsigned char        *_msg_ptr;
} ns_msg;
/* Private data structure - do not use from outside library. */
struct _ns_flagdata {  int mask, shift;  };
extern const struct _ns_flagdata _ns_flagdata[];
/* Accessor macros - this is part of the public interface. */
#define ns_msg_id(handle) ((handle)._id + 0)
#define ns_msg_base(handle) ((handle)._msg + 0)
#define ns_msg_end(handle) ((handle)._eom + 0)
#define ns_msg_size(handle) ((handle)._eom - (handle)._msg)
#define ns_msg_count(handle, section) ((handle)._counts[section] + 0)
/*%
 * This is a parsed record.  It is caller allocated and has no dynamic data.
 */
typedef        struct __ns_rr {
        char                        name[NS_MAXDNAME];
        uint16_t                type;
        uint16_t                rr_class;
        uint32_t                ttl;
        uint16_t                rdlength;
        const unsigned char *        rdata;
} ns_rr;
/* Accessor macros - this is part of the public interface. */
#define ns_rr_name(rr)        (((rr).name[0] != '\0') ? (rr).name : ".")
#define ns_rr_type(rr)        ((ns_type)((rr).type + 0))
#define ns_rr_class(rr)        ((ns_class)((rr).rr_class + 0))
#define ns_rr_ttl(rr)        ((rr).ttl + 0)
#define ns_rr_rdlen(rr)        ((rr).rdlength + 0)
#define ns_rr_rdata(rr)        ((rr).rdata + 0)
/*%
 * These don't have to be in the same order as in the packet flags word,
 * and they can even overlap in some cases, but they will need to be kept
 * in synch with ns_parse.c:ns_flagdata[].
 */
typedef enum __ns_flag {
        ns_f_qr,                /*%< Question/Response. */
        ns_f_opcode,                /*%< Operation code. */
        ns_f_aa,                /*%< Authoritative Answer. */
        ns_f_tc,                /*%< Truncation occurred. */
        ns_f_rd,                /*%< Recursion Desired. */
        ns_f_ra,                /*%< Recursion Available. */
        ns_f_z,                        /*%< MBZ. */
        ns_f_ad,                /*%< Authentic Data (DNSSEC). */
        ns_f_cd,                /*%< Checking Disabled (DNSSEC). */
        ns_f_rcode,                /*%< Response code. */
        ns_f_max
} ns_flag;
/*%
 * Currently defined opcodes.
 */
typedef enum __ns_opcode {
        ns_o_query = 0,                /*%< Standard query. */
        ns_o_iquery = 1,        /*%< Inverse query (deprecated/unsupported). */
        ns_o_status = 2,        /*%< Name server status query (unsupported). */
                                /* Opcode 3 is undefined/reserved. */
        ns_o_notify = 4,        /*%< Zone change notification. */
        ns_o_update = 5,        /*%< Zone update message. */
        ns_o_max = 6
} ns_opcode;
/*%
 * Currently defined response codes.
 */
typedef        enum __ns_rcode {
        ns_r_noerror = 0,        /*%< No error occurred. */
        ns_r_formerr = 1,        /*%< Format error. */
        ns_r_servfail = 2,        /*%< Server failure. */
        ns_r_nxdomain = 3,        /*%< Name error. */
        ns_r_notimpl = 4,        /*%< Unimplemented. */
        ns_r_refused = 5,        /*%< Operation refused. */
        /* these are for BIND_UPDATE */
        ns_r_yxdomain = 6,        /*%< Name exists */
        ns_r_yxrrset = 7,        /*%< RRset exists */
        ns_r_nxrrset = 8,        /*%< RRset does not exist */
        ns_r_notauth = 9,        /*%< Not authoritative for zone */
        ns_r_notzone = 10,        /*%< Zone of record different from zone section */
        ns_r_max = 11,
        /* The following are EDNS extended rcodes */
        ns_r_badvers = 16,
        /* The following are TSIG errors */
        ns_r_badsig = 16,
        ns_r_badkey = 17,
        ns_r_badtime = 18
} ns_rcode;
/* BIND_UPDATE */
typedef enum __ns_update_operation {
        ns_uop_delete = 0,
        ns_uop_add = 1,
        ns_uop_max = 2
} ns_update_operation;
/*%
 * This structure is used for TSIG authenticated messages
 */
struct ns_tsig_key {
        char name[NS_MAXDNAME], alg[NS_MAXDNAME];
        unsigned char *data;
        int len;
};
typedef struct ns_tsig_key ns_tsig_key;
/*%
 * This structure is used for TSIG authenticated TCP messages
 */
struct ns_tcp_tsig_state {
        int counter;
        struct dst_key *key;
        void *ctx;
        unsigned char sig[NS_PACKETSZ];
        int siglen;
};
typedef struct ns_tcp_tsig_state ns_tcp_tsig_state;
#define NS_TSIG_FUDGE 300
#define NS_TSIG_TCP_COUNT 100
#define NS_TSIG_ALG_HMAC_MD5 "HMAC-MD5.SIG-ALG.REG.INT"
#define NS_TSIG_ERROR_NO_TSIG -10
#define NS_TSIG_ERROR_NO_SPACE -11
#define NS_TSIG_ERROR_FORMERR -12
/*%
 * Currently defined type values for resources and queries.
 */
typedef enum __ns_type
  {
    ns_t_invalid = 0,
    ns_t_a = 1,
    ns_t_ns = 2,
    ns_t_md = 3,
    ns_t_mf = 4,
    ns_t_cname = 5,
    ns_t_soa = 6,
    ns_t_mb = 7,
    ns_t_mg = 8,
    ns_t_mr = 9,
    ns_t_null = 10,
    ns_t_wks = 11,
    ns_t_ptr = 12,
    ns_t_hinfo = 13,
    ns_t_minfo = 14,
    ns_t_mx = 15,
    ns_t_txt = 16,
    ns_t_rp = 17,
    ns_t_afsdb = 18,
    ns_t_x25 = 19,
    ns_t_isdn = 20,
    ns_t_rt = 21,
    ns_t_nsap = 22,
    ns_t_nsap_ptr = 23,
    ns_t_sig = 24,
    ns_t_key = 25,
    ns_t_px = 26,
    ns_t_gpos = 27,
    ns_t_aaaa = 28,
    ns_t_loc = 29,
    ns_t_nxt = 30,
    ns_t_eid = 31,
    ns_t_nimloc = 32,
    ns_t_srv = 33,
    ns_t_atma = 34,
    ns_t_naptr = 35,
    ns_t_kx = 36,
    ns_t_cert = 37,
    ns_t_a6 = 38,
    ns_t_dname = 39,
    ns_t_sink = 40,
    ns_t_opt = 41,
    ns_t_apl = 42,
    ns_t_ds = 43,
    ns_t_sshfp = 44,
    ns_t_ipseckey = 45,
    ns_t_rrsig = 46,
    ns_t_nsec = 47,
    ns_t_dnskey = 48,
    ns_t_dhcid = 49,
    ns_t_nsec3 = 50,
    ns_t_nsec3param = 51,
    ns_t_tlsa = 52,
    ns_t_smimea = 53,
    ns_t_hip = 55,
    ns_t_ninfo = 56,
    ns_t_rkey = 57,
    ns_t_talink = 58,
    ns_t_cds = 59,
    ns_t_cdnskey = 60,
    ns_t_openpgpkey = 61,
    ns_t_csync = 62,
    ns_t_spf = 99,
    ns_t_uinfo = 100,
    ns_t_uid = 101,
    ns_t_gid = 102,
    ns_t_unspec = 103,
    ns_t_nid = 104,
    ns_t_l32 = 105,
    ns_t_l64 = 106,
    ns_t_lp = 107,
    ns_t_eui48 = 108,
    ns_t_eui64 = 109,
    ns_t_tkey = 249,
    ns_t_tsig = 250,
    ns_t_ixfr = 251,
    ns_t_axfr = 252,
    ns_t_mailb = 253,
    ns_t_maila = 254,
    ns_t_any = 255,
    ns_t_uri = 256,
    ns_t_caa = 257,
    ns_t_avc = 258,
    ns_t_ta = 32768,
    ns_t_dlv = 32769,
    ns_t_max = 65536
  } ns_type;
/*%
 * Values for class field
 */
typedef enum __ns_class {
        ns_c_invalid = 0,        /*%< Cookie. */
        ns_c_in = 1,                /*%< Internet. */
        ns_c_2 = 2,                /*%< unallocated/unsupported. */
        ns_c_chaos = 3,                /*%< MIT Chaos-net. */
        ns_c_hs = 4,                /*%< MIT Hesiod. */
        /* Query class values which do not appear in resource records */
        ns_c_none = 254,        /*%< for prereq. sections in update requests */
        ns_c_any = 255,                /*%< Wildcard match. */
        ns_c_max = 65536
} ns_class;
/* Certificate type values in CERT resource records.  */
typedef enum __ns_cert_types {
        cert_t_pkix = 1,        /*%< PKIX (X.509v3) */
        cert_t_spki = 2,        /*%< SPKI */
        cert_t_pgp  = 3,        /*%< PGP */
        cert_t_url  = 253,        /*%< URL private type */
        cert_t_oid  = 254        /*%< OID private type */
} ns_cert_types;
/*%
 * EDNS0 extended flags and option codes, host order.
 */
#define NS_OPT_DNSSEC_OK        0x8000U
#define NS_OPT_NSID                3


#define	ns_msg_getflag		__ns_msg_getflag
#define ns_get16		__ns_get16
#define ns_get32		__ns_get32
#define ns_put16		__ns_put16
#define ns_put32		__ns_put32
#define ns_initparse		__ns_initparse
#define ns_skiprr		__ns_skiprr
#define ns_parserr		__ns_parserr
#define	ns_sprintrr		__ns_sprintrr
#define	ns_sprintrrf		__ns_sprintrrf
#define	ns_format_ttl		__ns_format_ttl
#define	ns_parse_ttl		__ns_parse_ttl
#define ns_datetosecs		__ns_datetosecs
#define	ns_name_ntol		__ns_name_ntol
#define	ns_name_ntop		__ns_name_ntop
#define	ns_name_pton		__ns_name_pton
#define	ns_name_unpack		__ns_name_unpack
#define	ns_name_pack		__ns_name_pack
#define	ns_name_compress	__ns_name_compress
#define	ns_name_uncompress	__ns_name_uncompress
#define	ns_name_skip		__ns_name_skip
#define	ns_name_rollback	__ns_name_rollback
#define	ns_sign			__ns_sign
#define	ns_sign2		__ns_sign2
#define	ns_sign_tcp		__ns_sign_tcp
#define	ns_sign_tcp2		__ns_sign_tcp2
#define	ns_sign_tcp_init	__ns_sign_tcp_init
#define ns_find_tsig		__ns_find_tsig
#define	ns_verify		__ns_verify
#define	ns_verify_tcp		__ns_verify_tcp
#define	ns_verify_tcp_init	__ns_verify_tcp_init
#define	ns_samedomain		__ns_samedomain
#define	ns_subdomain		__ns_subdomain
#define	ns_makecanon		__ns_makecanon
#define	ns_samename		__ns_samename


int		ns_msg_getflag __P((ns_msg, int));
u_int		ns_get16 __P((const u_char *));
u_long		ns_get32 __P((const u_char *));
void		ns_put16 __P((u_int, u_char *));
void		ns_put32 __P((u_long, u_char *));
int		ns_initparse __P((const u_char *src, int n, ns_msg *handle)) {return -1;}
int		ns_skiprr __P((const u_char *, const u_char *, ns_sect, int));
int		ns_parserr __P((ns_msg *msg, ns_sect sect, int n, ns_rr *rr)) {return -1;}
int		ns_sprintrr __P((const ns_msg *, const ns_rr *,
				 const char *, const char *, char *, size_t));
int		ns_sprintrrf __P((const u_char *, size_t, const char *,
				  ns_class, ns_type, u_long, const u_char *,
				  size_t, const char *, const char *,
				  char *, size_t));
int		ns_format_ttl __P((u_long, char *, size_t));
int		ns_parse_ttl __P((const char *, u_long *));
uint32_t 	ns_datetosecs __P((const char *cp, int *errp));
int		ns_name_ntol __P((const u_char *, u_char *, size_t));
int		ns_name_ntop __P((const u_char *, char *, size_t));
int		ns_name_pton __P((const char *, u_char *, size_t));
int		ns_name_unpack __P((const u_char *, const u_char *,
				    const u_char *, u_char *, size_t));
int		ns_name_pack __P((const u_char *, u_char *, int,
				  const u_char **, const u_char **));
int		ns_name_uncompress __P((const u_char *a, const u_char *b,
					const u_char *c, char *d, size_t n)) {return -1;}
int		ns_name_compress __P((const char *, u_char *, size_t,
				      const u_char **, const u_char **));
int		ns_name_skip __P((const u_char **, const u_char *));
void		ns_name_rollback __P((const u_char *, const u_char **,
				      const u_char **));
int		ns_sign __P((u_char *, int *, int, int, void *,
			     const u_char *, int, u_char *, int *, time_t));
int		ns_sign2 __P((u_char *, int *, int, int, void *,
			      const u_char *, int, u_char *, int *, time_t,
			      u_char **, u_char **));
int		ns_sign_tcp __P((u_char *, int *, int, int,
				 ns_tcp_tsig_state *, int));
int		ns_sign_tcp2 __P((u_char *, int *, int, int,
				  ns_tcp_tsig_state *, int,
				  u_char **, u_char **));
int		ns_sign_tcp_init __P((void *, const u_char *, int,
					ns_tcp_tsig_state *));
u_char		*ns_find_tsig __P((u_char *, u_char *));
int		ns_verify __P((u_char *, int *, void *,
			       const u_char *, int, u_char *, int *,
			       time_t *, int));
int		ns_verify_tcp __P((u_char *, int *, ns_tcp_tsig_state *, int));
int		ns_verify_tcp_init __P((void *, const u_char *, int,
					ns_tcp_tsig_state *));
int		ns_samedomain __P((const char *, const char *));
int		ns_subdomain __P((const char *, const char *));
int		ns_makecanon __P((const char *, char *, size_t));
int		ns_samename __P((const char *, const char *));

/*%
 * Inline versions of get/put short/long.  Pointer is advanced.
 */
#define NS_GET16(s, cp) do { \
        const unsigned char *t_cp = (const unsigned char *)(cp); \
        (s) = ((uint16_t)t_cp[0] << 8) \
            | ((uint16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
} while (0)
#define NS_GET32(l, cp) do { \
        const unsigned char *t_cp = (const unsigned char *)(cp); \
        (l) = ((uint32_t)t_cp[0] << 24) \
            | ((uint32_t)t_cp[1] << 16) \
            | ((uint32_t)t_cp[2] << 8) \
            | ((uint32_t)t_cp[3]) \
            ; \
        (cp) += NS_INT32SZ; \
} while (0)
#define NS_PUT16(s, cp) do { \
        uint16_t t_s = (uint16_t)(s); \
        unsigned char *t_cp = (unsigned char *)(cp); \
        *t_cp++ = t_s >> 8; \
        *t_cp   = t_s; \
        (cp) += NS_INT16SZ; \
} while (0)
#define NS_PUT32(l, cp) do { \
        uint32_t t_l = (uint32_t)(l); \
        unsigned char *t_cp = (unsigned char *)(cp); \
        *t_cp++ = t_l >> 24; \
        *t_cp++ = t_l >> 16; \
        *t_cp++ = t_l >> 8; \
        *t_cp   = t_l; \
        (cp) += NS_INT32SZ; \
} while (0)

u_int
ns_get16(const u_char *src) {
    u_int dst;

    NS_GET16(dst, src);
    return (dst);
}

u_long
ns_get32(const u_char *src) {
    u_long dst;

    NS_GET32(dst, src);
    return (dst);
}

void
ns_put16(u_int src, u_char *dst) {
    NS_PUT16(src, dst);
}

void
ns_put32(u_long src, u_char *dst) {
    NS_PUT32(src, dst);
}

#endif /* !_NAMESER_H_ */

