/*
 *
 *	@doc RESOLVE
 *
 *
 *	@module res_quer.c | Contains the implementation of res_query,
 *	res_search, and res_querydomain
 *
 * WSHelper DNS/Hesiod Library for WINSOCK
 *
 */

 /*
  * Copyright (c) 1988 Regents of the University of California.
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
  *      This product includes software developed by the University of
  *      California, Berkeley and its contributors.
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
  */

#include <windows.h>
#include <winsock.h>
#include "include/windows/resolv.h"
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <windns.h>

void
__putshort(register u_short s, register u_char *msgp)
{
	msgp[1] = LOBYTE(s);
	msgp[0] = HIBYTE(s);
}

void
__putlong(register u_long l, register u_char *msgp)
{
	msgp[3] = LOBYTE(LOWORD(l));
	msgp[2] = HIBYTE(LOWORD(l));
	msgp[1] = LOBYTE(HIWORD(l));
	msgp[0] = HIBYTE(HIWORD(l));
}

#define MAX_MSG_SIZE 0x8000

#define strcasecmp	stricmp

#ifdef _DEBUG
#define DEBUG
#endif
int
__hostalias(register const char *name, char* abuf);
DNS_STATUS do_res_search(const char *name, int qclass, int type, u_char *retanswer, int retanswerlen, int* anslen);
void __putshort(register u_short, register u_char *);
void __putlong(register u_long, u_char *);
int build_rr(char* p, PDNS_RECORD ptr, int qclass);
int put_qname(char* p, char* qname);



/*
	a generic query interface to the DNS name space. The query is performed with the dnsapi and
	the answer buffer is populated based on the returned RR set.

	\param[in]	name	domain name
	\param[in]	qclass  class of query(such as DNS_CLASS_INTERNET, DNS_CLASS_CSNET, DNS_CLASS_CHAOS,
						DNS_CLASS_HESIOD. Defined in windns.h)
	\param[in]	type	type of query(such as DNS_TYPE_A, DNS_TYPE_NS, DNS_TYPE_MX, DNS_TYPE_SRV. Defined in
						windns.h)
	\param[in]	answer  buffer to put answer in
	\param[in]	anslen	size of the answer buffer. compare the anslen with the return value, if the return
						value is bigger than anslen, it means the answer buffer doesn't contain the complete
						response. You will need to call this function again with a bigger answer buffer if
						you care about the complete response

	\retval		return the size of the response on success, -1 on error


 */
int WINAPI
res_search(const char *name, int qclass, int type, u_char *answer, int anslen)
/* domain name, class and type of query, buffer to put answer, size of answer */
{
	char debstr[80];
	int n = 0;
	DNS_STATUS status;
	char queryname[DNS_MAX_NAME_BUFFER_LENGTH];
	register const char *cp;
	int len = 0;

	char** domain;

	status = -1;
	memset(answer, 0, anslen);
	memset(queryname, 0, sizeof(queryname));

	for (cp = name, n = 0; *cp; cp++)
		if (*cp == '.')
			n++;

	if (n == 0 && !__hostalias(name, queryname) && strlen(queryname) > 0)
	{
		status = do_res_search(queryname, qclass, type, answer, anslen, &len);
		if (status == 0)
			return len;
	}

	strcpy(queryname, name);
	status = do_res_search(queryname, qclass, type, answer, anslen, &len);


	if (status)
	{
		return -1;
	}
	return len;
}

int
put_qname(char* cp, char* qname)
{
	char* p;
	char* temp;
	INT_PTR n = 0;
	INT_PTR i = 0;
	temp = qname;
	while (p = strchr(temp, '.'))
	{
		n = p - temp;
		if (n == 0)
		{
			temp++;
			break;
		}
		cp[0] = (int)n;
		cp++;
		i++;
		strncpy(cp, temp, n);
		temp = p + 1;
		cp = cp + n;
		i = i + n;
	}
	n = strlen(temp);
	if (n > 0)
	{
		cp[0] = (int)n;
		cp++;
		i++;
		strcpy(cp, temp);
		cp = cp + n;
	}
	cp[0] = 0;
	i = i + n + 1;
	return (int)i;
}

DNS_STATUS
do_res_search(const char *queryname, int qclass, int type, u_char *retanswer, int retanswerlen, int* anslen)
{
	PDNS_RECORD pDnsRecord;
	PDNS_RECORD ptr;
	DNS_STATUS status;
	DNS_FREE_TYPE freetype;
	HEADER *hp;
	u_char *cp;
	int  n;
	int i;
	u_char  answer[MAX_MSG_SIZE];
	DWORD options = DNS_QUERY_STANDARD;
	freetype = DnsFreeRecordListDeep;

	memset(answer, 0, MAX_MSG_SIZE);

	status = DnsQuery_A(queryname,                 //pointer to OwnerName
		type,         //Type of the record to be queried
		options,
		NULL,                   //contains DNS server IP address
		&pDnsRecord,                //Resource record comprising the response
		NULL);                     //reserved for future use

	if (status)
		return  status;


	hp = (HEADER *)answer;
	cp = answer + sizeof(HEADER);

	// populating the header
	hp->qr = 1;  // 0 for query 1 for response
	hp->opcode = 0; // standard query
	hp->aa = 1; // authoritative answer
	hp->tc = 0; // no truncation
	hp->ra = 1;  // recursion available
	hp->rcode = NOERROR;
	hp->qdcount = htons(1); // number of question entries
	i = put_qname(cp, (char*)queryname);
	cp = cp + i;
	__putshort(type, (u_char *)cp);
	cp += sizeof(u_short);
	__putshort(qclass, (u_char *)cp);
	cp += sizeof(u_short);

	// get the answer
	for (n = 0, ptr = pDnsRecord; ptr; ptr = ptr->pNext)
	{
		if ((ptr->Flags).S.Section == DNSREC_ANSWER ||
			(type == DNS_TYPE_PTR && (ptr->Flags).S.Section == DNSREC_QUESTION))
		{
			i = build_rr(cp, ptr, qclass);
			cp = cp + i;
			//strcpy(cp, pDnsRecord->pName);
			//cp += strlen(pDnsRecord->pName);
			//cp++;

			n++;
		}
	}
	hp->ancount = htons(n);

	// get the authority
	for (n = 0, ptr = pDnsRecord; ptr; ptr = ptr->pNext)
	{
		if ((ptr->Flags).S.Section == DNSREC_AUTHORITY)
		{
			i = build_rr(cp, ptr, qclass);
			cp = cp + i;

			n++;
		}
	}
	hp->nscount = htons(n);

	// get the additional resource
	for (n = 0, ptr = pDnsRecord; ptr; ptr = ptr->pNext)
	{
		if ((ptr->Flags).S.Section == DNSREC_ADDITIONAL)
		{
			i = build_rr(cp, ptr, qclass);
			cp = cp + i;

			n++;
		}

	}
	hp->arcount = htons(n);

	*anslen = (int)(cp - answer);
	if (*anslen > retanswerlen)
		memcpy(retanswer, answer, retanswerlen); // partial copy
	else
		memcpy(retanswer, answer, *anslen);
	DnsRecordListFree(pDnsRecord, freetype);
	return status;
}

int
build_rr(char* p, PDNS_RECORD ptr, int qclass)
{
	int i = 0;
	int n = 0;
	char* cp = p;
	char* temp = NULL;
	unsigned int index = 0;

	i = put_qname(cp, ptr->pName);
	cp = p + i;

	__putshort(ptr->wType, (u_char *)cp);
	i += sizeof(u_short);
	cp = p + i;
	__putshort(qclass, (u_char *)cp);
	i += sizeof(u_short);
	cp = p + i;
	__putlong(ptr->dwTtl, (u_char*)cp);
	i += sizeof(u_long);
	cp = p + i;
	switch (ptr->wType)
	{
	case DNS_TYPE_A:
		__putshort(sizeof(ptr->Data.A), (u_char*)cp); //RDLENGTH
		i += sizeof(u_short);
		cp = p + i;
		memcpy(cp, &(ptr->Data.A), sizeof(ptr->Data.A));
		i += sizeof(ptr->Data.A);
		break;
	case DNS_TYPE_NS:
	case DNS_TYPE_MD:
	case DNS_TYPE_MF:
	case DNS_TYPE_CNAME:
	case DNS_TYPE_MB:
	case DNS_TYPE_MG:
	case DNS_TYPE_MR:
	case DNS_TYPE_PTR:
		temp = cp;     // hold the spot for RD length
		i += sizeof(u_short);
		cp = p + i;
		n = put_qname(cp, ptr->Data.Ptr.pNameHost);
		i += n;
		__putshort(n, (u_char*)temp); //set RDLENGTH
		break;
	case DNS_TYPE_TEXT:
	case DNS_TYPE_HINFO:
	case DNS_TYPE_ISDN:
	case DNS_TYPE_X25:
		temp = cp; // hold the spot for RDLENGTH
		i += sizeof(u_short);
		cp = p + i;
		n = 0;
		for (index = 0; index < ptr->Data.Txt.dwStringCount; index++)
		{
			*cp = (int)(strlen(ptr->Data.Txt.pStringArray[index]));
			n += *cp;
			n++;
			strcpy(++cp, ptr->Data.Txt.pStringArray[index]);
		}
		i += n;
		__putshort(n, (u_char*)temp); // set RDLENGTH
		break;
	case DNS_TYPE_SRV:
		temp = cp; // hold the spot for RDLENGTH
		i += sizeof(u_short);
		cp = p + i;
		// priority
		__putshort(ptr->Data.Srv.wPriority, (u_char*)cp);
		i += sizeof(u_short);
		cp = p + i;
		//weight
		__putshort(ptr->Data.Srv.wWeight, (u_char*)cp);
		i += sizeof(u_short);
		cp = p + i;
		//port
		__putshort(ptr->Data.Srv.wPort, (u_char*)cp);
		i += sizeof(u_short);
		cp = p + i;

		n = put_qname(cp, ptr->Data.Srv.pNameTarget);
		i += n;
		__putshort((u_short)(n + sizeof(u_short) * 3), (u_char*)temp);

		break;
	case DNS_TYPE_MX:
	case DNS_TYPE_AFSDB:
	case DNS_TYPE_RT:
		temp = cp; // hold the spot for RDLENGTH
		i += sizeof(u_short);
		cp = p + i;
		__putshort(ptr->Data.Mx.wPreference, (u_char*)cp); // put wPreference
		i += sizeof(u_short);
		cp = p + i;
		n = put_qname(cp, ptr->Data.Mx.pNameExchange);
		i += n;
		__putshort((u_short)(n + sizeof(u_short)), (u_char*)temp);
		break;
	case DNS_TYPE_SOA:
		temp = cp; // hold the spot for RDLENGTH
		i += sizeof(u_short);
		cp = p + i;
		// primary server name
		n = put_qname(cp, ptr->Data.Soa.pNamePrimaryServer);
		i += n;
		cp = p + i;
		//the person responsible for this zone.
		n += put_qname(cp, ptr->Data.Soa.pNameAdministrator);
		i += n;
		cp = p + i;
		//SERIAL
		__putlong(ptr->Data.Soa.dwSerialNo, cp);
		n += sizeof(u_long);
		i += sizeof(u_long);
		cp = p + i;
		//refresh
		__putlong(ptr->Data.Soa.dwRefresh, cp);
		n += sizeof(u_long);
		i += sizeof(u_long);
		cp = p + i;
		//retry
		__putlong(ptr->Data.Soa.dwRetry, cp);
		n += sizeof(u_long);
		i += sizeof(u_long);
		cp = p + i;
		// expire
		__putlong(ptr->Data.Soa.dwExpire, cp);
		n += sizeof(u_long);
		i += sizeof(u_long);
		cp = p + i;
		// minimum TTL
		__putlong(ptr->Data.Soa.dwDefaultTtl, cp);
		n += sizeof(u_long);
		i += sizeof(u_long);
		// set RDLength
		__putshort(n, (u_char*)temp);
		break;
	case DNS_TYPE_NULL:
		__putshort((short)ptr->Data.Null.dwByteCount, (u_char*)cp); //RDLENGTH
		i += sizeof(u_short);
		cp = p + i;
		memcpy(cp, ptr->Data.Null.Data, ptr->Data.Null.dwByteCount);
		i += ptr->Data.Null.dwByteCount;
		break;
	case DNS_TYPE_WKS:   // needs more work
		temp = cp; // hold the spot for RDLENGTH
		i += sizeof(u_short);
		cp = p + i;
		// address
		memcpy(cp, &(ptr->Data.Wks.IpAddress), sizeof(ptr->Data.Wks.IpAddress));
		n = sizeof(ptr->Data.Wks.IpAddress);
		i += sizeof(ptr->Data.Wks.IpAddress);
		cp = p + i;
		// protocol
		*cp = ptr->Data.Wks.chProtocol;
		i++;
		n++;
		cp = p + i;
		//bit mask
		memcpy(cp, &(ptr->Data.Wks.BitMask), sizeof(ptr->Data.Wks.BitMask));
		n += sizeof(ptr->Data.Wks.BitMask);
		i += n;
		// set RDLength
		__putshort(n, (u_char*)temp);
		break;
	case DNS_TYPE_MINFO:
	case DNS_TYPE_RP:
		temp = cp; // hold the spot for RDLENGTH
		i += sizeof(u_short);
		cp = p + i;
		// pNameMailbox
		n = put_qname(cp, ptr->Data.Minfo.pNameMailbox);
		i += n;
		cp = p + i;
		// pNameErrorsMailbox;
		n += put_qname(cp, ptr->Data.Minfo.pNameMailbox);
		i += n;
		// set RDLength
		__putshort(n, (u_char*)temp);
		break;
	case DNS_TYPE_AAAA:
		__putshort(sizeof(ptr->Data.AAAA), (u_char*)cp); //RDLENGTH
		i += sizeof(u_short);
		cp = p + i;
		memcpy(cp, &(ptr->Data.AAAA), sizeof(ptr->Data.AAAA));
		i += sizeof(ptr->Data.AAAA);

		break;
	}
	return i;
}


int
__hostalias(register const char *name, char* abuf)
{
	register char *C1, *C2;
	FILE *fp;
	char *file;
	//  char *getenv(), *strcpy(), *strncpy();  // pbh XXX 11/1/96
	char buf[BUFSIZ];


	file = getenv("HOSTALIASES");
	if (file == NULL || (fp = fopen(file, "r")) == NULL)
		return -1;
	buf[sizeof(buf) - 1] = '\0';
	while (fgets(buf, sizeof(buf), fp)) {
		for (C1 = buf; *C1 && !isspace(*C1); ++C1);
		if (!*C1)
			break;
		*C1 = '\0';
		if (!strcasecmp(buf, name)) {
			while (isspace(*++C1));
			if (!*C1)
				break;
			for (C2 = C1 + 1; *C2 && !isspace(*C2); ++C2);
			abuf[sizeof(abuf) - 1] = *C2 = '\0';
			(void)strncpy(abuf, C1, sizeof(abuf) - 1);
			fclose(fp);
			return 0;
		}
	}
	fclose(fp);
	return -1;
}

int  WINAPI rdn_expand(const u_char  *msg, const u_char  *eomorig, const u_char  *comp_dn, char  *exp_dn, int length)
{
    register u_char *cp, *dn;
    register int n, c;
    u_char *eom;
	INT_PTR len = -1;
    int checked = 0;

    dn = exp_dn;
    cp = (u_char *)comp_dn;
    eom = exp_dn + length;
    /*
     * fetch next label in domain name
     */
    while (n = *cp++) {
        /*
         * Check for indirection
         */
        switch (n & INDIR_MASK) {
        case 0:
            if (dn != exp_dn) {
                if (dn >= eom)
                    return (-1);
                *dn++ = '.';
            }
            if (dn+n >= eom)
                return (-1);
            checked += n + 1;
            while (--n >= 0) {
                if ((c = *cp++) == '.') {
                    if (dn + n + 2 >= eom)
                        return (-1);
                    *dn++ = '\\';
                }
                *dn++ = c;
                if (cp >= eomorig)      /* out of range */
                    return(-1);
            }
            break;

        case INDIR_MASK:
            if (len < 0)
                len = cp - comp_dn + 1;
            cp = (u_char *)msg + (((n & 0x3f) << 8) | (*cp & 0xff));
            if (cp < msg || cp >= eomorig)  /* out of range */
                return(-1);
            checked += 2;
            /*
             * Check for loops in the compressed name;
             * if we've looked at the whole message,
             * there must be a loop.
             */
            if (checked >= eomorig - msg)
                return (-1);
            break;

        default:
            return (-1);                    /* flag error */
        }
    }
    *dn = '\0';
    if (len < 0)
        len = cp - comp_dn;
    return (int)(len);
}

/*
 * Skip over a compressed domain name. Return the size or -1.
 */
int __dn_skipname(const u_char *comp_dn, const u_char *eom)
{
    register u_char *cp;
    register int n;

    cp = (u_char *)comp_dn;
    while (cp < eom && (n = *cp++)) {
        /*
         * check for indirection
         */
        switch (n & INDIR_MASK) {
        case 0:         /* normal case, n == len */
            cp += n;
            continue;
        default:        /* illegal type */
            return (-1);
        case INDIR_MASK:        /* indirection */
            cp++;
        }
        break;
    }
    return (int)(cp - comp_dn);
}
