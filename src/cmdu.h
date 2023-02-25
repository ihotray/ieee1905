/*
 * cmdu.h
 * defines structs and functions for TLVs and CMDU manipulation.
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */



#ifndef CMDU_H
#define CMDU_H

#include <stdint.h>
#include <sys/time.h>
#include <libubox/list.h>

#include <easy/easy.h>
#include "bufutil.h"

/** struct cmdu_header - IEEE-1905 CMDU header */
struct cmdu_header {
	uint8_t version;
	uint8_t rsvd;		/**< reserved */
	uint16_t type;
	uint16_t mid;		/**< message id */
	uint8_t fid;		/**< fragment id */
	uint8_t flag;
} __attribute__ ((packed));

#define IS_CMDU_LAST_FRAGMENT(c)	!!((c)->hdr.flag & 0x80)
#define IS_CMDU_RELAY_MCAST(c)		!!((c)->hdr.flag & 0x40)

#define CMDU_SET_LAST_FRAGMENT(c)	(c)->hdr.flag |= 0x80
#define CMDU_SET_RELAY_MCAST(c)		(c)->hdr.flag |= 0x40

#define CMDU_DEFAULT_TIMEOUT		1000

/** struct cmdu_linear - represents a CMDU frame with header and TLVs */
struct cmdu_linear {
	struct cmdu_header hdr;
	uint8_t data[];
} __attribute__ ((packed));


#define TLV_HLEN		3

struct cmdu_frag {
	uint8_t *data;
	uint16_t len;
	struct list_head list;
};

/**
 * @struct cmdu_buff
 * @brief Control structure for a CMDU buffer
 *
 * This structure abstracts out a CMDU frame. In addition to holding pointer
 * to an actual CMDU frame, it holds meta information about the CMDU,
 * such as, for a Rx CMDU which interface it arrived on, sender's macaddress
 * etc.
 *
 * APIs are provided for working with a cmdu_buff. There are functions to
 * parse a cmdu_buff and get the list of TLVs within it, ititerate through TLVs
 * in a CMDU, adding a TLV, peeking a TLV, getting size of a CMDU frame etc.
 *
 * On the transmit and receive path, it is possible to achieve zero-memcpy for
 * CMDU manipulation including inserting/extracting the ethernet frame header.
 */
struct cmdu_buff {
	uint8_t *head;
	uint8_t *data;
	uint8_t *tail;
	uint8_t *end;
	uint8_t dev_macaddr[6];
	char dev_ifname[16];
	uint8_t origin[6];	/* source address of sender */
	uint8_t aladdr[6];	/* AL address of sender (when available) */
	uint32_t flags;
	uint16_t datalen;
	uint16_t len;
	struct cmdu_linear *cdata;
	uint32_t num_frags;
	struct list_head fraglist;
	struct list_head list;
};

/**
 * @enum tlv_presence
 * @brief defines the policy for occurrences of a TLV in a CMDU frame.
 */
enum tlv_presence {
	TLV_PRESENT_UNDEFINED,
	TLV_PRESENT_ONE,		/**< only one tlv of this type present */

	TLV_PRESENT_MORE,		/**< one or more tlvs of this tlv present */
	TLV_PRESENT_ONE_OR_MORE = TLV_PRESENT_MORE,

	TLV_PRESENT_OPTIONAL_ONE,	/**< zero or one of this tlv present */
	TLV_PRESENT_ZERO_OR_ONE = TLV_PRESENT_OPTIONAL_ONE,

	TLV_PRESENT_OPTIONAL_MORE,	/**< zero or more of this tlv present */
	TLV_PRESENT_ZERO_OR_MORE = TLV_PRESENT_OPTIONAL_MORE,

	TLV_PRESENT_NUM,
};

struct tlv_policy {
	uint8_t type;
	uint16_t len;
	uint16_t minlen;
	uint16_t maxlen;
	enum tlv_presence present;
};

/**
 * @struct tlv
 * @brief defines an IEEE-1905 TLV
 */
struct tlv {
	uint8_t type;
	uint16_t len;
	uint8_t data[];
} __attribute__ ((packed));

/**
 * Allocates a TLV
 * @param[in] datalen length of tlv data in bytes
 *
 * @return newly allocated tlv on success, or NULL if failed.
 */
struct tlv *tlv_alloc(uint16_t datalen);

/** Free an allocated TLV */
void tlv_free_linear(struct tlv *t);

/** Zeros out a TLV */
void tlv_zero(struct tlv *t);

/* following functions for internal use only */
int tlv_ok(struct tlv *t, int rem);
struct tlv *tlv_next(struct tlv *t, int *rem);

/** Get length of TLV data */
uint16_t tlv_length(struct tlv *t);

/** Get total length of a TLV including the header */
uint16_t tlv_total_length(struct tlv *t);

/** Helper function to stringify TLV type */
const char *tlv_type2str(uint8_t type);

/* Allocates cmdu_buff to hold 'size' length cmdu payload */
struct cmdu_buff *cmdu_alloc(int size);		// XXX: internal use

/** Allocates cmdu_buff to hold 'size' length cmdu payload */
struct cmdu_buff *cmdu_alloc_frame(int size);

/**
 * Allocates cmdu_buff to hold full-size ethernet frame of 1500 bytes
 *
 * @return newly allocated cmdu_buff on success, or NULL if failed.
 *
 * This function is useful to allocate CMDUs for transmit when size of the
 * payload i.e. TLV data is not known a-priori.
 */
struct cmdu_buff *cmdu_alloc_default(void);

/**
 * Allocates full-sized cmdu_buff without CMDU header info
 *
 * @return newly allocated cmdu_buff on success, or NULL if failed.
 *
 * This function is useful to allocate cmdu_buff for tx/rx of LLDP frames.
 */
struct cmdu_buff *cmdu_alloc_nohdr(void);


/**
 * Convenient function to allocate cmdu_buff that can hold a full-size CMDU
 * @param[in] type  CMDU type
 * @param[in|out] mid  CMDU mid if nonzero, or valid mid returned
 *
 * @return newly allocated cmdu_buff on success, or NULL if failed.
 *
 * If mid passed is 0, then the next valid mid gets assigned to the newly
 * allocated cmdu.
 */
struct cmdu_buff *cmdu_alloc_simple(uint16_t type, uint16_t *mid);


/**
 * Prepare cmdu_buff from a received CMDU whose fields are known
 * @param[in] type  CMDU type
 * @param[in|out] mid  CMDU mid if nonzero, or valid mid returned
 * @param[in] ifname  interface name through which the CMDU is received
 * @param[in] origin  macaddress of the source that sent the CMDU
 * @param[in] tlvs  flattened TLV data bytes
 * @param[in] tlvslen  length of the TLV data bytes
 *
 * @return newly allocated cmdu_buff on success, or NULL if failed.
 */
struct cmdu_buff *cmdu_alloc_custom(uint16_t type, uint16_t *mid,
				    char *ifname, uint8_t *origin,
				    uint8_t *tlvs, uint32_t tlvslen);


struct cmdu_buff *cmdu_realloc(struct cmdu_buff *c, size_t size);


/** Free CMDU allocated through cmdu_alloc*() functions */
void cmdu_free(struct cmdu_buff *c);

void cmdu_set_type(struct cmdu_buff *c, uint16_t type);
uint16_t cmdu_get_type(struct cmdu_buff *c);
void cmdu_set_mid(struct cmdu_buff *c, uint16_t mid);
uint16_t cmdu_get_mid(struct cmdu_buff *c);
void cmdu_set_fid(struct cmdu_buff *c, uint8_t fid);
uint8_t cmdu_get_fid(struct cmdu_buff *c);
uint8_t *cmdu_get_origin(struct cmdu_buff *c);

/** Full size of a CMDU frame including the CMDU header */
int cmdu_size(struct cmdu_buff *c);

/** Get a valid CMDU 'mid' that can be used next */
uint16_t cmdu_get_next_mid(void);

int cmdu_midgen_init(void);
void cmdu_midgen_exit(void);

/** Helper function to get expected response CMDU for a request CMDU */
uint16_t cmdu_expect_response(uint16_t req_type);

/** Helper function to check if a CMDU is of relay multicast type */
int cmdu_should_relay(uint16_t type);

/** Function to check if a CMDU type is valid */
int is_cmdu_type_valid(uint16_t type);

/** Function to check if a CMDU is of response type */
int is_cmdu_type_response(uint16_t type);

/** Function to check if a CMDU type must include atleast one TLV */
int is_cmdu_tlv_required(uint16_t type);

/** Parsing status of received CMDU */
enum CMDU_STATUS {
	CMDU_STATUS_OK,
	CMDU_STATUS_ERR_TLV_MALFORMED,
	CMDU_STATUS_ERR_TLV_NUM_LESS,	/* mandatory tlv(s) absent */
	CMDU_STATUS_ERR_TLV_NUM_MORE,
	CMDU_STATUS_ERR_TLV_NO_EOM,
	CMDU_STATUS_ERR_TLV_RESIDUE_DATA,
	CMDU_STATUS_ERR_TLV_LEN_INSUFFICIENT,
	CMDU_STATUS_ERR_TLV_LEN_OVERFLOW,
	CMDU_STATUS_ERR_CMDU_MALFORMED,
	CMDU_STATUS_ERR_MISC,

	IEEE1905_ERROR_MAXNUM,
	IEEE1905_ERROR_LAST = IEEE1905_ERROR_MAXNUM - 1,
};


extern int *ieee1905_get_errval(void);
#define ieee1905_error	(*ieee1905_get_errval())

const char *ieee1905_strerror(int err);

/** Parse a CMDU to get list of the TLVs present in it
 *
 * @param[in] c  cmdu_buff for parsing
 * @param[in|out] tv  array of TLVs to hold the returned TLVs
 * @param[in] policy  policy for TLV parsing
 * @param[in] policy_len  length of the policy
 *
 * @return 0 on success, else non-zero.
 *
 * The TLVs are returned in the passed 'tv' array.
 */
int cmdu_parse_tlvs(struct cmdu_buff *c, struct tlv *tv[][16],
		    struct tlv_policy *policy, int policy_len);


/** Parse a CMDU to get list of the TLVs of a single type
 *
 * @param[in] c  cmdu_buff for parsing
 * @param[in|out] tv  array of TLVs to hold the returned TLVs
 * @param[in] policy  policy for TLV parsing
 * @param[in|out] *num  number of TLVs
 *
 * @return 0 on success, else non-zero.
 *
 * This function can be used when number of TLVs of the same type is present
 * more then 16 times; f.e. CMDUs containing TLVs for scanresults.
 * The TLVs are returned in the passed 'tv' array. And, *num is updated with
 * the actual number of TLVs present.
 */
int cmdu_parse_tlv_single(struct cmdu_buff *c, struct tlv *tv[],
			  struct tlv_policy *policy, int *num);


/** Copy append flattended TLVs data buffer into a CMDU */
int cmdu_copy_tlvs_linear(struct cmdu_buff *c, uint8_t *tlvs, uint32_t tlvslen);

/** Copy append un-flattened TLVs into a CMDU */
int cmdu_copy_tlvs(struct cmdu_buff *c, struct tlv *tv[], int tv_arrsize);

/** Create a clone or duplicate of a CMDU */
struct cmdu_buff *cmdu_clone(struct cmdu_buff *frm);

/** Function to reserve space at the tail of a CMDU buffer */
struct tlv *cmdu_reserve_tlv(struct cmdu_buff *c, uint16_t tlv_datalen);

/** Function puts a TLV within the CMDU buffer at the reserved area */
int cmdu_put_tlv(struct cmdu_buff *c, struct tlv *t);

/** Copy data at the tail of a CMDU */
int cmdu_put(struct cmdu_buff *c, uint8_t *bytes, int len);

/** Append End-Of-Message TLV to a CMDU */
int cmdu_put_eom(struct cmdu_buff *c);

/** Remove End-Of-Message TLV from a CMDU */
int cmdu_pull_eom(struct cmdu_buff *c);

struct tlv *cmdu_extract_tlv(struct cmdu_buff *c, uint8_t tlv_type);
struct tlv *cmdu_peek_tlv(struct cmdu_buff *c, uint8_t tlv_type);

#if 0
int cmdu_reserve(struct cmdu_buff *c, size_t s);
int cmdu_expand(struct cmdu_buff *c, size_t newsize);
#endif


/** Helper function to stringify a CMDU type */
const char *cmdu_type2str(uint16_t type);

/** Iterate through TLVs within a CMDU */
#define cmdu_for_each_tlv(pos, tlvs, rem)	\
	for (pos = (struct tlv *) tlvs;		\
	     tlv_ok(pos, rem);			\
	     pos = tlv_next(pos, &rem))



#endif /* CMDU_H */
