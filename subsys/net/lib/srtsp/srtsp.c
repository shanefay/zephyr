/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(CONFIG_NET_DEBUG_srtsp)
#define SYS_LOG_DOMAIN "srtsp"
#define NET_LOG_ENABLED 1
#endif

#include <stdlib.h>
#include <stddef.h>
#include <zephyr/types.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>

#include <misc/byteorder.h>
#include <net/buf.h>
#include <net/net_pkt.h>
#include <net/net_ip.h>


#include <net/srtsp.h>

struct option_context {
	u16_t delta;
	u16_t offset;
	struct net_buf *frag;
};

#define SRTSP_VERSION 1

#define SRTSP_MARKER 0xFF //TODO: change this to be different than CoAP

#define BASIC_HEADER_SIZE 4


#define PKT_WAIT_TIME K_SECONDS(1)

/* Values as per RFC 7252, section-3.1.
 *
 * Option Delta/Length: 4-bit unsigned integer. A value between 0 and
 * 12 indicates the Option Delta/Length.  Three values are reserved for
 * special constructs:
 * 13: An 8-bit unsigned integer precedes the Option Value and indicates
 *     the Option Delta/Length minus 13.
 * 14: A 16-bit unsigned integer in network byte order precedes the
 *     Option Value and indicates the Option Delta/Length minus 269.
 * 15: Reserved for future use.
 */
#define SRTSP_OPTION_NO_EXT 12 /* Option's Delta/Length without extended data */
#define SRTSP_OPTION_EXT_13 13
#define SRTSP_OPTION_EXT_14 14
#define SRTSP_OPTION_EXT_15 15
#define SRTSP_OPTION_EXT_269 269

const u8_t TIMESTAMP_SIZE = 4;

static u8_t option_header_get_delta(u8_t opt)
{
	return (opt & 0xF0) >> 4;
}

static u8_t option_header_get_len(u8_t opt)
{
	return opt & 0x0F;
}

static void option_header_set_delta(u8_t *opt, u8_t delta)
{
	*opt = (delta & 0xF) << 4;
}

static void option_header_set_len(u8_t *opt, u8_t len)
{
	*opt |= (len & 0xF);
}

static u16_t get_srtsp_packet_len(struct net_pkt *pkt)
{
	u16_t len;

	/* TODO: verify with smaller packets */
	len = net_pkt_get_len(pkt)
	      - net_pkt_ip_hdr_len(pkt)
	      - net_pkt_ipv6_ext_len(pkt)
	      - NET_UDPH_LEN;

	return len;
}

static int check_frag_read_status(const struct net_buf *frag, u16_t offset)
{
	if (!frag && offset == 0xffff) { //if frag != NULL
		return -EINVAL;
	} else if (!frag && offset == 0) { //if frag && offset !=0
		return 0;
	}

	return 1;
}

static int decode_delta(struct option_context *context, u16_t opt,
			u16_t *opt_ext, u16_t *hdr_len)
{
	int ret = 0;

	if (opt == SRTSP_OPTION_EXT_13) {
		u8_t val;

		*hdr_len = 1;
		context->frag = net_frag_read_u8(context->frag,
						 context->offset,
						 &context->offset,
						 &val);
		ret = check_frag_read_status(context->frag,
					     context->offset);
		if (ret < 0) {
			return -EINVAL;
		}

		opt = val + SRTSP_OPTION_EXT_13;
	} else if (opt == SRTSP_OPTION_EXT_14) {
		u16_t val;

		*hdr_len = 2;
		context->frag = net_frag_read_be16(context->frag,
						   context->offset,
						   &context->offset,
						   &val);
		ret = check_frag_read_status(context->frag,
					     context->offset);
		if (ret < 0) {
			return -EINVAL;
		}

		opt = val + SRTSP_OPTION_EXT_269;
	} else if (opt == SRTSP_OPTION_EXT_15) {
		return -EINVAL;
	}

	*opt_ext = opt;

	return ret;
}

static int parse_option(const struct srtsp_packet *cpkt,
			struct option_context *context,
			struct srtsp_option *option,
			u16_t *opt_len)
{
	u16_t hdr_len;
	u16_t delta;
	u16_t len;
	u8_t opt;
	int r;
	SYS_LOG_DBG("PARSE OPTION CALLED");
	context->frag = net_frag_read_u8(context->frag,
					 context->offset,
					 &context->offset,
					 &opt);
	r = check_frag_read_status(context->frag, context->offset); //check that frag is not 0 or null, returns -22 if null, 0 if 0, 1 otherwise
	if (r < 0) {
		return r;
	}

	*opt_len += 1;

	/* This indicates that options have ended */
	if (opt == SRTSP_MARKER) {
		/* packet w/ marker but no payload is malformed */
		return r > 0 ? 0 : -EINVAL;
	}

	delta = option_header_get_delta(opt);
	len = option_header_get_len(opt);

	/* r == 0 means no more data to read from fragment, but delta
	 * field shows that packet should contain more data, it must
	 * be a malformed packet.
	 */
	if (r == 0 && delta > SRTSP_OPTION_NO_EXT) {
		return -EINVAL;
	}

	if (delta > SRTSP_OPTION_NO_EXT) {
		/* In case 'delta' doesn't fit the option fixed header. */
		r = decode_delta(context, delta, &delta, &hdr_len);
		if ((r < 0) || (r == 0 && len > SRTSP_OPTION_NO_EXT)) {
			return -EINVAL;
		}

		*opt_len += hdr_len;
	}

	if (len > SRTSP_OPTION_NO_EXT) {
		/* In case 'len' doesn't fit the option fixed header. */
		r = decode_delta(context, len, &len, &hdr_len);
		if (r < 0) {
			return -EINVAL;
		}

		*opt_len += hdr_len;
	}

	*opt_len += len;

	if (r == 0) {
		if (len == 0) {
			context->delta += delta;
			return r;
		}

		/* r == 0 means no more data to read from fragment, but len
		 * field shows that packet should contain more data, it must
		 * be a malformed packet.
		 */
		return -EINVAL;
	}

	if (option) {
		/*
		 * Make sure the option data will fit into the value field of
		 * srtsp_option.
		 * NOTE: To expand the size of the value field set:
		 * CONFIG_SRTSP_EXTENDED_OPTIONS_LEN=y
		 * CONFIG_SRTSP_EXTENDED_OPTIONS_LEN_VALUE=<size>
		 *TODO: possibly implement these options. If they're defined in the config does it just work?
		 */
		if (len > sizeof(option->value)) {
			NET_ERR("%u is > sizeof(srtsp_option->value)(%zu)!",
				len, sizeof(option->value));
			return -ENOMEM;
		}

		option->delta = context->delta + delta;
		option->len = len;
		context->frag = net_frag_read(context->frag, context->offset,
					      &context->offset, len,
					      &option->value[0]);
	} else {
		context->frag = net_frag_skip(context->frag, context->offset,
					      &context->offset, len);
	}

	r = check_frag_read_status(context->frag, context->offset);
	if (r < 0) {
		return r;
	}

	context->delta += delta;

	return r;
}

static int parse_options(const struct srtsp_packet *cpkt,
			 struct srtsp_option *options, u8_t opt_num)
{
	struct option_context context = {
					.delta = 0,
					.frag = NULL,
					.offset = 0
					};
	u16_t opt_len;
	u8_t num;
	int r;
	SYS_LOG_DBG("PARSE OPTIONS CALLED");

	/* Skip CoAP header */
	context.frag = net_frag_skip(cpkt->frag, cpkt->offset,
				     &context.offset, cpkt->hdr_len);
	r = check_frag_read_status(context.frag, context.offset);
	if (r <= 0) {
		return r;
	}

	num = 0;
	opt_len = 0;

	while (true) {
		struct srtsp_option *option;

		option = num < opt_num ? &options[num++] : NULL;
		r = parse_option(cpkt, &context, option, &opt_len);
		if (r <= 0) {
			break;
		}
	}

	if (r < 0) {
		return r;
	}

	return opt_len;
}


//gets the 4 reserved bits that come after version and type in the header
u8_t get_header_reserved_bits(const struct srtsp_packet *cpkt)
{
	struct net_buf *frag;
	u16_t offset;
	u8_t res_bits;
	SYS_LOG_DBG("GET RES BITS CALLED");
	frag = net_frag_read_u8(cpkt->frag, cpkt->offset, &offset, &res_bits);

	return res_bits & 0xF;
}

static u16_t get_pkt_len(const struct srtsp_packet *cpkt)
{
	struct net_buf *frag;
	u16_t len;

	len = cpkt->frag->len - cpkt->offset;

	for (frag = cpkt->frag->frags; frag; frag = frag->frags) {
		len += frag->len;
	}

	return len;
}

//where the first changes need to be made. Need to lock down header structure
static int get_header_len(struct srtsp_packet *cpkt)
{
	SYS_LOG_DBG("GET HEADER LEN CALLED");
	//u8_t res_bits;
	u16_t len;
	int hdrlen;

	len = get_pkt_len(cpkt);

	hdrlen = BASIC_HEADER_SIZE;

	if (len < hdrlen) {
		return -EINVAL;
	}

	/* The value is currently irrelevant, may change later
	if (tkl > 8) {
		return -EINVAL;
	}
	*/

	if (len < hdrlen + TIMESTAMP_SIZE) {
		return -EINVAL;
	}

	cpkt->hdr_len =  hdrlen + TIMESTAMP_SIZE;

	return 0;
}

int srtsp_packet_parse(struct srtsp_packet *cpkt, struct net_pkt *pkt,
		      struct srtsp_option *options, u8_t opt_num)
{
	int ret;
	SYS_LOG_DBG("PACKET PARSE CALLED");
	printk("srtsp_packet_parse()\n");
	if (!cpkt || !pkt || !pkt->frags) {
		return -EINVAL;
	}

	cpkt->pkt = pkt;
	cpkt->hdr_len = 0;
	cpkt->opt_len = 0;

	//skip all the ipv6 and udp stuff to get to the SRTSP packet
	cpkt->frag = net_frag_skip(pkt->frags, 0, &cpkt->offset,
				   net_pkt_ip_hdr_len(pkt) +
				   NET_UDPH_LEN +
				   net_pkt_ipv6_ext_len(pkt));
	ret = check_frag_read_status(cpkt->frag, cpkt->offset); //if cpkt->frag && offset == 0xffff, fuck up, if ==0 reutrn 0, 1 otherwise
	if (ret <= 0) {
		return ret;
	}

	ret = get_header_len(cpkt);
	if (ret < 0) {
		return -EINVAL;
	}

	ret = parse_options(cpkt, options, opt_num);
	if (ret < 0) {
		return -EINVAL;
	}

	cpkt->opt_len = ret;

	return 0;
}

static u32_t get_timestamp()
{
	return k_uptime_get_32();
}

int srtsp_packet_init(struct srtsp_packet *cpkt, struct net_pkt *pkt,
		     u8_t ver, u8_t type, u8_t res_bits,
		     u8_t *timestamp, u8_t code, u16_t id)
{
	u8_t hdr;
	bool res;
  printk("in init\n");
	if (!cpkt || !pkt || !pkt->frags) {
		printk("something didnt pass in right\n");
		return -EINVAL;
	}

	memset(cpkt, 0, sizeof(*cpkt));
	cpkt->pkt = pkt;
	cpkt->frag = pkt->frags;
	cpkt->offset = 0;
	cpkt->last_delta = 0;

	hdr = (ver & 0x3) << 6;
	hdr |= (type & 0x3) << 4;
	hdr |= res_bits & 0xF; //TODO: remove token length, replace with 0 for now

	net_pkt_append_u8(pkt, hdr);
	net_pkt_append_u8(pkt, code);
	net_pkt_append_be16(pkt, id);
	u32_t temp = get_timestamp();
	u8_t * time_stamp = (u8_t*) &temp;
	if(time_stamp) {
		res = net_pkt_append_all(pkt, TIMESTAMP_SIZE, time_stamp, PKT_WAIT_TIME);
		if (!res) {
			return -ENOMEM;
		}
	}
	/*
	if (token && tokenlen) {
		res = net_pkt_append_all(pkt, tokenlen, token, PKT_WAIT_TIME);
		if (!res) {
			return -ENOMEM;
		}
	}
	*/

	/* Header length : (version + type + timestamp size) + code + id  */
	cpkt->hdr_len = 1 + 1 + 2 + TIMESTAMP_SIZE; //adjust with + 4 for timestamp

	return 0;
}

int srtsp_pending_init(struct srtsp_pending *pending,
		      const struct srtsp_packet *request,
		      const struct sockaddr *addr)
{
	memset(pending, 0, sizeof(*pending));
	pending->id = srtsp_header_get_id(request);
	memcpy(&pending->addr, addr, sizeof(*addr));

	/* Will increase the reference count when the pending is cycled */
	pending->pkt = request->pkt;

	return 0;
}

struct srtsp_pending *srtsp_pending_next_unused(
	struct srtsp_pending *pendings, size_t len)
{
	struct srtsp_pending *p;
	size_t i;

	for (i = 0, p = pendings; i < len; i++, p++) {
		if (p->timeout == 0 && !p->pkt) {
			return p;
		}
	}

	return NULL;
}

struct srtsp_reply *srtsp_reply_next_unused(
	struct srtsp_reply *replies, size_t len)
{
	struct srtsp_reply *r;
	size_t i;

	for (i = 0, r = replies; i < len; i++, r++) {
		if (!r->reply) {
			return r;
		}
	}

	return NULL;
}

static inline bool is_addr_unspecified(const struct sockaddr *addr)
{
	if (addr->sa_family == AF_UNSPEC) {
		return true;
	}

	if (addr->sa_family == AF_INET6) {
		return net_is_ipv6_addr_unspecified(
			&(net_sin6(addr)->sin6_addr));
	} else if (addr->sa_family == AF_INET) {
		return net_sin(addr)->sin_addr.s4_addr32[0] == 0;
	}

	return false;
}

struct srtsp_observer *srtsp_observer_next_unused(
	struct srtsp_observer *observers, size_t len)
{
	struct srtsp_observer *o;
	size_t i;

	for (i = 0, o = observers; i < len; i++, o++) {
		if (is_addr_unspecified(&o->addr)) {
			return o;
		}
	}

	return NULL;
}

struct srtsp_pending *srtsp_pending_received(
	const struct srtsp_packet *response,
	struct srtsp_pending *pendings, size_t len)
{
	struct srtsp_pending *p;
	u16_t resp_id = srtsp_header_get_id(response);
	size_t i;

	for (i = 0, p = pendings; i < len; i++, p++) {
		if (!p->timeout) {
			continue;
		}

		if (resp_id != p->id) {
			continue;
		}

		srtsp_pending_clear(p);
		return p;
	}

	return NULL;
}

struct srtsp_pending *srtsp_pending_next_to_expire(
	struct srtsp_pending *pendings, size_t len)
{
	struct srtsp_pending *p, *found = NULL;
	size_t i;

	for (i = 0, p = pendings; i < len; i++, p++) {
		if (p->timeout && (!found || found->timeout < p->timeout)) {
			found = p;
		}
	}

	return found;
}

#define LAST_TIMEOUT (2345 * 4)

static s32_t next_timeout(s32_t previous)
{
	switch (previous) {
	case 0:
		return 2345;
	case 2345:
		return 2345 * 2;
	case (2345 * 2):
		return LAST_TIMEOUT;
	case LAST_TIMEOUT:
		return LAST_TIMEOUT;
	}

	return 2345;
}

bool srtsp_pending_cycle(struct srtsp_pending *pending)
{
	s32_t old = pending->timeout;
	bool cont;

	pending->timeout = next_timeout(pending->timeout);

	/* If the timeout changed, it's not the last, continue... */
	cont = (old != pending->timeout);
	if (cont) {
		/* When it it is the last retransmission, the buffer
		 * will be destroyed when it is transmitted.
		 */
		net_pkt_ref(pending->pkt);
	}

	return cont;
}

void srtsp_pending_clear(struct srtsp_pending *pending)
{
	pending->timeout = 0;
	net_pkt_unref(pending->pkt);
	pending->pkt = NULL;
}

static bool uri_path_eq(const struct srtsp_packet *cpkt,
			const char * const *path,
			struct srtsp_option *options,
			u8_t opt_num)
{
	u8_t i;
	u8_t j = 0;

	for (i = 0; i < opt_num && path[j]; i++) {
		if (options[i].delta != SRTSP_OPTION_URI_PATH) {
			continue;
		}

		if (options[i].len != strlen(path[j])) {
			return false;
		}

		if (memcmp(options[i].value, path[j], options[i].len)) {
			return false;
		}

		j++;
	}

	if (path[j]) {
		return false;
	}

	for (; i < opt_num; i++) {
		if (options[i].delta == SRTSP_OPTION_URI_PATH) {
			return false;
		}
	}

	return true;
}


static srtsp_method_t method_from_code(const struct srtsp_resource *resource,
				      u8_t code)
{
	SYS_LOG_DBG("METHOD FROM CODE CALLED");
	switch (code) {
	case SRTSP_METHOD_SETUP:
		SYS_LOG_DBG("METHOD: SETUP");
		return resource->setup;
	case SRTSP_METHOD_PLAY:
	SYS_LOG_DBG("METHOD: PLAY");
		return resource->play;
	case SRTSP_METHOD_PAUSE:
	SYS_LOG_DBG("METHOD: PAUSE");
		printk("pause method\n");
		return resource->pause;
	case SRTSP_METHOD_TEARDOWN:
	SYS_LOG_DBG("METHOD: TEARDOWN");
		printk("teardown method\n");
		return resource->teardown;
	default:
		SYS_LOG_DBG("METHOD: NULL");
		return NULL;
	}
}

static bool is_request(const struct srtsp_packet *cpkt)
{
	u8_t code = srtsp_header_get_code(cpkt);
	//~ is bitwise compliment
	//SRTSP_REQUEST_MASK is 0x07
	//it's bitwise compliment is 11111000
	//we're returning the inverse of this & operation, which means that
	//code & 11111000 must be 0 to be a request, so code cant have
	//any bits above the 3 least significant
	//this will allow for 8 different requests, and only 4 are currently used
	return !(code & ~SRTSP_REQUEST_MASK);
}

int srtsp_handle_request(struct srtsp_packet *cpkt,
			struct srtsp_resource *resources,
			struct srtsp_option *options,
			u8_t opt_num)
{
	struct srtsp_resource *resource;
	printk("srtsp_handle_request\n");
	if (!is_request(cpkt)) {
		return 0;
	}

	/* FIXME: deal with hierarchical resources */
	for (resource = resources; resource && resource->path; resource++) {
		srtsp_method_t method;
		u8_t code;
		//if not the right uri path, skip to next loop iteration
		if (!uri_path_eq(cpkt, resource->path, options, opt_num)) {
			continue;
		}

		code = srtsp_header_get_code(cpkt);
		printk("Code: %u\n", code);
		method = method_from_code(resource, code);
		if (!method) {
			return 0;
		}

		return method(resource, cpkt);
	}
	return -ENOENT;
}

unsigned int srtsp_option_value_to_int(const struct srtsp_option *option)
{
	switch (option->len) {
	case 0:
		return 0;
	case 1:
		return option->value[0];
	case 2:
		return (option->value[1] << 0) | (option->value[0] << 8);
	case 3:
		return (option->value[2] << 0) | (option->value[1] << 8) |
			(option->value[0] << 16);
	case 4:
		return (option->value[2] << 0) | (option->value[2] << 8) |
			(option->value[1] << 16) | (option->value[0] << 24);
	default:
		return 0;
	}

	return 0;
}

static int get_observe_option(const struct srtsp_packet *cpkt)
{
	struct srtsp_option option = {};
	u16_t count = 1;
	int r;

	r = srtsp_find_options(cpkt, SRTSP_OPTION_OBSERVE, &option, count);
	if (r <= 0) {
		return -ENOENT;
	}

	return srtsp_option_value_to_int(&option);
}

//TODO: remove references to tkl
struct srtsp_reply *srtsp_response_received(
	const struct srtsp_packet *response,
	const struct sockaddr *from,
	struct srtsp_reply *replies, size_t len)
{
	struct srtsp_reply *r;
	u8_t timestamp[4];
	u16_t id;
	u8_t res_bits;
	size_t i;

	id = srtsp_header_get_id(response);
	//puts the timestamp where the pointer is, and returns its lenght
	res_bits = srtsp_header_get_timestamp(response, (u8_t *)timestamp);

	for (i = 0, r = replies; i < len; i++, r++) {
		int age;

		if ((r->id == 0) ) {
			continue;
		}

		/*Piggybacked must match id when token is empty
		if ((r->id != id) && (tkl == 0)) {
			continue;
		}

		if (tkl > 0 && memcmp(r->token, token, tkl)) {
			continue;
		}*/

		age = get_observe_option(response);
		if (age > 0) {
			/* age == 2 means that the notifications wrapped,
			 * or this is the first one
			 */
			if (r->age > age && age != 2) {
				continue;
			}

			r->age = age;
		}

		r->reply(response, r, from);
		return r;
	}

	return NULL;
}

//TODO: remove references to tkl
void srtsp_reply_init(struct srtsp_reply *reply,
		     const struct srtsp_packet *request)
{
	u8_t timestamp[4];
	u8_t res_bits;
	int age;

	reply->id = srtsp_header_get_id(request);
	res_bits = srtsp_header_get_timestamp(request, (u8_t *)&timestamp);

	/*if (tkl > 0) {
		memcpy(reply->token, token, tkl);
	}
	*/
	reply->res_bits = res_bits;

	age = get_observe_option(request);

	/* It means that the request enabled observing a resource */
	if (age == 0) {
		reply->age = 2;
	}
}

void srtsp_reply_clear(struct srtsp_reply *reply)
{
	reply->id = 0;
	reply->res_bits = 0;
	reply->reply = NULL;
}

int srtsp_resource_notify(struct srtsp_resource *resource)
{
	struct srtsp_observer *o;

	resource->age++;

	if (!resource->notify) {
		return -ENOENT;
	}

	SYS_SLIST_FOR_EACH_CONTAINER(&resource->observers, o, list) {
		resource->notify(resource, o);
	}

	return 0;
}

bool srtsp_request_is_observe(const struct srtsp_packet *request)
{
	return get_observe_option(request) == 0;
}

//this is weird, dont know about observers
//TODO: figure it out
void srtsp_observer_init(struct srtsp_observer *observer,
			const struct srtsp_packet *request,
			const struct sockaddr *addr)
{
	u8_t timestamp[4];
	u8_t timestamp_size;

	timestamp_size = srtsp_header_get_timestamp(request, (u8_t *)&timestamp);

	if (timestamp_size > 0) {
		memcpy(observer->token, timestamp, timestamp_size);
	}

	observer->tkl =timestamp_size;

	net_ipaddr_copy(&observer->addr, addr);
}

bool srtsp_register_observer(struct srtsp_resource *resource,
			    struct srtsp_observer *observer)
{
	bool first;

	sys_slist_append(&resource->observers, &observer->list);

	first = resource->age == 0;
	if (first) {
		resource->age = 2;
	}

	return first;
}

void srtsp_remove_observer(struct srtsp_resource *resource,
			  struct srtsp_observer *observer)
{
	sys_slist_find_and_remove(&resource->observers, &observer->list);
}

static bool sockaddr_equal(const struct sockaddr *a,
			   const struct sockaddr *b)
{
	/* FIXME: Should we consider ipv6-mapped ipv4 addresses as equal to
	 * ipv4 addresses?
	 */
	if (a->sa_family != b->sa_family) {
		return false;
	}

	if (a->sa_family == AF_INET) {
		const struct sockaddr_in *a4 = net_sin(a);
		const struct sockaddr_in *b4 = net_sin(b);

		if (a4->sin_port != b4->sin_port) {
			return false;
		}

		return net_ipv4_addr_cmp(&a4->sin_addr, &b4->sin_addr);
	}

	if (b->sa_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = net_sin6(a);
		const struct sockaddr_in6 *b6 = net_sin6(b);

		if (a6->sin6_scope_id != b6->sin6_scope_id) {
			return false;
		}

		if (a6->sin6_port != b6->sin6_port) {
			return false;
		}

		return net_ipv6_addr_cmp(&a6->sin6_addr, &b6->sin6_addr);
	}

	/* Invalid address family */
	return false;
}

struct srtsp_observer *srtsp_find_observer_by_addr(
	struct srtsp_observer *observers, size_t len,
	const struct sockaddr *addr)
{
	size_t i;

	for (i = 0; i < len; i++) {
		struct srtsp_observer *o = &observers[i];

		if (sockaddr_equal(&o->addr, addr)) {
			return o;
		}
	}

	return NULL;
}

//get the uptime in milliseconds - this functions as the timestamp until such
//a point that sntp is integrated


int srtsp_packet_append_payload_marker(struct srtsp_packet *cpkt)
{
	return net_pkt_append_u8(cpkt->pkt, SRTSP_MARKER) ? 0 : -EINVAL;
}

int srtsp_packet_append_payload(struct srtsp_packet *cpkt, u8_t *payload,
			       u16_t payload_len)
{
	bool status;
	printk("Payload: %u\n", payload);
	printk("Payload Length: %u", payload_len);
	status = net_pkt_append_all(cpkt->pkt, payload_len, payload,
				    PKT_WAIT_TIME);

	return status ? 0 : -EINVAL;
}

//Not relevant, extended options not defined, leaving in case they become defined
static u8_t encode_extended_option(u16_t num, u8_t *opt, u16_t *ext)
{
	if (num < SRTSP_OPTION_EXT_13) {
		*opt = num;
		*ext = 0;

		return 0;
	} else if (num < SRTSP_OPTION_EXT_269) {
		*opt = SRTSP_OPTION_EXT_13;
		*ext = num - SRTSP_OPTION_EXT_13;

		return 1;
	}

	*opt = SRTSP_OPTION_EXT_14;
	*ext = num - SRTSP_OPTION_EXT_269;

	return 2;
}

static int encode_option(struct srtsp_packet *cpkt, u16_t code,
			 const u8_t *value, u16_t len)
{
	u16_t delta_ext; /* Extended delta */
	u16_t len_ext; /* Extended length */
	u8_t opt; /* delta | len */
	u8_t opt_delta;
	u8_t opt_len;
	u8_t delta_size;
	u8_t len_size;
	bool res;

	delta_size = encode_extended_option(code, &opt_delta, &delta_ext);
	len_size = encode_extended_option(len, &opt_len, &len_ext);

	option_header_set_delta(&opt, opt_delta);
	option_header_set_len(&opt, opt_len);

	net_pkt_append_u8(cpkt->pkt, opt);

	if (delta_size == 1) {
		net_pkt_append_u8(cpkt->pkt, (u8_t) delta_ext);
	} else if (delta_size == 2) {
		net_pkt_append_be16(cpkt->pkt, delta_ext);
	}

	if (len_size == 1) {
		net_pkt_append_u8(cpkt->pkt, (u8_t) len_ext);
	} else if (delta_size == 2) {
		net_pkt_append_be16(cpkt->pkt, len_ext);
	}

	if (len && value) {
		res = net_pkt_append_all(cpkt->pkt, len, value, PKT_WAIT_TIME);
		if (!res) {
			return -EINVAL;
		}
	}

	return  (1 + delta_size + len_size + len);
}

/* TODO Add support for inserting options in proper place
 * and modify other option's delta accordingly.
 */
int srtsp_packet_append_option(struct srtsp_packet *cpkt, u16_t code,
			      const u8_t *value, u16_t len)
{
	struct net_buf *frag;
	u16_t offset;
	int r;

	if (!cpkt) {
		return -EINVAL;
	}

	if (len && !value) {
		return -EINVAL;
	}

	if (code < cpkt->last_delta) {
		NET_ERR("Options should be in ascending order");
		return -EINVAL;
	}

	/* Skip CoAP packet header */
	frag = net_frag_skip(cpkt->frag, cpkt->offset, &offset, cpkt->hdr_len);
	if (!frag && offset == 0xffff) {
		return -EINVAL;
	}

	/* Calculate delta, if this option is not the first one */
	if (cpkt->opt_len) {
		code = (code == cpkt->last_delta) ? 0 :
			code - cpkt->last_delta;
	}

	r = encode_option(cpkt, code, value, len);
	if (r < 0) {
		return -EINVAL;
	}

	cpkt->opt_len += r;
	cpkt->last_delta += code;

	return 0;
}

int srtsp_append_option_int(struct srtsp_packet *cpkt, u16_t code,
			   unsigned int val)
{
	u8_t data[4], len;

	if (val == 0) {
		data[0] = 0;
		len = 0;
	} else if (val < 0xFF) {
		data[0] = (u8_t) val;
		len = 1;
	} else if (val < 0xFFFF) {
		sys_put_be16(val, data);
		len = 2;
	} else if (val < 0xFFFFFF) {
		sys_put_be16(val, data);
		data[2] = val >> 16;
		len = 3;
	} else {
		sys_put_be32(val, data);
		len = 4;
	}

	return srtsp_packet_append_option(cpkt, code, data, len);
}

int srtsp_find_options(const struct srtsp_packet *cpkt, u16_t code,
		      struct srtsp_option *options, u16_t veclen)
{
	struct option_context context = {
					  .delta = 0,
					  .frag = NULL,
					  .offset = 0
					};
	u16_t opt_len;
	int count;
	int r;

	if (!cpkt || !cpkt->pkt || !cpkt->pkt->frags || !cpkt->hdr_len) {
		return -EINVAL;
	}

	/* Skip CoAP header */
	context.frag = net_frag_skip(cpkt->frag, cpkt->offset,
				     &context.offset, cpkt->hdr_len);
	r = check_frag_read_status(context.frag, context.offset);
	if (r <= 0) {
		return r;
	}

	opt_len = 0;
	count = 0;

	while (context.delta <= code && count < veclen) {
		r = parse_option(cpkt, &context, &options[count], &opt_len);
		if (r < 0) {
			return -EINVAL;
		}

		if (code == options[count].delta) {
			count++;
		}

		if (r == 0) {
			break;
		}
	}

	return count;
}

u8_t srtsp_header_get_version(const struct srtsp_packet *cpkt)
{
	struct net_buf *frag;
	u16_t offset;
	u8_t version;

	frag = net_frag_read_u8(cpkt->frag, cpkt->offset, &offset, &version);
	if (!frag && offset == 0xffff) {
		return 0;
	}

	return (version & 0xC0) >> 6;
}

u8_t srtsp_header_get_type(const struct srtsp_packet *cpkt)
{
	struct net_buf *frag;
	u16_t offset;
	u8_t type;

	frag = net_frag_read_u8(cpkt->frag, cpkt->offset, &offset, &type);
	if (!frag && offset == 0xffff) {
		return 0;
	}

	return (type & 0x30) >> 4;
}

static u8_t __srtsp_header_get_code(const struct srtsp_packet *cpkt)
{
	struct net_buf *frag;
	u16_t offset;
	u8_t code;

	frag = net_frag_skip(cpkt->frag, cpkt->offset, &offset, 1);
	frag = net_frag_read_u8(frag, offset, &offset, &code);
	if (!frag && offset == 0xffff) {
		return 0;
	}

	return code;
}

u8_t srtsp_header_get_timestamp(const struct srtsp_packet *cpkt, u8_t *timestamp)
{
	struct net_buf *frag;
	u16_t offset;

	if (!cpkt || !timestamp) {
		return 0;
	}

	frag = net_frag_skip(cpkt->frag, cpkt->offset, &offset,
			     BASIC_HEADER_SIZE);
	frag = net_frag_read(frag, offset, &offset, TIMESTAMP_SIZE, timestamp);
	if (!frag && offset == 0xffff) {
		return 0;
	}

	return TIMESTAMP_SIZE;
}

u8_t srtsp_header_get_code(const struct srtsp_packet *cpkt)
{
	u8_t code = __srtsp_header_get_code(cpkt);

	switch (code) {
	/* Methods are encoded in the code field too */
	case SRTSP_METHOD_SETUP:
	case SRTSP_METHOD_PLAY:
	case SRTSP_METHOD_PAUSE:
	case SRTSP_METHOD_TEARDOWN:

	/* All the defined response codes */
	case SRTSP_RESPONSE_CODE_OK:
	/*case SRTSP_RESPONSE_CODE_CREATED:
	case SRTSP_RESPONSE_CODE_DELETED:
	case SRTSP_RESPONSE_CODE_VALID:
	case SRTSP_RESPONSE_CODE_CHANGED:
	case SRTSP_RESPONSE_CODE_CONTENT:
	case SRTSP_RESPONSE_CODE_CONTINUE:
	*/
	case SRTSP_RESPONSE_CODE_MOVED_PERMANENTLY:
	case SRTSP_RESPONSE_CODE_FOUND:
	case SRTSP_RESPONSE_CODE_SEE_OTHER:
	case SRTSP_RESPONSE_CODE_NOT_MODIFIED:
	case SRTSP_RESPONSE_CODE_USE_PROXY:
	case SRTSP_RESPONSE_CODE_BAD_REQUEST:
	case SRTSP_RESPONSE_CODE_UNAUTHORIZED:
	case SRTSP_RESPONSE_CODE_BAD_OPTION:
	case SRTSP_RESPONSE_CODE_FORBIDDEN:
	case SRTSP_RESPONSE_CODE_NOT_FOUND:
	case SRTSP_RESPONSE_CODE_NOT_ALLOWED:
	case SRTSP_RESPONSE_CODE_NOT_ACCEPTABLE:
	case SRTSP_RESPONSE_CODE_REQUEST_TIMEOUT:
	case SRTSP_RESPONSE_CODE_GONE:
	case SRTSP_RESPONSE_CODE_PRECONDITION_FAILED:
	case SRTSP_RESPONSE_CODE_REQUEST_TOO_LARGE:
	case SRTSP_RESPONSE_CODE_URI_TO_LONG:
	case SRTSP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT:
	case SRTSP_RESPONSE_CODE_INVALID_RANGE:
	case SRTSP_RESPONSE_CODE_INTERNAL_ERROR:
	case SRTSP_RESPONSE_CODE_NOT_IMPLEMENTED:
	case SRTSP_RESPONSE_CODE_BAD_GATEWAY:
	case SRTSP_RESPONSE_CODE_SERVICE_UNAVAILABLE:
	case SRTSP_RESPONSE_CODE_GATEWAY_TIMEOUT:
	case SRTSP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED:
		return code;
	default:
		return SRTSP_CODE_EMPTY;
	}
}

u16_t srtsp_header_get_id(const struct srtsp_packet *cpkt)
{
	struct net_buf *frag;
	u16_t offset;
	u16_t id;
	frag = net_frag_skip(cpkt->frag, cpkt->offset, &offset, 2);
	frag = net_frag_read_be16(frag, offset, &offset, &id);
	if (!frag && offset == 0xffff) {
		return 0;
	}

	return id;
}

struct net_buf *srtsp_packet_get_payload(const struct srtsp_packet *cpkt,
					u16_t *offset, u16_t *len)
{
	struct net_buf *frag = NULL;
	u16_t srtsp_pkt_len;

	if (!cpkt || !cpkt->pkt || !offset || !len) {
		return NULL;
	}

	*offset = 0xffff;
	*len = 0;

	srtsp_pkt_len = get_srtsp_packet_len(cpkt->pkt);

	frag = net_frag_skip(cpkt->frag, cpkt->offset, offset,
			     cpkt->hdr_len + cpkt->opt_len);
	*len = srtsp_pkt_len - cpkt->hdr_len - cpkt->opt_len;

	return frag;
}


int srtsp_block_transfer_init(struct srtsp_block_context *ctx,
			      enum srtsp_block_size block_size,
			      size_t total_size)
{
	ctx->block_size = block_size;
	ctx->total_size = total_size;
	ctx->current = 0;

	return 0;
}

#define GET_BLOCK_SIZE(v) (((v) & 0x7))
#define GET_MORE(v) (!!((v) & 0x08))
#define GET_NUM(v) ((v) >> 4)

#define SET_BLOCK_SIZE(v, b) (v |= ((b) & 0x07))
#define SET_MORE(v, m) ((v) |= (m) ? 0x08 : 0x00)
#define SET_NUM(v, n) ((v) |= ((n) << 4))

int srtsp_append_block1_option(struct srtsp_packet *cpkt,
			      struct srtsp_block_context *ctx)
{
	u16_t bytes = srtsp_block_size_to_bytes(ctx->block_size);
	unsigned int val = 0;
	int r;

	if (is_request(cpkt)) {
		SET_BLOCK_SIZE(val, ctx->block_size);
		SET_MORE(val, ctx->current + bytes < ctx->total_size);
		SET_NUM(val, ctx->current / bytes);
	} else {
		SET_BLOCK_SIZE(val, ctx->block_size);
		SET_NUM(val, ctx->current / bytes);
	}

	r = srtsp_append_option_int(cpkt, SRTSP_OPTION_BLOCK1, val);

	return r;
}

int srtsp_append_block2_option(struct srtsp_packet *cpkt,
			      struct srtsp_block_context *ctx)
{
	int r, val = 0;
	u16_t bytes = srtsp_block_size_to_bytes(ctx->block_size);

	if (is_request(cpkt)) {
		SET_BLOCK_SIZE(val, ctx->block_size);
		SET_NUM(val, ctx->current / bytes);
	} else {
		SET_BLOCK_SIZE(val, ctx->block_size);
		SET_MORE(val, ctx->current + bytes < ctx->total_size);
		SET_NUM(val, ctx->current / bytes);
	}

	r = srtsp_append_option_int(cpkt, SRTSP_OPTION_BLOCK2, val);

	return r;
}

int srtsp_append_size1_option(struct srtsp_packet *cpkt,
			     struct srtsp_block_context *ctx)
{
	return srtsp_append_option_int(cpkt, SRTSP_OPTION_SIZE1, ctx->total_size);
}

int srtsp_append_size2_option(struct srtsp_packet *cpkt,
			     struct srtsp_block_context *ctx)
{
	return srtsp_append_option_int(cpkt, SRTSP_OPTION_SIZE2, ctx->total_size);
}

static int get_block_option(const struct srtsp_packet *cpkt, u16_t code)
{
	struct srtsp_option option;
	unsigned int val;
	int count = 1;

	count = srtsp_find_options(cpkt, code, &option, count);
	if (count <= 0) {
		return -ENOENT;
	}

	val = srtsp_option_value_to_int(&option);

	return val;
}

static int update_descriptive_block(struct srtsp_block_context *ctx,
				    int block, int size)
{
	size_t new_current = GET_NUM(block) << (GET_BLOCK_SIZE(block) + 4);

	if (block == -ENOENT) {
		return 0;
	}

	if (size && ctx->total_size && ctx->total_size != size) {
		return -EINVAL;
	}

	if (ctx->current > 0 && GET_BLOCK_SIZE(block) > ctx->block_size) {
		return -EINVAL;
	}

	if (ctx->total_size && new_current > ctx->total_size) {
		return -EINVAL;
	}

	if (size) {
		ctx->total_size = size;
	}
	ctx->current = new_current;
	ctx->block_size = min(GET_BLOCK_SIZE(block), ctx->block_size);

	return 0;
}

static int update_control_block1(struct srtsp_block_context *ctx,
				     int block, int size)
{
	size_t new_current = GET_NUM(block) << (GET_BLOCK_SIZE(block) + 4);

	if (block == -ENOENT) {
		return 0;
	}

	if (new_current != ctx->current) {
		return -EINVAL;
	}

	if (GET_BLOCK_SIZE(block) > ctx->block_size) {
		return -EINVAL;
	}

	ctx->block_size = GET_BLOCK_SIZE(block);
	ctx->total_size = size;

	return 0;
}

static int update_control_block2(struct srtsp_block_context *ctx,
				 int block, int size)
{
	size_t new_current = GET_NUM(block) << (GET_BLOCK_SIZE(block) + 4);

	if (block == -ENOENT) {
		return 0;
	}

	if (GET_MORE(block)) {
		return -EINVAL;
	}

	if (GET_NUM(block) > 0 && GET_BLOCK_SIZE(block) != ctx->block_size) {
		return -EINVAL;
	}

	ctx->current = new_current;
	ctx->block_size = min(GET_BLOCK_SIZE(block), ctx->block_size);

	return 0;
}

int srtsp_update_from_block(const struct srtsp_packet *cpkt,
			   struct srtsp_block_context *ctx)
{
	int r, block1, block2, size1, size2;

	block1 = get_block_option(cpkt, SRTSP_OPTION_BLOCK1);
	block2 = get_block_option(cpkt, SRTSP_OPTION_BLOCK2);
	size1 = get_block_option(cpkt, SRTSP_OPTION_SIZE1);
	size2 = get_block_option(cpkt, SRTSP_OPTION_SIZE2);

	size1 = size1 == -ENOENT ? 0 : size1;
	size2 = size2 == -ENOENT ? 0 : size2;

	if (is_request(cpkt)) {
		r = update_control_block2(ctx, block2, size2);
		if (r) {
			return r;
		}

		return update_descriptive_block(ctx, block1, size1);
	}

	r = update_control_block1(ctx, block1, size1);
	if (r) {
		return r;
	}

	return update_descriptive_block(ctx, block2, size2);
}

size_t srtsp_next_block(const struct srtsp_packet *cpkt,
		       struct srtsp_block_context *ctx)
{
	int block;

	if (is_request(cpkt)) {
		block = get_block_option(cpkt, SRTSP_OPTION_BLOCK1);
	} else {
		block = get_block_option(cpkt, SRTSP_OPTION_BLOCK2);
	}

	if (!GET_MORE(block)) {
		return 0;
	}

	ctx->current += srtsp_block_size_to_bytes(ctx->block_size);

	return ctx->current;
}

u8_t *srtsp_next_token(void)
{
	static u32_t rand[2];

	rand[0] = sys_rand32_get();
	rand[1] = sys_rand32_get();

	return (u8_t *) rand;
}
