/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 *
 * @brief CoAP implementation for Zephyr.
 */

#ifndef __SRTSP_H__
#define __SRTSP_H__

#include <zephyr/types.h>
#include <stddef.h>
#include <stdbool.h>
#include <net/net_ip.h>

#include <misc/slist.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief SRTSP library
 * @defgroup srtsp SRTSP Library
 * @ingroup networking
 * @{
 */

/**
 * @brief Set of CoAP packet options we are aware of.
 *
 * Users may add options other than these to their packets, provided
 * they know how to format them correctly. The only restriction is
 * that all options must be added to a packet in numeric order.
 *
 * Refer to RFC 7252, section 12.2 for more information.
 */
enum srtsp_option_num {
	SRTSP_OPTION_IF_MATCH = 1,
	SRTSP_OPTION_URI_HOST = 3,
	SRTSP_OPTION_ETAG = 4,
	SRTSP_OPTION_IF_NONE_MATCH = 5,
	SRTSP_OPTION_OBSERVE = 6,
	SRTSP_OPTION_URI_PORT = 7,
	SRTSP_OPTION_LOCATION_PATH = 8,
	SRTSP_OPTION_URI_PATH = 11,
	SRTSP_OPTION_CONTENT_FORMAT = 12,
	SRTSP_OPTION_MAX_AGE = 14,
	SRTSP_OPTION_URI_QUERY = 15,
	SRTSP_OPTION_ACCEPT = 17,
	SRTSP_OPTION_LOCATION_QUERY = 20,
	SRTSP_OPTION_BLOCK2 = 23,
	SRTSP_OPTION_BLOCK1 = 27,
	SRTSP_OPTION_SIZE2 = 28,
	SRTSP_OPTION_PROXY_URI = 35,
	SRTSP_OPTION_PROXY_SCHEME = 39,
	SRTSP_OPTION_SIZE1 = 60,
};

/**
 * @brief Available request methods.
 *
 * To be used when creating a request or a response.
 */
enum srtsp_method {
	SRTSP_METHOD_SETUP = 0,
	SRTSP_METHOD_PLAY = 1,
	SRTSP_METHOD_PAUSE = 2,
	SRTSP_METHOD_TEARDOWN = 3,
};

#define SRTSP_REQUEST_MASK 0x07

/**
 * @brief CoAP packets may be of one of these types.
 */
enum srtsp_msgtype {
	/**
	 * Confirmable message.
	 *
	 * The packet is a request or response the destination end-point must
	 * acknowledge.
	 */
	SRTSP_TYPE_CON = 0,
	/**
	 * Non-confirmable message.
	 *
	 * The packet is a request or response that doesn't
	 * require acknowledgements.
	 */
	SRTSP_TYPE_NON_CON = 1,
	/**
	 * Acknowledge.
	 *
	 * Response to a confirmable message.
	 */
	SRTSP_TYPE_ACK = 2,
	/**
	 * Reset.
	 *
	 * Rejecting a packet for any reason is done by sending a message
	 * of this type.
	 */
	SRTSP_TYPE_RESET = 3
};

#define srtsp_make_response_code(clas, det) ((clas << 5) | (det))

/**
 * @brief Set of response codes available for a response packet.
 *
 * To be used when creating a response.
 */
enum srtsp_response_code {
	SRTSP_RESPONSE_CODE_OK = srtsp_make_response_code(2, 0),
	/*SRTSP_RESPONSE_CODE_CREATED = srtsp_make_response_code(2, 1),
	SRTSP_RESPONSE_CODE_DELETED = srtsp_make_response_code(2, 2),
	SRTSP_RESPONSE_CODE_VALID = srtsp_make_response_code(2, 3),
	SRTSP_RESPONSE_CODE_CHANGED = srtsp_make_response_code(2, 4),
	SRTSP_RESPONSE_CODE_CONTENT = srtsp_make_response_code(2, 5),
	SRTSP_RESPONSE_CODE_CONTINUE = srtsp_make_response_code(2, 31),
	*/
	SRTSP_RESPONSE_CODE_MOVED_PERMANENTLY = srtsp_make_response_code(3, 1),
	SRTSP_RESPONSE_CODE_FOUND = srtsp_make_response_code(3, 2),
	SRTSP_RESPONSE_CODE_SEE_OTHER = srtsp_make_response_code(3, 3),
	SRTSP_RESPONSE_CODE_NOT_MODIFIED = srtsp_make_response_code(3, 4),
	SRTSP_RESPONSE_CODE_USE_PROXY = srtsp_make_response_code(3, 5),
	SRTSP_RESPONSE_CODE_BAD_REQUEST = srtsp_make_response_code(4, 0),
	SRTSP_RESPONSE_CODE_UNAUTHORIZED = srtsp_make_response_code(4, 1),
	SRTSP_RESPONSE_CODE_BAD_OPTION = srtsp_make_response_code(4, 2), //RTSP spec says this should by payment required, leavingn it as bad optoin
	SRTSP_RESPONSE_CODE_FORBIDDEN = srtsp_make_response_code(4, 3),
	SRTSP_RESPONSE_CODE_NOT_FOUND = srtsp_make_response_code(4, 4),
	SRTSP_RESPONSE_CODE_NOT_ALLOWED = srtsp_make_response_code(4, 5),
	SRTSP_RESPONSE_CODE_NOT_ACCEPTABLE = srtsp_make_response_code(4, 6),
	SRTSP_RESPONSE_CODE_REQUEST_TIMEOUT = srtsp_make_response_code(4, 8),
	SRTSP_RESPONSE_CODE_GONE = srtsp_make_response_code(4, 10),
	SRTSP_RESPONSE_CODE_PRECONDITION_FAILED = srtsp_make_response_code(4, 12),
	SRTSP_RESPONSE_CODE_REQUEST_TOO_LARGE = srtsp_make_response_code(4, 13),
	SRTSP_RESPONSE_CODE_URI_TO_LONG = srtsp_make_response_code(4, 14),
	SRTSP_RESPONSE_CODE_UNSUPPORTED_CONTENT_FORMAT =
						srtsp_make_response_code(4, 15),
	SRTSP_RESPONSE_CODE_INVALID_RANGE = srtsp_make_response_code(4, 57),
	SRTSP_RESPONSE_CODE_INTERNAL_ERROR = srtsp_make_response_code(5, 0),
	SRTSP_RESPONSE_CODE_NOT_IMPLEMENTED = srtsp_make_response_code(5, 1),
	SRTSP_RESPONSE_CODE_BAD_GATEWAY = srtsp_make_response_code(5, 2),
	SRTSP_RESPONSE_CODE_SERVICE_UNAVAILABLE = srtsp_make_response_code(5, 3),
	SRTSP_RESPONSE_CODE_GATEWAY_TIMEOUT = srtsp_make_response_code(5, 4),
	SRTSP_RESPONSE_CODE_PROXYING_NOT_SUPPORTED =
						srtsp_make_response_code(5, 5)
};

#define SRTSP_CODE_EMPTY (0)

struct srtsp_observer;
struct srtsp_packet;
struct srtsp_pending;
struct srtsp_reply;
struct srtsp_resource;

/**
 * @typedef srtsp_method_t
 * @brief Type of the callback being called when a resource's method is
 * invoked by the remote entity.
 */
typedef int (*srtsp_method_t)(struct srtsp_resource *resource,
			     struct srtsp_packet *request);

/**
 * @typedef srtsp_notify_t
 * @brief Type of the callback being called when a resource's has observers
 * to be informed when an update happens.
 */
typedef void (*srtsp_notify_t)(struct srtsp_resource *resource,
			      struct srtsp_observer *observer);

/**
 * @brief Description of CoAP resource.
 *
 * CoAP servers often want to register resources, so that clients can act on
 * them, by fetching their state or requesting updates to them.
 */
struct srtsp_resource {
	/** Which function to be called for each CoAP method */
	srtsp_method_t setup, play, pause, teardown;
	srtsp_notify_t notify;
	const char * const *path;
	void *user_data;
	sys_slist_t observers;
	int age;
};

/**
 * @brief Represents a remote device that is observing a local resource.
 */
struct srtsp_observer {
	sys_snode_t list;
	struct sockaddr addr;
	u8_t token[8];
	u8_t tkl;
};

/**
 * @brief Representation of a CoAP packet.
 */
struct srtsp_packet {
	struct net_pkt *pkt;
	struct net_buf *frag; /* Where CoAP header resides */
	u16_t offset; /* Where CoAP header starts.*/
	u8_t hdr_len; /* CoAP header length */
	u8_t opt_len; /* Total options length (delta + len + value) */
	u16_t last_delta; /* Used only when preparing CoAP packet */
};

/**
 * @typedef srtsp_reply_t
 * @brief Helper function to be called when a response matches the
 * a pending request.
 */
typedef int (*srtsp_reply_t)(const struct srtsp_packet *response,
			    struct srtsp_reply *reply,
			    const struct sockaddr *from);

/**
 * @brief Represents a request awaiting for an acknowledgment (ACK).
 */
struct srtsp_pending {
	struct net_pkt *pkt;
	struct sockaddr addr;
	s32_t timeout;
	u16_t id;
};

/**
 * @brief Represents the handler for the reply of a request, it is
 * also used when observing resources.
 */
struct srtsp_reply {
	srtsp_reply_t reply;
	void *user_data;
	int age;
	u8_t timestamp[4];
	u16_t id;
	u8_t res_bits;
};

/**
 * @brief Indicates that the remote device referenced by @a addr, with
 * @a request, wants to observe a resource.
 *
 * @param observer Observer to be initialized
 * @param request Request on which the observer will be based
 * @param addr Address of the remote device
 */
void srtsp_observer_init(struct srtsp_observer *observer,
			const struct srtsp_packet *request,
			const struct sockaddr *addr);

/**
 * @brief After the observer is initialized, associate the observer
 * with an resource.
 *
 * @param resource Resource to add an observer
 * @param observer Observer to be added
 *
 * @return true if this is the first observer added to this resource.
 */
bool srtsp_register_observer(struct srtsp_resource *resource,
			    struct srtsp_observer *observer);

/**
 * @brief Remove this observer from the list of registered observers
 * of that resource.
 *
 * @param resource Resource in which to remove the observer
 * @param observer Observer to be removed
 */
void srtsp_remove_observer(struct srtsp_resource *resource,
			  struct srtsp_observer *observer);

/**
 * @brief Returns the observer that matches address @a addr.
 *
 * @param observers Pointer to the array of observers
 * @param len Size of the array of observers
 * @param addr Address of the endpoint observing a resource
 *
 * @return A pointer to a observer if a match is found, NULL
 * otherwise.
 */
struct srtsp_observer *srtsp_find_observer_by_addr(
	struct srtsp_observer *observers, size_t len,
	const struct sockaddr *addr);

/**
 * @brief Returns the next available observer representation.
 *
 * @param observers Pointer to the array of observers
 * @param len Size of the array of observers
 *
 * @return A pointer to a observer if there's an available observer,
 * NULL otherwise.
 */
struct srtsp_observer *srtsp_observer_next_unused(
	struct srtsp_observer *observers, size_t len);

/**
 * @brief Indicates that a reply is expected for @a request.
 *
 * @param reply Reply structure to be initialized
 * @param request Request from which @a reply will be based
 */
void srtsp_reply_init(struct srtsp_reply *reply,
		     const struct srtsp_packet *request);

/**
 * @brief Represents the value of a CoAP option.
 *
 * To be used with srtsp_find_options().
 */
struct srtsp_option {
	u16_t delta;

#if defined(CONFIG_SRTSP_EXTENDED_OPTIONS_LEN) //can define a config option for this later
	u16_t len;
	u8_t value[CONFIG_SRTSP_EXTENDED_OPTIONS_LEN_VALUE];
#else
	u8_t len;
	//13, 14, 15 reserved for special use
	u8_t value[12];
#endif
};

/**
 * @brief Parses the CoAP packet in @a pkt, validating it and
 * initializing @a cpkt. @a pkt must remain valid while @a cpkt is used.
 *
 * @param cpkt Packet to be initialized from received @a pkt.
 * @param pkt Network Packet containing a CoAP packet, its @a data pointer is
 * positioned on the start of the CoAP packet.
 * @param options Parse options and cache its details.
 * @param opt_num Number of options
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_packet_parse(struct srtsp_packet *cpkt, struct net_pkt *pkt,
		      struct srtsp_option *options, u8_t opt_num);

/**
 * @brief Creates a new CoAP packet from a net_pkt. @a pkt must remain
 * valid while @a cpkt is used.
 *
 * @param cpkt New packet to be initialized using the storage from @a
 * pkt.
 * @param pkt Network Packet that will contain a CoAP packet
 * @param ver CoAP header version
 * @param type CoAP header type
 * @param tokenlen CoAP header token length
 * @param token CoAP header token
 * @param code CoAP header code
 * @param id CoAP header message id
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_packet_init(struct srtsp_packet *cpkt, struct net_pkt *pkt,
		     u8_t ver, u8_t type, u8_t tokenlen,
		     u8_t *token, u8_t code, u16_t id);

/**
 * @brief Initialize a pending request with a request.
 *
 * The request's fields are copied into the pending struct, so @a
 * request doesn't have to live for as long as the pending struct
 * lives, but net_pkt needs to live for at least that long.
 *
 * @param pending Structure representing the waiting for a
 * confirmation message, initialized with data from @a request
 * @param request Message waiting for confirmation
 * @param addr Address to send the retransmission
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_pending_init(struct srtsp_pending *pending,
		      const struct srtsp_packet *request,
		      const struct sockaddr *addr);

/**
 * @brief Returns the next available pending struct, that can be used
 * to track the retransmission status of a request.
 *
 * @param pendings Pointer to the array of #srtsp_pending structures
 * @param len Size of the array of #srtsp_pending structures
 *
 * @return pointer to a free #srtsp_pending structure, NULL in case
 * none could be found.
 */
struct srtsp_pending *srtsp_pending_next_unused(
	struct srtsp_pending *pendings, size_t len);

/**
 * @brief Returns the next available reply struct, so it can be used
 * to track replies and notifications received.
 *
 * @param replies Pointer to the array of #srtsp_reply structures
 * @param len Size of the array of #srtsp_reply structures
 *
 * @return pointer to a free #srtsp_reply structure, NULL in case
 * none could be found.
 */
struct srtsp_reply *srtsp_reply_next_unused(
	struct srtsp_reply *replies, size_t len);

/**
 * @brief After a response is received, clear all pending
 * retransmissions related to that response.
 *
 * @param response The received response
 * @param pendings Pointer to the array of #srtsp_reply structures
 * @param len Size of the array of #srtsp_reply structures
 *
 * @return pointer to the associated #srtsp_pending structure, NULL in
 * case none could be found.
 */
struct srtsp_pending *srtsp_pending_received(
	const struct srtsp_packet *response,
	struct srtsp_pending *pendings, size_t len);

/**
 * @brief After a response is received, call srtsp_reply_t handler
 * registered in #srtsp_reply structure
 *
 * @param response A response received
 * @param from Address from which the response was received
 * @param replies Pointer to the array of #srtsp_reply structures
 * @param len Size of the array of #srtsp_reply structures
 *
 * @return Pointer to the reply matching the packet received, NULL if
 * none could be found.
 */
struct srtsp_reply *srtsp_response_received(
	const struct srtsp_packet *response,
	const struct sockaddr *from,
	struct srtsp_reply *replies, size_t len);

/**
 * @brief Returns the next pending about to expire, pending->timeout
 * informs how many ms to next expiration.
 *
 * @param pendings Pointer to the array of #srtsp_pending structures
 * @param len Size of the array of #srtsp_pending structures
 *
 * @return The next #srtsp_pending to expire, NULL if none is about to
 * expire.
 */
struct srtsp_pending *srtsp_pending_next_to_expire(
	struct srtsp_pending *pendings, size_t len);

/**
 * @brief After a request is sent, user may want to cycle the pending
 * retransmission so the timeout is updated.
 *
 * @param pending Pending representation to have its timeout updated
 *
 * @return false if this is the last retransmission.
 */
bool srtsp_pending_cycle(struct srtsp_pending *pending);

/**
 * @brief Cancels the pending retransmission, so it again becomes
 * available.
 *
 * @param pending Pending representation to be canceled
 */
void srtsp_pending_clear(struct srtsp_pending *pending);

/**
 * @brief Cancels awaiting for this reply, so it becomes available
 * again.
 *
 * @param reply The reply to be canceled
 */
void srtsp_reply_clear(struct srtsp_reply *reply);

/**
 * @brief When a request is received, call the appropriate methods of
 * the matching resources.
 *
 * @param cpkt Packet received
 * @param resources Array of known resources
 * @param options Parsed options from srtsp_packet_parse()
 * @param opt_num Number of options
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_handle_request(struct srtsp_packet *cpkt,
			struct srtsp_resource *resources,
			struct srtsp_option *options,
			u8_t opt_num);

/**
 * @brief Indicates that this resource was updated and that the @a
 * notify callback should be called for every registered observer.
 *
 * @param resource Resource that was updated
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_resource_notify(struct srtsp_resource *resource);

/**
 * @brief Returns if this request is enabling observing a resource.
 *
 * @param request Request to be checked
 *
 * @return True if the request is enabling observing a resource, False
 * otherwise
 */
bool srtsp_request_is_observe(const struct srtsp_packet *request);

/**
 * @brief Append payload marker to CoAP packet
 *
 * @param cpkt Packet to append the payload marker (0xFF)
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_packet_append_payload_marker(struct srtsp_packet *cpkt);

/**
 * @brief Append payload to CoAP packet
 *
 * @param cpkt Packet to append the payload
 * @param payload CoAP packet payload
 * @param payload_len CoAP packet payload len
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_packet_append_payload(struct srtsp_packet *cpkt, u8_t *payload,
			       u16_t payload_len);

/**
 * @brief Appends an option to the packet.
 *
 * Note: options must be added in numeric order of their codes. Otherwise
 * error will be returned.
 * TODO: Add support for placing options according to its delta value.
 *
 * @param cpkt Packet to be updated
 * @param code Option code to add to the packet, see #srtsp_option_num
 * @param value Pointer to the value of the option, will be copied to the packet
 * @param len Size of the data to be added
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_packet_append_option(struct srtsp_packet *cpkt, u16_t code,
			      const u8_t *value, u16_t len);

/**
 * @brief Converts an option to its integer representation.
 *
 * Assumes that the number is encoded in the network byte order in the
 * option.
 *
 * @param option Pointer to the option value, retrieved by
 * srtsp_find_options()
 *
 * @return The integer representation of the option
 */
unsigned int srtsp_option_value_to_int(const struct srtsp_option *option);

/**
 * @brief Appends an integer value option to the packet.
 *
 * The option must be added in numeric order of their codes, and the
 * least amount of bytes will be used to encode the value.
 *
 * @param cpkt Packet to be updated
 * @param code Option code to add to the packet, see #srtsp_option_num
 * @param val Integer value to be added
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_append_option_int(struct srtsp_packet *cpkt, u16_t code,
			   unsigned int val);

/**
 * @brief Return the values associated with the option of value @a
 * code.
 *
 * @param cpkt CoAP packet representation
 * @param code Option number to look for
 * @param options Array of #srtsp_option where to store the value
 * of the options found
 * @param veclen Number of elements in the options array
 *
 * @return The number of options found in packet matching code,
 * negative on error.
 */
int srtsp_find_options(const struct srtsp_packet *cpkt, u16_t code,
		      struct srtsp_option *options, u16_t veclen);

/**
 * Represents the size of each block that will be transferred using
 * block-wise transfers [RFC7959]:
 *
 * Each entry maps directly to the value that is used in the wire.
 *
 * https://tools.ietf.org/html/rfc7959
 */
enum srtsp_block_size {
	SRTSP_BLOCK_16,
	SRTSP_BLOCK_32,
	SRTSP_BLOCK_64,
	SRTSP_BLOCK_128,
	SRTSP_BLOCK_256,
	SRTSP_BLOCK_512,
	SRTSP_BLOCK_1024,
};

/**
 * @brief Helper for converting the enumeration to the size expressed
 * in bytes.
 *
 * @param block_size The block size to be converted
 *
 * @return The size in bytes that the block_size represents
 */
static inline u16_t srtsp_block_size_to_bytes(
	enum srtsp_block_size block_size)
{
	return (1 << (block_size + 4));
}

/**
 * @brief Represents the current state of a block-wise transaction.
 */
struct srtsp_block_context {
	size_t total_size;
	size_t current;
	enum srtsp_block_size block_size;
};

/**
 * @brief Initializes the context of a block-wise transfer.
 *
 * @param ctx The context to be initialized
 * @param block_size The size of the block
 * @param total_size The total size of the transfer, if known
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_block_transfer_init(struct srtsp_block_context *ctx,
			     enum srtsp_block_size block_size,
			     size_t total_size);

/**
 * @brief Append BLOCK1 option to the packet.
 *
 * @param cpkt Packet to be updated
 * @param ctx Block context from which to retrieve the
 * information for the Block1 option
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_append_block1_option(struct srtsp_packet *cpkt,
			      struct srtsp_block_context *ctx);

/**
 * @brief Append BLOCK2 option to the packet.
 *
 * @param cpkt Packet to be updated
 * @param ctx Block context from which to retrieve the
 * information for the Block2 option
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_append_block2_option(struct srtsp_packet *cpkt,
			      struct srtsp_block_context *ctx);

/**
 * @brief Append SIZE1 option to the packet.
 *
 * @param cpkt Packet to be updated
 * @param ctx Block context from which to retrieve the
 * information for the Size1 option
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_append_size1_option(struct srtsp_packet *cpkt,
			     struct srtsp_block_context *ctx);

/**
 * @brief Append SIZE2 option to the packet.
 *
 * @param cpkt Packet to be updated
 * @param ctx Block context from which to retrieve the
 * information for the Size2 option
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_append_size2_option(struct srtsp_packet *cpkt,
			     struct srtsp_block_context *ctx);

/**
 * @brief Retrieves BLOCK{1,2} and SIZE{1,2} from @a cpkt and updates
 * @a ctx accordingly.
 *
 * @param cpkt Packet in which to look for block-wise transfers options
 * @param ctx Block context to be updated
 *
 * @return 0 in case of success or negative in case of error.
 */
int srtsp_update_from_block(const struct srtsp_packet *cpkt,
			   struct srtsp_block_context *ctx);

/**
 * @brief Updates @a ctx so after this is called the current entry
 * indicates the correct offset in the body of data being
 * transferred.
 *
 * @param cpkt Packet in which to look for block-wise transfers options
 * @param ctx Block context to be updated
 *
 * @return The offset in the block-wise transfer, 0 if the transfer
 * has finished.
 */
size_t srtsp_next_block(const struct srtsp_packet *cpkt,
		       struct srtsp_block_context *ctx);

/**
 * @brief Returns the version present in a CoAP packet.
 *
 * @param cpkt CoAP packet representation
 *
 * @return the CoAP version in packet
 */
u8_t srtsp_header_get_version(const struct srtsp_packet *cpkt);

/**
 * @brief Returns the type of the CoAP packet.
 *
 * @param cpkt CoAP packet representation
 *
 * @return the type of the packet
 */
u8_t srtsp_header_get_type(const struct srtsp_packet *cpkt);

/**
 * @brief Returns the token (if any) in the CoAP packet.
 *
 * @param cpkt CoAP packet representation
 * @param timestamp Where to store the timestamp
 *
 * @return Timestamp length in the CoAP packet.
 */
u8_t srtsp_header_get_timestamp(const struct srtsp_packet *cpkt, u8_t *token);

/**
 * @brief Returns the code of the CoAP packet.
 *
 * @param cpkt CoAP packet representation
 *
 * @return the code present in the packet
 */
u8_t srtsp_header_get_code(const struct srtsp_packet *cpkt);

/**
 * @brief Returns the message id associated with the CoAP packet.
 *
 * @param cpkt CoAP packet representation
 *
 * @return the message id present in the packet
 */
u16_t srtsp_header_get_id(const struct srtsp_packet *cpkt);

/**
 * @brief Helper to generate message ids
 *
 * @return a new message id
 */
static inline u16_t srtsp_next_id(void)
{
	static u16_t message_id;

	return ++message_id;
}

/**
 * @brief Returns the fragment pointer and offset where payload starts
 * in the CoAP packet.
 *
 * @param cpkt CoAP packet representation
 * @param offset Stores the offset value where payload starts
 * @param len Total length of CoAP payload
 *
 * @return the net_buf fragment pointer and offset value if payload exists
 *         NULL pointer and offset set to 0 in case there is no payload
 *         NULL pointer and offset value 0xffff in case of an error
 */
struct net_buf *srtsp_packet_get_payload(const struct srtsp_packet *cpkt,
					u16_t *offset,
					u16_t *len);


/**
 * @brief Returns a randomly generated array of 8 bytes, that can be
 * used as a message's token.
 *
 * @return a 8-byte pseudo-random token.
 */
u8_t *srtsp_next_token(void);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __SRTSP_H__ */
