/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if 1
#define SYS_LOG_DOMAIN "srtsp-server"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <errno.h>

#include <zephyr.h>
#include <board.h>

#include <misc/byteorder.h>
#include <net/net_core.h>
#include <net/net_ip.h>
#include <net/net_pkt.h>
#include <net/net_context.h>
#include <net/udp.h>

#include <net_private.h>

#include <logging/sys_log.h>


#include <gpio.h>

#include <net/srtsp.h>
#include <net/srtsp_link_format.h>

#define MY_SRTSP_PORT 5683

#define ALL_NODES_LOCAL_SRTSP_MCAST					\
	{ { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd } } }

#define MY_IP6ADDR \
	{ { { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1 } } }

#if defined(LED0_GPIO_PORT)
#define LED_GPIO_NAME LED0_GPIO_PORT
#define LED_PIN LED0_GPIO_PIN
#else
#define LED_GPIO_NAME "(fail)"
#define LED_PIN 0
#endif

static struct net_context *context;

static struct device *led0;

static const char led_on[] = "LED ON\n";
static const char led_off[] = "LED OFF\n";
static const char led_toggle_on[] = "LED Toggle ON\n";
static const char led_toggle_off[] = "LED Toggle OFF\n";

static bool fake_led;

static void get_from_ip_addr(struct srtsp_packet *cpkt,
			     struct sockaddr_in6 *from)
{
	struct net_udp_hdr hdr, *udp_hdr;

	udp_hdr = net_udp_get_hdr(cpkt->pkt, &hdr);
	if (!udp_hdr) {
		return;
	}

	net_ipaddr_copy(&from->sin6_addr, &NET_IPV6_HDR(cpkt->pkt)->src);

	from->sin6_port = udp_hdr->src_port;
	from->sin6_family = AF_INET6;
}

static int well_known_core_get(struct srtsp_resource *resource,
			       struct srtsp_packet *request)
{
	struct srtsp_packet response;
	struct sockaddr_in6 from;
	struct net_pkt *pkt;
	struct net_buf *frag;
	int r;

	NET_DBG("");

	pkt = net_pkt_get_tx(context, K_FOREVER);
	frag = net_pkt_get_data(context, K_FOREVER);
	net_pkt_frag_add(pkt, frag);

	r = srtsp_well_known_core_get(resource, request, &response, pkt);
	if (r < 0) {
		net_pkt_unref(response.pkt);
		return r;
	}

	get_from_ip_addr(request, &from);
	r = net_context_sendto(response.pkt, (const struct sockaddr *)&from,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		net_pkt_unref(response.pkt);
	}

	return r;
}

static bool read_led(void)
{
	u32_t led = 0;
	int r;

	if (!led0) {
		return fake_led;
	}

	r = gpio_pin_read(led0, LED_PIN, &led);
	if (r < 0) {
		return false;
	}

	return !led;
}

static void write_led(bool led)
{
	if (!led0) {
		fake_led = led;
		return;
	}

	gpio_pin_write(led0, LED_PIN, !led);
}

static int led_get(struct srtsp_resource *resource,
		   struct srtsp_packet *request)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct srtsp_packet response;
	const char *str;
	u16_t len, id;
	int r;

	SYS_LOG_DBG("GET WAS CALLED");


	id = srtsp_header_get_id(request);

	pkt = net_pkt_get_tx(context, K_FOREVER);
	if (!pkt) {
		return -ENOMEM;
	}

	frag = net_pkt_get_data(context, K_FOREVER);
	if (!frag) {
		return -ENOMEM;
	}

	net_pkt_frag_add(pkt, frag);

	r = srtsp_packet_init(&response, pkt, 1, SRTSP_TYPE_ACK,
			     0, NULL, SRTSP_RESPONSE_CODE_OK, id);
	if (r < 0) {
		return -EINVAL;
	}

	if (read_led()) {
		str = led_on;
		len = sizeof(led_on);
	} else {
		str = led_off;
		len = sizeof(led_off);
	}

	r = srtsp_packet_append_payload_marker(&response);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	r = srtsp_packet_append_payload(&response, (u8_t *)str, len);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	get_from_ip_addr(request, &from);
	r = net_context_sendto(pkt, (const struct sockaddr *)&from,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		net_pkt_unref(pkt);
	}

	return r;
}

static int led_post(struct srtsp_resource *resource,
		    struct srtsp_packet *request)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct srtsp_packet response;
	const char *str;
	u8_t payload;
	u8_t len;
	u16_t id;
	u16_t offset;
	u32_t led;
	int r;

	SYS_LOG_DBG("POST WAS CALLED");

	led = 0;
	frag = net_frag_skip(request->frag, request->offset, &offset,
			     request->hdr_len + request->opt_len);
	if (!frag && offset == 0xffff) {
		return -EINVAL;
	}

	frag = net_frag_read_u8(frag, offset, &offset, &payload);
	if (!frag && offset == 0xffff) {
		printk("packet without payload, so toggle the led");
		led = read_led();
		led = !led;
	} else {
		if (payload == 0x31) {
			led = 1;
		}
	}

	write_led(led);

	id = srtsp_header_get_id(request);

	pkt = net_pkt_get_tx(context, K_FOREVER);
	if (!pkt) {
		return -ENOMEM;
	}

	frag = net_pkt_get_data(context, K_FOREVER);
	if (!frag) {
		return -ENOMEM;
	}

	net_pkt_frag_add(pkt, frag);

	r = srtsp_packet_init(&response, pkt, 1, SRTSP_TYPE_ACK,
			     0, NULL, SRTSP_RESPONSE_CODE_OK, id); //response code no longer exists, reference another one
	if (r < 0) {
		return -EINVAL;
	}

	if (led) {
		str = led_toggle_on;
		len = sizeof(led_toggle_on);
	} else {
		str = led_toggle_off;
		len = sizeof(led_toggle_off);
	}

	r = srtsp_packet_append_payload_marker(&response);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	r = srtsp_packet_append_payload(&response, (u8_t *)str, len);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	get_from_ip_addr(request, &from);
	r = net_context_sendto(pkt, (const struct sockaddr *)&from,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		net_pkt_unref(pkt);
	}

	return r;
}

static int led_put(struct srtsp_resource *resource,
		   struct srtsp_packet *request)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct srtsp_packet response;
	const char *str;
	u8_t payload;
	u8_t len;
	u16_t id;
	u16_t offset;
	u32_t led;
	int r;

	SYS_LOG_DBG("PUT WAS CALLED");

	led = 0;
	frag = net_frag_skip(request->frag, request->offset, &offset,
			     request->hdr_len + request->opt_len);
	if (!frag && offset == 0xffff) {
		return -EINVAL;
	}

	frag = net_frag_read_u8(frag, offset, &offset, &payload);
	if (!frag && offset == 0xffff) {
		printk("packet without payload, so toggle the led");
		led = read_led();
		led = !led;
	} else {
		if (payload == 0x31) {
			led = 1;
		}
	}

	write_led(led);

	id = srtsp_header_get_id(request);

	pkt = net_pkt_get_tx(context, K_FOREVER);
	if (!pkt) {
		return -ENOMEM;
	}

	frag = net_pkt_get_data(context, K_FOREVER);
	if (!frag) {
		return -ENOMEM;
	}

	net_pkt_frag_add(pkt, frag);

	r = srtsp_packet_init(&response, pkt, 1, SRTSP_TYPE_ACK,
			     0, NULL, SRTSP_RESPONSE_CODE_OK, id);
	if (r < 0) {
		return -EINVAL;
	}

	if (led) {
		str = led_on;
		len = sizeof(led_on);
	} else {
		str = led_off;
		len = sizeof(led_off);
	}

	r = srtsp_packet_append_payload_marker(&response);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	r = srtsp_packet_append_payload(&response, (u8_t *)str, len);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	get_from_ip_addr(request, &from);
	r = net_context_sendto(pkt, (const struct sockaddr *)&from,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		net_pkt_unref(pkt);
	}

	return r;
}

static int dummy_get(struct srtsp_resource *resource,
		     struct srtsp_packet *request)
{
	static const char dummy_str[] = "Just a test\n";
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct srtsp_packet response;
	u16_t id;
	int r;

	id = srtsp_header_get_id(request);

	pkt = net_pkt_get_tx(context, K_FOREVER);
	if (!pkt) {
		return -ENOMEM;
	}

	frag = net_pkt_get_data(context, K_FOREVER);
	if (!frag) {
		return -ENOMEM;
	}

	net_pkt_frag_add(pkt, frag);

	r = srtsp_packet_init(&response, pkt, 1, SRTSP_TYPE_ACK,
			     0, NULL, SRTSP_RESPONSE_CODE_OK, id);
	if (r < 0) {
		return -EINVAL;
	}

	r = srtsp_packet_append_payload_marker(&response);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	r = srtsp_packet_append_payload(&response, (u8_t *)dummy_str,
				      sizeof(dummy_str));
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	get_from_ip_addr(request, &from);
	r = net_context_sendto(pkt, (const struct sockaddr *)&from,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		net_pkt_unref(pkt);
	}

	return r;
}

static const char * const led_default_path[] = { "led", NULL };
static const char * const led_default_attributes[] = {
	"title=\"LED\"",
	"rt=Text",
	NULL };

static const char * const dummy_path[] = { "dummy", NULL };
static const char * const dummy_attributes[] = {
	"title=\"Dummy\"",
	"rt=dummy",
	NULL };

static struct srtsp_resource resources[] = {
	{ .setup = well_known_core_get,
	  .play = NULL,
	  .pause = NULL,
	  .path = SRTSP_WELL_KNOWN_CORE_PATH,
	  .user_data = NULL,
	},
	{ .setup = led_get,
	  .play = led_post,
	  .pause = led_put,
	  .path = led_default_path,
	  .user_data = &((struct srtsp_core_metadata) {
			  .attributes = led_default_attributes,
			}),
	},
	{ .setup = dummy_get,
	  .path = dummy_path,
	  .user_data = &((struct srtsp_core_metadata) {
			  .attributes = dummy_attributes,
			}),
	},
	{ },
};

static void udp_receive(struct net_context *context,
			struct net_pkt *pkt,
			int status,
			void *user_data)
{
	struct srtsp_packet request;
	struct srtsp_option options[16] = { 0 };
	u8_t opt_num = 16;
	int r;
	SYS_LOG_DBG("UDP RECEIVE CALLED");
	r = srtsp_packet_parse(&request, pkt, options, opt_num);
	if (r < 0) {
		NET_ERR("Invalid data received (%d)\n", r);
		net_pkt_unref(pkt);
		return;
	}

	r = srtsp_handle_request(&request, resources, options, opt_num);
	if (r < 0) {
		NET_ERR("No handler for such request (%d)\n", r);
	}

	net_pkt_unref(pkt);
}

static bool join_srtsp_multicast_group(void)
{
	static struct in6_addr my_addr = MY_IP6ADDR;
	static struct sockaddr_in6 mcast_addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = ALL_NODES_LOCAL_SRTSP_MCAST,
		.sin6_port = htons(MY_SRTSP_PORT) };
	struct net_if_mcast_addr *mcast;
	struct net_if_addr *ifaddr;
	struct net_if *iface;

	iface = net_if_get_default();
	if (!iface) {
		NET_ERR("Could not get default interface");
		return false;
	}

	ifaddr = net_if_ipv6_addr_add(net_if_get_default(),
				      &my_addr, NET_ADDR_MANUAL, 0);
	if (!ifaddr) {
		NET_ERR("Could not add IPv6 address to default interface");
		return false;
	}
	ifaddr->addr_state = NET_ADDR_PREFERRED;

	mcast = net_if_ipv6_maddr_add(iface, &mcast_addr.sin6_addr);
	if (!mcast) {
		NET_ERR("Could not add multicast address to interface\n");
		return false;
	}

	return true;
}

void main(void)
{
	static struct sockaddr_in6 any_addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
		.sin6_port = htons(MY_SRTSP_PORT) };
	int r;

	led0 = device_get_binding(LED_GPIO_NAME);
	/* Want it to be NULL if not available */

	if (led0) {
		gpio_pin_configure(led0, LED_PIN, GPIO_DIR_OUT);
		gpio_pin_write(led0, LED_PIN, 0);
	}

	if (!join_srtsp_multicast_group()) {
		NET_ERR("Could not join CoAP multicast group\n");
		return;
	}

	r = net_context_get(PF_INET6, SOCK_DGRAM, IPPROTO_UDP, &context);
	if (r) {
		NET_ERR("Could not get an UDP context\n");
		return;
	}

	r = net_context_bind(context, (struct sockaddr *) &any_addr,
			     sizeof(any_addr));
	if (r) {
		NET_ERR("Could not bind the context\n");
		return;
	}

	r = net_context_recv(context, udp_receive, 0, NULL);
	if (r) {
		NET_ERR("Could not receive in the context\n");
		return;
	}
}
