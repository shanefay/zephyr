/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if 1
#define SYS_LOG_DOMAIN "srtsp-server"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
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

#include <../include/logging/sys_log.h>
#include <kernel.h>

#include <gpio.h>


#include <net/srtsp.h>
#include <net/srtsp_link_format.h>


#define MY_SRTSP_PORT 50000
#define SOCK_SIZE 24


#define ALL_NODES_LOCAL_SRTSP_MCAST					\
	{ { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd } } }

#define MY_IP6ADDR \
	{ { { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1 } } }

#define MAX_ACTIVE_CONNECTIONS = 1;


#if defined(LED0_GPIO_PORT)
#define LED_GPIO_NAME LED0_GPIO_PORT
#define LED_PIN LED0_GPIO_PIN
#else
#define LED_GPIO_NAME "(fail)"
#define LED_PIN 0
#endif

static struct net_context *context;

static struct device *led0;

static struct srtsp_packet req;
static struct srtsp_resource rez;
static struct sockaddr_in6 dest;
static int seconds = 0;


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


static u8_t* sample_sine()
{
	if(seconds % 6 < 3){
		return 0xff;
	} else{
		return 0x00;
	}
}



void transmit_pkt(struct k_work *work)
{
	seconds++;
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct srtsp_packet response;
	u16_t id;

	int r;



 pkt = net_pkt_get_tx(context, K_FOREVER);
 if (!pkt) {
	 return;
 }

 frag = net_pkt_get_data(context, K_FOREVER);
 if (!frag) {
	 return;
 }
 net_pkt_frag_add(pkt, frag);
 id = srtsp_header_get_id(&req);

	r = srtsp_packet_init(&response, pkt, 1, SRTSP_TYPE_NON_CON,
			     0, NULL, SRTSP_RESPONSE_CODE_OK, id);
	if (r < 0) {
		return;
	}

	r = srtsp_packet_append_payload_marker(&response);
	if (r < 0) {
		net_pkt_unref(pkt);
		return ;
	}
	u8_t* value = sample_sine();
	r = srtsp_packet_append_payload(&response, (u8_t *)value,
				      sizeof(value));
	if (r < 0) {
		net_pkt_unref(pkt);
		return;
	}

	get_from_ip_addr(&req, &from);
	r = net_context_sendto(pkt, (const struct sockaddr *)&dest,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		net_pkt_unref(pkt);
	}
	u8_t * temp = (u8_t*) &value;
	k_free(temp);
}

K_WORK_DEFINE(task, transmit_pkt);

void timer_handler(struct k_timer* timer)
{
	k_work_submit(&task);
}
K_TIMER_DEFINE(timer, timer_handler, NULL);

static int play(struct srtsp_resource *resource,
		   struct srtsp_packet *request)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct srtsp_packet response;
	u8_t payload;
	u16_t id;
	u16_t offset;
	int r;

	frag = net_frag_skip(request->frag, request->offset, &offset,
			     request->hdr_len + request->opt_len);
	if (!frag && offset == 0xffff) {
		return -EINVAL;
	}

	frag = net_frag_read_u8(frag, offset, &offset, &payload);
	if (!frag && offset == 0xffff) {
		printk("packet without payload, so start streaming to them\n");

	} // check here if payload becomes relevant

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

	get_from_ip_addr(request, &from);
	r = net_context_sendto(pkt, (const struct sockaddr *)&from,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		net_pkt_unref(pkt);
	}
	rez = *resource;
	req = *request;
	memcpy(&dest, &from, sizeof(struct sockaddr_in6));


	k_timer_start(&timer, K_SECONDS(7), K_SECONDS(7));
	return r;
}

static int pause(struct srtsp_resource *resource,
		   struct srtsp_packet *request)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct srtsp_packet response;
	u16_t id;
	//u16_t offset;
	int r;
	pkt = net_pkt_get_tx(context, K_FOREVER);
	if (!pkt) {
		return -ENOMEM;
	}

	frag = net_pkt_get_data(context, K_FOREVER);
	if (!frag) {
		return -ENOMEM;
	}
	id = srtsp_header_get_id(&req);
	net_pkt_frag_add(pkt, frag);

 	r = srtsp_packet_init(&response, pkt, 1, SRTSP_TYPE_ACK,
 			     0, NULL, SRTSP_RESPONSE_CODE_OK, id);

 	if (r < 0) {
 		return -EINVAL;
 	}

 	get_from_ip_addr(&req, &from);
 	r = net_context_sendto(pkt, (const struct sockaddr *)&from,
 			       sizeof(struct sockaddr_in6),
 			       NULL, 0, NULL, NULL);

 	if (r < 0) {
 		net_pkt_unref(pkt);
 	}

	k_timer_stop(&timer);

	return r;
}

static int setup(struct srtsp_resource *resource,
		   struct srtsp_packet *request)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct srtsp_packet response;
	u16_t id;
	int r;

	pkt = net_pkt_get_tx(context, K_FOREVER);
	if (!pkt) {
		return -ENOMEM;
	}

	frag = net_pkt_get_data(context, K_FOREVER);
	if (!frag) {
		return -ENOMEM;
	}
	id = srtsp_header_get_id(request);
	printk("ID: %u\n", id);
	net_pkt_frag_add(pkt, frag);
 	r = srtsp_packet_init(&response, pkt, 1, SRTSP_TYPE_ACK,
 			     0, NULL, SRTSP_RESPONSE_CODE_OK, id);
 	if (r < 0) {
 		return -EINVAL;
 	}


 	get_from_ip_addr(request, &from);
 	r = net_context_sendto(pkt, (const struct sockaddr *)&from,
 			       sizeof(struct sockaddr_in6),
 			       NULL, 0, NULL, NULL);
 	if (r < 0) {
 		net_pkt_unref(pkt);
 	}
	req = *request;
	rez = *resource;
	return r;
}

static int teardown(struct srtsp_resource *resource,
		   struct srtsp_packet *request)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct srtsp_packet response;
	u16_t id;
	int r;

	pkt = net_pkt_get_tx(context, K_FOREVER);
	if (!pkt) {
		return -ENOMEM;
	}

	frag = net_pkt_get_data(context, K_FOREVER);
	if (!frag) {
		return -ENOMEM;
	}

	id = srtsp_header_get_id(&req);
	net_pkt_frag_add(pkt, frag);
 	r = srtsp_packet_init(&response, pkt, 1, SRTSP_TYPE_ACK,
 			     0, NULL, SRTSP_RESPONSE_CODE_OK, id);
 	if (r < 0) {
 		return -EINVAL;
 	}


 	get_from_ip_addr(&req, &from);
 	r = net_context_sendto(pkt, (const struct sockaddr *)&from,
 			       sizeof(struct sockaddr_in6),
 			       NULL, 0, NULL, NULL);

 	if (r < 0) {
 		net_pkt_unref(pkt);
 	}
	k_timer_stop(&timer);
	//k_free(&req);
	//k_free(&dest);

	return r;
}


static const char * const led_default_path[] = { "led", NULL };
static const char * const led_default_attributes[] = {
	"title=\"LED\"",
	"rt=Text",
	NULL };



//change methods here, and what they do
static struct srtsp_resource resources[] = {
	{ .setup = well_known_core_get,
	  .play = NULL,
	  .pause = NULL,
		.teardown = NULL,
	  .path = SRTSP_WELL_KNOWN_CORE_PATH,
	  .user_data = NULL,
	},
	{ .setup = setup,
	  .play = play,
	  .pause = pause,
		.teardown = teardown,
	  .path = led_default_path,
	  .user_data = &((struct srtsp_core_metadata) {
			  .attributes = led_default_attributes,
			}),
	},
};

static void udp_receive(struct net_context *context,
			struct net_pkt *pkt,
			int status,
			void *user_data)
{
	struct srtsp_packet request;
	struct srtsp_option options[16] = { 0 };
	u8_t opt_num = 16;
	int r = -1;
	//SYS_LOG_DBG("UDP RECEIVE CALLED");
	printk("udp_receive\n");

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
	/*if(active_requests + 1 < MAX_ACTIVE_CONNECTIONS) {
		requests[active_requests] = request;
		resources_in_use[active_requests] = r;
		active_requests++;
	} else {
		NET_ERR("At max active connections");
	}*/

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
	SYS_LOG_DBG("MAIN STARTED");
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
