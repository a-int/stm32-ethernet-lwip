/*
  ***************************************************************************************************************
  ***************************************************************************************************************
  ***************************************************************************************************************

  File:		  udpServerRAW.c
  Author:     ControllersTech.com
  Updated:    Jul 23, 2021

  ***************************************************************************************************************
  Copyright (C) 2017 ControllersTech.com

  This is a free software under the GNU license, you can redistribute it and/or modify it under the terms
  of the GNU General Public License version 3 as published by the Free Software Foundation.
  This software library is shared with public for educational purposes, without WARRANTY and Author is not liable for any damages caused directly
  or indirectly by this software, read more about this on the GNU General Public License.

  ***************************************************************************************************************
*/


#include "err.h"
#include "ip4_addr.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"

#include "stdio.h"
#include "udpRAW.h"

void udp_receive_callback(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);

void udpServer_init(void){
	struct udp_pcb* pcb = udp_new();

	ip4_addr_t ip;
	IP_ADDR4(&ip, 192, 168, 1, 101);

	err_t err = udp_bind(pcb, &ip, 7); // bind the IP and port for PCB
	if(err == ERR_OK){
		udp_recv(pcb, udp_receive_callback, NULL); // assign callback function if received data
	} else {
		udp_remove(pcb);
	}
}

void udp_receive_callback(void *arg, struct udp_pcb *upcb, struct pbuf *p, const ip_addr_t *addr, u16_t port){
	struct pbuf* txbuffer;
	char* buffer[100];
	u32_t len = sprintf(buffer, "TEST OF UDP %s", (char*)p->payload);
	txbuffer = pbuf_alloc(PBUF_TRANSPORT, len, PBUF_RAM); // allocate the neccessary memory block
	pbuf_take(txbuffer, buffer, len); // copy the data to allocated memory

	udp_connect(upcb, addr, port);
	udp_send(upcb, txbuffer);
	udp_disconnect(upcb);
	
	pbuf_free(txbuffer); // free the allocated buffer
	pbuf_free(p); // free the received data buffer
}
