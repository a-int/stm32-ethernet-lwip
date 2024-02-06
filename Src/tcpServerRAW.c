#include "tcpRAW.h"
#include "err.h"
#include "lwip/tcp.h"

enum tcp_server_states
{
  ES_NONE = 0,
  ES_ACCEPTED,
  ES_RECEIVED,
  ES_CLOSING
};

struct tcp_server_struct
{
  u8_t state;             /* current connection state */
  struct tcp_pcb *pcb;    /* pointer on the current tcp_pcb */
  struct pbuf *p;         /* pointer on the received/to be transmitted pbuf */
};


static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err);
static err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void tcp_server_error(void *arg, err_t err);
static err_t tcp_server_poll(void *arg, struct tcp_pcb *tpcb);
static err_t tcp_server_sent(void *arg, struct tcp_pcb *tpcb, u16_t len);
static void tcp_server_send(struct tcp_pcb *tpcb, struct tcp_server_struct *es);
static void tcp_server_connection_close(struct tcp_pcb *tpcb, struct tcp_server_struct *es);

static void tcp_server_handle (struct tcp_pcb *tpcb, struct tcp_server_struct *es);

void tcp_server_init(void)
{
	struct tcp_pcb* tpcb = tcp_new();
	ip_addr_t myIPADDR;
	IP_ADDR4(&myIPADDR, 192, 168, 1, 101);
	err_t err = tcp_bind(tpcb, &myIPADDR, 10);
	if (err == ERR_OK) {
		tpcb = tcp_listen(tpcb);
		tcp_accept(tpcb, tcp_server_accept);
	} else {
		memp_free(MEMP_TCP_PCB, tpcb);
	}
}

static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
  err_t ret_err;
  struct tcp_server_struct *es;
  es = (struct tcp_server_struct *)mem_malloc(sizeof(struct tcp_server_struct));
  if (es != NULL)
  {
    es->state = ES_ACCEPTED;
    es->pcb = newpcb;
    es->p = NULL;
    tcp_arg(newpcb, es);
    tcp_recv(newpcb, tcp_server_recv);
    tcp_err(newpcb, tcp_server_error);
    tcp_poll(newpcb, tcp_server_poll, 0);
    ret_err = ERR_OK;
  }
  else
  {
    tcp_close(newpcb);
    ret_err = ERR_MEM;
  }
  return ret_err;
}

static err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
  struct tcp_server_struct *es = (struct tcp_server_struct *)arg;
  err_t ret_err;

  if (p == NULL)
  {
    es->state = ES_CLOSING;
    if(es->p == NULL) {
       tcp_server_connection_close(tpcb, es);
    } else {
      tcp_sent(tpcb, tcp_server_sent);
      tcp_server_send(tpcb, es);
    }
    ret_err = ERR_OK;
  } else if(es->state == ES_ACCEPTED) {
    es->state = ES_RECEIVED;
    es->p = p;
    tcp_sent(tpcb, tcp_server_sent);
    tcp_server_handle(tpcb, es);
    ret_err = ERR_OK;
  } else if (es->state == ES_RECEIVED) {
    if(es->p == NULL) {
      es->p = p;
      tcp_server_handle(tpcb, es);
    } 
    else {
      struct pbuf *ptr;
      ptr = es->p;
      pbuf_chain(ptr,p);
    }
    ret_err = ERR_OK;
  } 
  return ret_err;
}

static void tcp_server_error(void *arg, err_t err) {
  struct tcp_server_struct *es  = (struct tcp_server_struct *)arg;
  if (es != NULL) {
    mem_free(es);
  }
}

static err_t tcp_server_poll(void *arg, struct tcp_pcb *tpcb) {
  return ERR_OK;
}

static err_t tcp_server_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
  struct tcp_server_struct *es = (struct tcp_server_struct *)arg;
  if(es->p != NULL) {
    tcp_sent(tpcb, tcp_server_sent);
    tcp_server_send(tpcb, es);
  }
  return ERR_OK;
}

static void tcp_server_send(struct tcp_pcb *tpcb, struct tcp_server_struct *es) {
  while ((es->p != NULL) && (es->p->len <= tcp_sndbuf(tpcb))) {
    struct pbuf *ptr = es->p;
    u16_t plen = ptr->len;
    tcp_write(tpcb, ptr->payload, ptr->len, TCP_WRITE_FLAG_COPY);
    es->p = ptr->next;
    if(es->p != NULL) {
      pbuf_ref(es->p);
    }
    while(pbuf_free(ptr));
    tcp_recved(tpcb, plen);
  }
}

static void tcp_server_connection_close(struct tcp_pcb *tpcb, struct tcp_server_struct *es)
{
  mem_free(es);
  tcp_close(tpcb);
}

static void tcp_server_handle(struct tcp_pcb *tpcb, struct tcp_server_struct *es)
{
	char buf[30 + es->p->len];
	int len = sprintf(buf, "%s+ Hello from TCP SERVER\n", (char *)es->p->payload);
	es->p->payload = (void *)buf;
	es->p->tot_len = (es->p->tot_len - es->p->len) + len;
	es->p->len = len;
	tcp_server_send(tpcb, es);
}
