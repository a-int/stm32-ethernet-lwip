#include "pbuf.h"
#include "tcpRAW.h"
#include "err.h"
#include "lwip/tcp.h"

enum tcp_client_states
{
  ES_NONE = 0,
  ES_CONNECTED,
  ES_CLOSING
};

struct tcp_client_struct
{
  u8_t state;             /* current connection state */
  struct tcp_pcb *pcb;    /* pointer on the current tcp_pcb */
  struct pbuf *p;         /* pointer on the received/to be transmitted pbuf */
};


static err_t tcp_client_connected(void *arg, struct tcp_pcb *newpcb, err_t err);
static err_t tcp_client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static void tcp_client_error(void *arg, err_t err);
static err_t tcp_client_poll(void *arg, struct tcp_pcb *tpcb);
static err_t tcp_client_sent(void *arg, struct tcp_pcb *tpcb, u16_t len);
static void tcp_client_send(struct tcp_pcb *tpcb, struct tcp_client_struct *es);
static void tcp_client_connection_close(struct tcp_pcb *tpcb, struct tcp_client_struct *es);
static void tcp_client_handle (struct tcp_pcb *tpcb, struct tcp_client_struct *es);

void tcp_client_init(void)
{
	struct tcp_pcb* tpcb = tcp_new();
	ip_addr_t myIPADDR;
	IP_ADDR4(&myIPADDR, 192, 168, 1, 100);
	err_t err = tcp_connect(tpcb, &myIPADDR, 30, tcp_client_connected);
	// if (err != ERR_OK)
	// 	memp_free(MEMP_TCP_PCB, tpcb);
	// }
}

static err_t tcp_client_connected(void *arg, struct tcp_pcb *newpcb, err_t err) {
  err_t ret_err;
  struct tcp_client_struct *es = (struct tcp_client_struct *)mem_malloc(sizeof(struct tcp_client_struct));
  if (es != NULL)
  {
    es->state = ES_CONNECTED;
    es->pcb = newpcb;
    es->p = NULL;
    
    tcp_arg(newpcb, es);
    tcp_recv(newpcb, tcp_client_recv);
    tcp_err(newpcb, tcp_client_error);
    tcp_poll(newpcb, tcp_client_poll, 0);
    ret_err = ERR_OK;
  }
  else
  {
    tcp_close(newpcb);
    ret_err = ERR_MEM;
  }
  return ret_err;
}

static err_t tcp_client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
  struct tcp_client_struct *es = (struct tcp_client_struct *)arg;
  err_t ret_err;

  if (p == NULL)
  {
    es->state = ES_CLOSING;
    if(es->p == NULL) {
       tcp_client_connection_close(tpcb, es);
    } else {
      tcp_sent(tpcb, tcp_client_sent);
      tcp_client_send(tpcb, es);
    }
    ret_err = ERR_OK;
  } else if(es->state == ES_CONNECTED) {
    if(es->p == NULL) {
      es->p = p;
      tcp_client_handle(tpcb, es);
    } else {
      pbuf_chain(es->p, p);
    } 
    ret_err = ERR_OK;
  } 
  return ret_err;
}

static void tcp_client_error(void *arg, err_t err) {
  struct tcp_client_struct *es  = (struct tcp_client_struct *)arg;
  if (es != NULL) {
    mem_free(es);
  }
}

static err_t tcp_client_poll(void *arg, struct tcp_pcb *tpcb) {
  return ERR_OK;
}

static err_t tcp_client_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
  struct tcp_client_struct *es = (struct tcp_client_struct *)arg;
  if(es->p != NULL) {
    tcp_sent(tpcb, tcp_client_sent);
    tcp_client_send(tpcb, es);
  }
  return ERR_OK;
}

static void tcp_client_send(struct tcp_pcb *tpcb, struct tcp_client_struct *es) {
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

static void tcp_client_connection_close(struct tcp_pcb *tpcb, struct tcp_client_struct *es)
{
  mem_free(es);
  tcp_close(tpcb);
}

static void tcp_client_handle(struct tcp_pcb *tpcb, struct tcp_client_struct *es)
{
	char buf[es->p->len + 30];
	int len = sprintf(buf, "%s + Hello from TCP SERVER\n", (const char*)es->p->payload);
  es->p->payload = buf;
	es->p->tot_len = (es->p->tot_len - es->p->len) + len;
	es->p->len = len;
	tcp_client_send(tpcb, es);
}
