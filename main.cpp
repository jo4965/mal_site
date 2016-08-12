#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT */
#include <errno.h>
#include <cstring>
#include <string>
#include <iostream>
#include <fstream>

using namespace std;

#include <libnetfilter_queue/libnetfilter_queue.h>

/* returns packet id */

/**********************/
/* MY ADDITIONAL CODE */
/**********************/

string * mal_sites;  // get strings from mal_sites.txt
int num_str = 0;
#define LIMIT_MAL_SITES 100

void fetch_malsites(void) // update mal_sites with strings from mal_sites.txt
{
    char * buffer = (char *) malloc(sizeof(char) * 100);
    ifstream fin;
    fin.open("/home/dm/Desktop/bob/netfilterq/mal_site.txt");

    int str_len = 0;
    mal_sites = new string[LIMIT_MAL_SITES];
    //printf("%d", fseek(fp, SEEK_CUR, 7));
    while(fin.seekg(7, ios::cur) && fin >> mal_sites[num_str])  // with seekg, remove "http://" prefix
    {
        fin.seekg(1, ios::cur); // remove '\n' postfix

        str_len = mal_sites[num_str].length();
        if (mal_sites[num_str].at(str_len-1) == '/')
            mal_sites[num_str].at(str_len-1) = 0;

        cout << mal_sites[num_str++] <<endl;
    }

    free(buffer);
    return;
}

void create_drop_log(string * mal_site) // If an url is dropped, this function will be called.
{
    FILE * fp = fopen("/home/dm/Desktop/bob/netfilterq/dropped_log.txt", "at");
    string message;

    if(!fp)
    {
        cout <<"dropped_log.txt FILE OPEN ERROR" << endl;
        exit(-1);
    }
    message = "The dropped packet contains following url : " + *mal_site;

    cout << message << endl;
    fputs(message.c_str(), fp);
    fputs('\n', fp);
    fclose(fp);
    return;
}

/********************************/


void dump(unsigned char*buf, size_t len) {
  size_t i;

  for (i = 0; i < len; i++) {
    printf("%02x ", *buf++);
    if ((i + 1) % 16 == 0)
      printf("\n");
  }
  printf("\n");
  fflush(stdout);
}


static u_int32_t verdict_pkt (struct nfq_data *tb, int * id)
{
  struct nfqnl_msg_packet_hdr *ph;
  struct nfqnl_msg_packet_hw *hwph;
  u_int32_t mark,ifi;
  int ret;
  unsigned char *data;
  ph = nfq_get_msg_packet_hdr(tb);
  if (ph) {
    *id = ntohl(ph->packet_id);
    printf("hw_protocol=0x%04x hook=%u id=%u ",
      ntohs(ph->hw_protocol), ph->hook, *id);
  }

  hwph = nfq_get_packet_hw(tb);
  if (hwph) {
    int i, hlen = ntohs(hwph->hw_addrlen);

    printf("hw_src_addr=");
    for (i = 0; i < hlen-1; i++)
      printf("%02x:", hwph->hw_addr[i]);
    printf("%02x ", hwph->hw_addr[hlen-1]);
  }


  mark = nfq_get_nfmark(tb);
  if (mark)
    printf("mark=%u ", mark);

  ifi = nfq_get_indev(tb);
  if (ifi)
    printf("indev=%u ", ifi);

  ifi = nfq_get_outdev(tb);
  if (ifi)
    printf("outdev=%u ", ifi);
  ifi = nfq_get_physindev(tb);
  if (ifi)
    printf("physindev=%u ", ifi);

  ifi = nfq_get_physoutdev(tb);
  if (ifi)
    printf("physoutdev=%u ", ifi);

  ret = nfq_get_payload(tb, &data);

  if (ret >= 0)
    printf("payload_len=%d\n", ret);

  fputc('\n', stdout);

/* MY ADDITIONAL CODE */
  /* VERDICT PHASE
   * IF THE HTTP PAYLOAD CONTAIN MALWARE.TXT URL,
   * THE PACKET IS DROPPED.
   * OTHERWISE, THE PACKET IS ACCEPTED. */

  data[ret] = 0;
  string pkt = (char *)(data + 64);      // pkt starts from the packet near http(64)
  string finder;                        // finder
  string mal_site;
  int drop_it = false;                  // If it is true, the packet will be dropped

  dump((unsigned char *)data,ret);
  cout << (char *)data << endl;
  for(int i = 0 ; i < num_str ; i++)
  {
      mal_site = mal_sites[i];
      finder = mal_site;
      if (pkt.find(finder) != string::npos)   // drop selection
      {
          cout << "drop" << endl;
          drop_it = true;
          create_drop_log(&mal_site);
          return drop_it;
      }
  }

  drop_it = false;
  return drop_it;
 /*****************************/
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data)
{
  u_int32_t id;

  /**** MY ADDITIONAL CODE *****/
  int drop_it = verdict_pkt(nfa, (int *)&id);

  cout << "entering callback" << endl;
  if (drop_it)      // if drop_it is true drop the packet
      return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
  else
      return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

  /*****************************/
}


int main(int argc, char **argv)
{
  struct nfq_handle *h;
  struct nfq_q_handle *qh;
  struct nfnl_handle *nh;
  int fd;
  int rv;
  char buf[4096] __attribute__ ((aligned));

  printf("opening library handle\n");
  h = nfq_open();
  if (!h) {
    fprintf(stderr, "error during nfq_open()\n");
    exit(1);
  }

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    exit(1);
  }

  printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    exit(1);
  }

  printf("binding this socket to queue '0'\n");
  qh = nfq_create_queue(h,  0, &cb, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }

  printf("setting copy_packet mode\n");
  if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }

  fd = nfq_fd(h);

  /* MY ADDITIONAL CODE  */
  fetch_malsites();
  /***********************/

  for (;;) {
    if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
      printf("pkt received\n");
      //dump((unsigned char *)buf, rv);
      nfq_handle_packet(h, buf, rv);
      continue;
    }
    /* if your application is too slow to digest the packets that
     * are sent from kernel-space, the socket buffer that we use
     * to enqueue packets may fill up returning ENOBUFS. Depending
     * on your application, this error may be ignored. Please, see
     * the doxygen documentation of this library on how to improve
     * this situation.
     */
    if (rv < 0 && errno == ENOBUFS) {
      printf("losing packets!\n");
      continue;
    }
    perror("recv failed");
    break;
  }

  printf("unbinding from queue 0\n");
  nfq_destroy_queue(qh);

#ifdef INSANE
  /* normally, applications SHOULD NOT issue this command, since
   * it detaches other programs/sockets from AF_INET, too ! */
  printf("unbinding from AF_INET\n");
  nfq_unbind_pf(h, AF_INET);
#endif

  printf("closing library handle\n");
  nfq_close(h);

  exit(0);
}
