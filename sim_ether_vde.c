/* sim_ether_vde.c: VDE plug implementation for simulated ethernet
  ------------------------------------------------------------------------------
   Copyright (c) 2010, Ingo Albrecht

   Permission is hereby granted, free of charge, to any person obtaining a
   copy of this software and associated documentation files (the "Software"),
   to deal in the Software without restriction, including without limitation
   the rights to use, copy, modify, merge, publish, distribute, sublicense,
   and/or sell copies of the Software, and to permit persons to whom the
   Software is furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
   THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
   IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
   CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

   Except as contained in this notice, the name of the author shall not be
   used in advertising or otherwise to promote the sale, use or other dealings
   in this Software without prior written authorization from the author.

  ------------------------------------------------------------------------------

  ------------------------------------------------------------------------------
*/

#include <ctype.h>
#include <libvdeplug.h>

#include <unistd.h>
#include <fcntl.h>

#include "sim_ether.h"

/*============================================================================*/
/*                          Internal structures                               */
/*============================================================================*/

struct eth_vde {
  VDECONN* conn;
  char descr[256];
};

typedef struct eth_vde ETH_VDE;


/*============================================================================*/
/*                             Implementation                                 */
/*============================================================================*/

t_stat eth_vde_close(ETH_DEV* dev);
t_stat eth_vde_write(ETH_DEV* dev, ETH_PACK* packet, ETH_PCALLBACK routine);
t_stat eth_vde_read(ETH_DEV* dev, ETH_PACK* packet, ETH_PCALLBACK routine);
t_stat eth_vde_filter(ETH_DEV* dev, int addr_count, ETH_MAC* addresses,
                      ETH_BOOL all_multicast, ETH_BOOL promiscuous);

t_stat eth_vde_open(ETH_DEV* dev, char* name, DEVICE* dptr, uint32 dbit)
{
  int res;
  ETH_VDE* devi;
  struct vde_open_args voa;

  /* fill in callbacks */
  dev->cb_close  = eth_vde_close;
  dev->cb_write  = eth_vde_write;
  dev->cb_read   = eth_vde_read;
  dev->cb_filter = eth_vde_filter;

  /* allocate implementation structure */
  if(!dev->implementation) {
    dev->implementation = (ETH_VDE*)malloc(sizeof(ETH_VDE));
    memset(dev->implementation, 0, sizeof(ETH_VDE));
  }
  devi = dev->implementation;

  /* try to open vde link */
  voa.port = 0;
  voa.group = NULL;
  voa.mode = 0;
  devi->conn = vde_open(name, &devi->descr[0], &voa);
  if(!devi->conn) {
    return SCPE_OPENERR;
  }

  printf("vde link opened\n");

  /* make socket non-blocking */
  res = fcntl(vde_datafd(devi->conn), F_SETFL, O_NONBLOCK);
  if(res == -1) {
    printf("failed to set nonblock: %s\n", strerror(errno));
  }

  /* set device name */
  dev->name = strdup(name);

  return SCPE_OK;
}

t_stat eth_vde_close(ETH_DEV* dev)
{
  ETH_VDE* devi = (ETH_VDE*)dev->implementation;

  vde_close(devi->conn);

  return SCPE_OK;
}

t_stat eth_vde_write(ETH_DEV* dev, ETH_PACK* packet, ETH_PCALLBACK routine)
{
  int res;
  ETH_VDE* devi;

  if (!dev) return SCPE_UNATT;

  devi = (ETH_VDE*)dev->implementation;

  if (!devi) return SCPE_UNATT;

  if (!packet) return SCPE_ARG;

  res = vde_send(devi->conn, &packet->msg[0], packet->len, 0);
  if(res == -1) {
    if(errno == EAGAIN || errno == EWOULDBLOCK) {
      goto done;
    } else {
      printf("vde err on send: %s\n", strerror(errno));
      return SCPE_IOERR;
    }
  }
  if(res == 0) {
    printf("vde disconnected!\n");
    goto done;
  }
  if(res != packet->len) {
    printf("short write %d of %d!\n", res, packet->len);
    return SCPE_OK;
  }

  if(routine) {
    routine(0);
  }

 done:
  return SCPE_OK;
}

t_stat eth_vde_read(ETH_DEV* dev, ETH_PACK* packet, ETH_PCALLBACK routine)
{
  int res;
  ETH_VDE* devi;

  if (!dev) return SCPE_UNATT;

  devi = (ETH_VDE*)dev->implementation;

  if (!devi) return SCPE_UNATT;

  if (!packet) return SCPE_ARG;

  res = vde_recv(devi->conn, &packet->msg[0], ETH_FRAME_SIZE, 0);
  if(res == -1) {
    if(errno == EAGAIN || errno == EWOULDBLOCK) {
      goto done;
    } else {
      printf("vde err on recv: %s\n", strerror(errno));
      return SCPE_IOERR;
    }
  }
  if(res == 0) {
    printf("vde disconnected!\n");
    goto done;
  }

  packet->len = res;

  if(routine) {
    routine(0);
  }

 done:
  return SCPE_OK;
}

t_stat eth_vde_filter(ETH_DEV* dev, int addr_count, ETH_MAC* addresses,
                      ETH_BOOL all_multicast, ETH_BOOL promiscuous)
{
  return SCPE_OK;
}
