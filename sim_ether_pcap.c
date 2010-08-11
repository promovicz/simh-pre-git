/* sim_ether.c: OS-dependent network routines
  ------------------------------------------------------------------------------
   Copyright (c) 2002-2007, David T. Hittner

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

  Supported/Tested Platforms:

  Windows(NT,2K,XP,2K3)     WinPcap         V3.0+
  Linux                     libpcap at least 0.9
  OpenBSD,FreeBSD,NetBSD    libpcap at least 0.9
  MAC OS/X                  libpcap at least 0.9
  Solaris Sparc             libpcap at least 0.9
  Solaris Intel             libpcap at least 0.9
  AIX                       ??
  HP/UX                     ??
  Compaq Tru64 Unix         ??
  VMS                       Alpha/Itanium VMS only, needs VMS libpcap
  
  WinPcap is available from: 
                        http://winpcap.polito.it/
  libpcap for VMS is available from: 
                        http://simh.trailing-edge.com/sources/vms-pcap.zip
  libpcap for other Unix platforms is available at: 
        Current Version:  http://www.tcpdump.org/daily/libpcap-current.tar.gz
        Released Version: http://www.tcpdump.org/release/
        Note: You can only use the released version if it is at least 
              version 0.9

        
        We've gotten the tarball, unpacked, built and installed it with:
            gzip -dc libpcap-current.tar.gz | tar xvf -
            cd libpcap-directory-name
            ./configure
            make
            make install
        Note:  The "make install" step generally will have to be done as root.
        This will install libpcap in /usr/local/lib and /usr/local/include
        It is then important to make sure that you get the just installed 
        libpcap components referenced during your build.  This is generally 
        achieved by invoking gcc with: 
             -isystem /usr/local/include -L /usr/local/lib


  Note: Building for the platforms indicated above, with the indicated libpcap, 
  should automatically leverage the appropriate mechanisms contained here.  
  Things are structured so that it is likely to work for any other as yet 
  untested platform.  If it works for you, please let the author know so we 
  can update the table above.  If it doesn't work, then the following #define 
  variables can influence the operation on an untested platform.

  USE_BPF           - Determines if this code leverages a libpcap/WinPcap 
                      provided bpf packet filtering facility.  All tested 
                      environments have bpf facilities that work the way we 
                      need them to.  However a new one might not.  undefine 
                      this variable to let this code do its own filtering.
  USE_SETNONBLOCK   - Specifies whether the libpcap environment's non-blocking 
                      semantics are to be leveraged.  This helps to manage the 
                      varying behaviours of the kernel packet facilities 
                      leveraged by libpcap.
  USE_READER_THREAD - Specifies that packet reading should be done in the 
                      context of a separate thread.  The Posix threading 
                      APIs are used.  This option is less efficient than the
                      default non-threaded approach, but it exists since some 
                      platforms don't want to work with nonblocking libpcap 
                      semantics.   OpenBSD and NetBSD either don't have pthread 
                      APIs available, or they are too buggy to be useful. 
                      Using the threaded approach may require special compile 
                      and/or link time switches (i.e. -lpthread or -pthread, 
                      etc.) Consult the documentation for your platform as 
                      needed.
  MUST_DO_SELECT    - Specifies that when USE_READER_THREAD is active, that 
                      select() should be used to determin when available 
                      packets are ready for reading.  Otherwise, we depend 
                      on the libpcap/kernel packet timeout specified on 
                      pcap_open_live.  If USE_READER_THREAD is not set, then 
                      MUST_DO_SELECT is irrelevant

  NEED_PCAP_SENDPACKET
                    - Specifies that you are using an older version of libpcap
                      which doesn't provide a pcap_sendpacket API.

  NOTE: Changing these defines is done in either sim_ether.h OR on the global 
        compiler command line which builds all of the modules included in a
        simulator.

  ------------------------------------------------------------------------------
*/

#include <ctype.h>
#include "sim_ether.h"
#include "sim_sock.h"

extern FILE *sim_log;

/* make common BSD code a bit easier to read in this file */
/* OS/X seems to define and compile using one of these BSD types */
#if defined(__NetBSD__) || defined (__OpenBSD__) || defined (__FreeBSD__)
#define xBSD 1
#endif
#if !defined(__FreeBSD__) && !defined(_WIN32) && !defined(VMS)
#define USE_SETNONBLOCK 1
#endif

#if defined(__sun__) && defined(__i386__)
#define USE_READER_THREAD 1
#endif

/* make common winpcap code a bit easier to read in this file */
#if defined(_WIN32) || defined(VMS)
#define PCAP_READ_TIMEOUT -1
#else
#define PCAP_READ_TIMEOUT  1
#endif

/* set related values to have correct relationships */
#if defined (USE_READER_THREAD)
#if defined (USE_SETNONBLOCK)
#undef USE_SETNONBLOCK
#endif
#undef PCAP_READ_TIMEOUT
#define PCAP_READ_TIMEOUT 15
#if !defined (xBSD) && !defined(_WIN32) && !defined(VMS)
#define MUST_DO_SELECT
#endif
#endif

/*
  USE_BPF is defined to let this code leverage the libpcap/OS kernel provided 
  BPF packet filtering.  This generally will enhance performance.  It may not 
  be available in some environments and/or it may not work correctly, so 
  undefining this will still provide working code here.
*/
#define USE_BPF 1

#if defined (USE_READER_THREAD)
#include <pthread.h>
#endif

/*============================================================================*/
/*      WIN32, Linux, and xBSD routines use WinPcap and libpcap packages      */
/*        OpenVMS Alpha uses a WinPcap port and an associated execlet         */
/*============================================================================*/

#if defined (xBSD) && !defined(__APPLE__)
#include <sys/ioctl.h>
#include <net/bpf.h>
#endif /* xBSD */

#include <pcap.h>
#include <string.h>

/* Allows windows to look up user-defined adapter names */
#if defined(_WIN32)
#include <winreg.h>
#endif

/*============================================================================*/
/*                          Windows pcap loading                              */
/*============================================================================*/

#if defined(_WIN32) && defined(USE_SHARED)
/* Dynamic DLL loading technique and modified source comes from
   Etherial/WireShark capture_pcap.c */

/* Dynamic DLL load variables */
static HINSTANCE hDll = 0;          /* handle to DLL */
static int dll_loaded = 0;          /* 0=not loaded, 1=loaded, 2=DLL load failed, 3=Func load failed */
static char* no_wpcap = "wpcap load failure";

/* define pointers to pcap functions needed */
static void    (*p_pcap_close) (pcap_t *);
static int     (*p_pcap_compile) (pcap_t *, struct bpf_program *, char *, int, bpf_u_int32);
static int     (*p_pcap_datalink) (pcap_t *);
static int     (*p_pcap_dispatch) (pcap_t *, int, pcap_handler, u_char *);
static int     (*p_pcap_findalldevs) (pcap_if_t **, char *);
static void    (*p_pcap_freealldevs) (pcap_if_t *);
static void    (*p_pcap_freecode) (struct bpf_program *);
static char*   (*p_pcap_geterr) (pcap_t *);
static int     (*p_pcap_lookupnet) (const char *, bpf_u_int32 *, bpf_u_int32 *, char *);
static pcap_t* (*p_pcap_open_live) (const char *, int, int, int, char *);
static int     (*p_pcap_sendpacket) (pcap_t* handle, const u_char* msg, int len);
static int     (*p_pcap_setfilter) (pcap_t *, struct bpf_program *);
static char*   (*p_pcap_lib_version) (void);

/* load function pointer from DLL */
void load_function(char* function, void** func_ptr) {
    *func_ptr = GetProcAddress(hDll, function);
    if (*func_ptr == 0) {
        char* msg = "Eth: Failed to find function '%s' in wpcap.dll\r\n";
        printf (msg, function);
            if (sim_log) fprintf (sim_log, msg, function);
        dll_loaded = 3;
    }
}

/* load wpcap.dll as required */
int load_wpcap(void) {
    switch(dll_loaded) {
        case 0:                                 /* not loaded */
            /* attempt to load DLL */
            hDll = LoadLibrary(TEXT("wpcap.dll"));
            if (hDll == 0) {
                /* failed to load DLL */
                char* msg  = "Eth: Failed to load wpcap.dll\r\n";
                char* msg2 = "Eth: You must install WinPcap 4.x to use networking\r\n";
                printf (msg);
                printf (msg2);
                if (sim_log) {
                    fprintf (sim_log, msg);
                    fprintf (sim_log, msg2);
                }
                dll_loaded = 2;
                break;
            } else {
                /* DLL loaded OK */
                dll_loaded = 1;
            }

            /* load required functions; sets dll_load=3 on error */
            load_function("pcap_close",            (void**) &p_pcap_close);
            load_function("pcap_compile",        (void**) &p_pcap_compile);
            load_function("pcap_datalink",        (void**) &p_pcap_datalink);
            load_function("pcap_dispatch",        (void**) &p_pcap_dispatch);
            load_function("pcap_findalldevs",    (void**) &p_pcap_findalldevs);
            load_function("pcap_freealldevs",    (void**) &p_pcap_freealldevs);
            load_function("pcap_freecode",        (void**) &p_pcap_freecode);
            load_function("pcap_geterr",        (void**) &p_pcap_geterr);
            load_function("pcap_lookupnet",        (void**) &p_pcap_lookupnet);
            load_function("pcap_open_live",        (void**) &p_pcap_open_live);
            load_function("pcap_sendpacket",    (void**) &p_pcap_sendpacket);
            load_function("pcap_setfilter",        (void**) &p_pcap_setfilter);
            load_function("pcap_lib_version",   (void**) &p_pcap_lib_version);

            if (dll_loaded == 1) {
                /* log successful load */
                char* version = p_pcap_lib_version();
                printf("%s\n", version);
                if (sim_log)
                    fprintf(sim_log, "%s\n", version);
            }
            break;
        default:                                /* loaded or failed */
            break;
    }
    return (dll_loaded == 1) ? 1 : 0;
}

/* define functions with dynamic revectoring */
void pcap_close(pcap_t* a) {
    if (load_wpcap() != 0) {
        p_pcap_close(a);
    }
}

int pcap_compile(pcap_t* a, struct bpf_program* b, char* c, int d, bpf_u_int32 e) {
    if (load_wpcap() != 0) {
        return p_pcap_compile(a, b, c, d, e);
    } else {
        return 0;
    }
}

int pcap_datalink(pcap_t* a) {
    if (load_wpcap() != 0) {
        return p_pcap_datalink(a);
    } else {
        return 0;
    }
}

int pcap_dispatch(pcap_t* a, int b, pcap_handler c, u_char* d) {
    if (load_wpcap() != 0) {
        return p_pcap_dispatch(a, b, c, d);
    } else {
        return 0;
    }
}

int pcap_findalldevs(pcap_if_t** a, char* b) {
    if (load_wpcap() != 0) {
        return p_pcap_findalldevs(a, b);
    } else {
        *a = 0;
        strcpy(b, no_wpcap);
        return -1;
    }
}

void pcap_freealldevs(pcap_if_t* a) {
    if (load_wpcap() != 0) {
        p_pcap_freealldevs(a);
    }
}

void pcap_freecode(struct bpf_program* a) {
    if (load_wpcap() != 0) {
        p_pcap_freecode(a);
    }
}

char* pcap_geterr(pcap_t* a) {
    if (load_wpcap() != 0) {
        return p_pcap_geterr(a);
    } else {
        return (char*) 0;
    }
}

int pcap_lookupnet(const char* a, bpf_u_int32* b, bpf_u_int32* c, char* d) {
    if (load_wpcap() != 0) {
        return p_pcap_lookupnet(a, b, c, d);
    } else {
        return 0;
    }
}

pcap_t* pcap_open_live(const char* a, int b, int c, int d, char* e) {
    if (load_wpcap() != 0) {
        return p_pcap_open_live(a, b, c, d, e);
    } else {
        return (pcap_t*) 0;
    }
}

int pcap_sendpacket(pcap_t* a, const u_char* b, int c) {
    if (load_wpcap() != 0) {
        return p_pcap_sendpacket(a, b, c);
    } else {
        return 0;
    }
}

int pcap_setfilter(pcap_t* a, struct bpf_program* b) {
    if (load_wpcap() != 0) {
        return p_pcap_setfilter(a, b);
    } else {
        return 0;
    }
}
#endif

/*============================================================================*/
/*                      Deal with sendpacket presence                         */
/*============================================================================*/

/* Some platforms have always had pcap_sendpacket */
#if defined(_WIN32) || defined(VMS)
#define HAS_PCAP_SENDPACKET 1
#else
/* The latest libpcap and WinPcap all have pcap_sendpacket */
#if !defined (NEED_PCAP_SENDPACKET)
#define HAS_PCAP_SENDPACKET 1
#endif
#endif

#if !defined (HAS_PCAP_SENDPACKET)
/* libpcap has no function to write a packet, so we need to implement
   pcap_sendpacket() for compatibility with the WinPcap base code.
   Return value: 0=Success, -1=Failure */
int pcap_sendpacket(pcap_t* handle, const u_char* msg, int len)
{
#if defined (__linux)
  return (send(pcap_fileno(handle), msg, len, 0) == len)? 0 : -1;
#else
  return (write(pcap_fileno(handle), msg, len) == len)? 0 : -1;
#endif /* linux */
}
#endif /* !HAS_PCAP_SENDPACKET */

/*============================================================================*/
/*                          Internal structures                               */
/*============================================================================*/

struct eth_pcap {
    pcap_t *pcap;
#if defined (USE_READER_THREAD)
  ETH_QUE       read_queue;
  pthread_mutex_t     lock;
  pthread_t     reader_thread;                          /* Reader Thread Id */
#endif
};

typedef struct eth_pcap ETH_PCAP;

/*============================================================================*/
/*                             Reader thread                                  */
/*============================================================================*/

#if defined (USE_READER_THREAD)
#include <pthread.h>

void eth_callback(u_char* info, const struct pcap_pkthdr* header, const u_char* data);

static void *
_eth_reader(void *arg)
{
ETH_DEV* volatile dev = (ETH_DEV*)arg;
ETH_PCAP* volatile devi = (ETH_PCAP*)dev->implementation;
int status;
struct timeval timeout;

  timeout.tv_sec = 0;
  timeout.tv_usec = 200*1000;

  sim_debug(dev->dbit, dev->dptr, "Reader Thread Starting\n");

  while (devi->pcap) {
#if defined (MUST_DO_SELECT)
    int sel_ret;

    fd_set setl;
    FD_ZERO(&setl);
    FD_SET(pcap_get_selectable_fd((pcap_t *)devi->pcap), &setl);
    sel_ret = select(1+pcap_get_selectable_fd((pcap_t *)devi->pcap), &setl, NULL, NULL, &timeout);
    if (sel_ret < 0 && errno != EINTR) break;
    if (sel_ret > 0) {
      /* dispatch read request queue available packets */
      status = pcap_dispatch((pcap_t*)devi->pcap, -1, &eth_callback, (u_char*)dev);
    }
#else
    /* dispatch read request queue available packets */
    status = pcap_dispatch((pcap_t*)devi->pcap, 1, &eth_callback, (u_char*)dev);
#endif
  }

  sim_debug(dev->dbit, dev->dptr, "Reader Thread Exiting\n");
  return NULL;
}
#endif

/*============================================================================*/
/*                        Device listing and finding                          */
/*============================================================================*/

/*
     The libpcap provided API pcap_findalldevs() on most platforms, will 
     leverage the getifaddrs() API if it is available in preference to 
     alternate platform specific methods of determining the interface list.

     A limitation of getifaddrs() is that it returns only interfaces which
     have associated addresses.  This may not include all of the interesting
     interfaces that we are interested in since a host may have dedicated
     interfaces for a simulator, which is otherwise unused by the host.

     One could hand craft the the build of libpcap to specifically use 
     alternate methods to implement pcap_findalldevs().  However, this can 
     get tricky, and would then result in a sort of deviant libpcap.

     This routine exists to allow platform specific code to validate and/or 
     extend the set of available interfaces to include any that are not
     returned by pcap_findalldevs.

*/
int eth_host_devices(int used, int max, ETH_LIST* list)
{
  pcap_t* conn;
  int i, j, datalink;
  char errbuf[PCAP_ERRBUF_SIZE];

  for (i=0; i<used; ++i) {
    /* Cull any non-ethernet interface types */
    conn = pcap_open_live(list[i].name, ETH_MAX_PACKET, ETH_PROMISC, PCAP_READ_TIMEOUT, errbuf);
    if (NULL != conn) datalink = pcap_datalink(conn), pcap_close(conn);
    if ((NULL == conn) || (datalink != DLT_EN10MB)) {
      for (j=i; j<used-1; ++j)
        list[j] = list[j+1];
      --used;
      --i;
    }
  } /* for */

#if defined(_WIN32)
  /* replace device description with user-defined adapter name (if defined) */
  for (i=0; i<used; i++) {
        char regkey[2048];
    char regval[2048];
        LONG status;
    DWORD reglen, regtype;
    HKEY reghnd;

        /* These registry keys don't seem to exist for all devices, so we simply ignore errors. */
        /* Windows XP x64 registry uses wide characters by default,
            so we force use of narrow characters by using the 'A'(ANSI) version of RegOpenKeyEx.
            This could cause some problems later, if this code is internationalized. Ideally,
            the pcap lookup will return wide characters, and we should use them to build a wide
            registry key, rather than hardcoding the string as we do here. */
        if(list[i].name[strlen( "\\Device\\NPF_" )] == '{') {
              sprintf( regkey, "SYSTEM\\CurrentControlSet\\Control\\Network\\"
                            "{4D36E972-E325-11CE-BFC1-08002BE10318}\\%hs\\Connection", list[i].name+
                            strlen( "\\Device\\NPF_" ) );
              if((status = RegOpenKeyExA (HKEY_LOCAL_MACHINE, regkey, 0, KEY_QUERY_VALUE, &reghnd)) != ERROR_SUCCESS) {
                  continue;
              }
        reglen = sizeof(regval);

      /* look for user-defined adapter name, bail if not found */    
        /* same comment about Windows XP x64 (above) using RegQueryValueEx */
      if((status = RegQueryValueExA (reghnd, "Name", NULL, &regtype, regval, &reglen)) != ERROR_SUCCESS) {
              RegCloseKey (reghnd);
            continue;
        }
      /* make sure value is the right type, bail if not acceptable */
        if((regtype != REG_SZ) || (reglen > sizeof(regval))) {
            RegCloseKey (reghnd);
            continue;
        }
      /* registry value seems OK, finish up and replace description */
        RegCloseKey (reghnd );
      sprintf (list[i].desc, "%s", regval);
    }
  } /* for */
#endif

    return used;
}

int eth_devices(int max, ETH_LIST* list)
{
  pcap_if_t* alldevs;
  pcap_if_t* dev;
  int i = 0;
  char errbuf[PCAP_ERRBUF_SIZE];

#ifndef DONT_USE_PCAP_FINDALLDEVS
  /* retrieve the device list */
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    char* msg = "Eth: error in pcap_findalldevs: %s\r\n";
    printf (msg, errbuf);
    if (sim_log) fprintf (sim_log, msg, errbuf);
  } else {
    /* copy device list into the passed structure */
    for (i=0, dev=alldevs; dev; dev=dev->next) {
      if ((dev->flags & PCAP_IF_LOOPBACK) || (!strcmp("any", dev->name))) continue;
      list[i].num = i;
      sprintf(list[i].name, "%s", dev->name);
      if (dev->description)
        sprintf(list[i].desc, "%s", dev->description);
      else
        sprintf(list[i].desc, "%s", "No description available");
      if (i++ >= max) break;
    }

    /* free device list */
    pcap_freealldevs(alldevs);
  }
#endif

  /* Add any host specific devices and/or validate those already found */
  i = eth_host_devices(i, max, list);

  /* return device count */
  return i;
}

char* eth_getname(int number, char* name)
{
  ETH_LIST  list[ETH_MAX_DEVICE];
  int count = eth_devices(ETH_MAX_DEVICE, list);

  if (count <= number) return 0;
  strcpy(name, list[number].name);
  return name;
}

char* eth_getname_bydesc(char* desc, char* name)
{
  ETH_LIST  list[ETH_MAX_DEVICE];
  int count = eth_devices(ETH_MAX_DEVICE, list);
  int i;
  int j=strlen(desc);

  for (i=0; i<count; i++) {
    int found = 1;
    int k = strlen(list[i].desc);

    if (j != k) continue;
    for (k=0; k<j; k++)
      if (tolower(list[i].desc[k]) != tolower(desc[k]))
        found = 0;
    if (found == 0) continue;

    /* found a case-insensitive description match */
    strcpy(name, list[i].name);
    return name;
  }
  /* not found */
  return 0;
}

/* strncasecmp() is not available on all platforms */
int eth_strncasecmp(char* string1, char* string2, int len)
{
  int i;
  unsigned char s1, s2;

  for (i=0; i<len; i++) {
    s1 = string1[i];
    s2 = string2[i];
    if (islower (s1)) s1 = toupper (s1);
    if (islower (s2)) s2 = toupper (s2);

    if (s1 < s2)
      return -1;
    if (s1 > s2)
      return 1;
    if (s1 == 0) return 0;
  }
  return 0;
}

char* eth_getname_byname(char* name, char* temp)
{
  ETH_LIST  list[ETH_MAX_DEVICE];
  int count = eth_devices(ETH_MAX_DEVICE, list);
  int i, n, found;

  found = 0;
  n = strlen(name);
  for (i=0; i<count && !found; i++) {
    if (eth_strncasecmp(name, list[i].name, n) == 0) {
      found = 1;
      strcpy(temp, list[i].name); /* only case might be different */
    }
  }
  if (found) {
    return temp;
  } else {
    return 0;
  }
}

/*============================================================================*/
/*                             Implementation                                 */
/*============================================================================*/

t_stat eth_pcap_close(ETH_DEV* dev);
t_stat eth_pcap_write(ETH_DEV* dev, ETH_PACK* packet, ETH_PCALLBACK routine);
t_stat eth_pcap_read(ETH_DEV* dev, ETH_PACK* packet, ETH_PCALLBACK routine);
t_stat eth_pcap_filter(ETH_DEV* dev, int addr_count, ETH_MAC* addresses,
                       ETH_BOOL all_multicast, ETH_BOOL promiscuous);

t_stat eth_pcap_open(ETH_DEV* dev, char* name, DEVICE* dptr, uint32 dbit)
{
    dbit = 1;

  ETH_PCAP* devi;
  const int bufsz = (BUFSIZ < ETH_MAX_PACKET) ? ETH_MAX_PACKET : BUFSIZ;
  char errbuf[PCAP_ERRBUF_SIZE];
  char temp[1024];
  char* savname = name;
  int   num;
  char* msg;

  /* fill in callbacks */
  dev->cb_close = &eth_pcap_close;
  dev->cb_write = &eth_pcap_write;
  dev->cb_read = &eth_pcap_read;
  dev->cb_filter = &eth_pcap_filter;

  /* allocate implementation structure */
  devi = (ETH_PCAP*)malloc(sizeof(ETH_PCAP));
  dev->implementation = devi;
  memset(devi, 0, sizeof(ETH_PCAP));

  /* translate name of type "ethX" to real device name */
  if ((strlen(name) == 4)
      && (tolower(name[0]) == 'e')
      && (tolower(name[1]) == 't')
      && (tolower(name[2]) == 'h')
      && isdigit(name[3])
     ) {
    num = atoi(&name[3]);
    savname = eth_getname(num, temp);
    if (savname == 0) /* didn't translate */
      return SCPE_OPENERR;
  } else {
    /* are they trying to use device description? */
    savname = eth_getname_bydesc(name, temp);
    if (savname == 0) { /* didn't translate */
      /* probably is not ethX and has no description */
      savname = eth_getname_byname(name, temp);
      if (savname == 0) /* didn't translate */
        return SCPE_OPENERR;
    }
  }

  /* attempt to connect device */
  memset(errbuf, 0, sizeof(errbuf));
  devi->pcap = (void*) pcap_open_live(savname, bufsz, ETH_PROMISC, PCAP_READ_TIMEOUT, errbuf);
  if (!devi->pcap) { /* can't open device */
    msg = "Eth: pcap_open_live error - %s\r\n";
    printf (msg, errbuf);
    if (sim_log) fprintf (sim_log, msg, errbuf);
    return SCPE_OPENERR;
  } else {
    msg = "Eth: opened %s\r\n";
    printf (msg, savname);
    if (sim_log) fprintf (sim_log, msg, savname);
  }

  /* save name of device */
  dev->name = malloc(strlen(savname)+1);
  strcpy(dev->name, savname);

  /* save debugging information */
  dev->dptr = dptr;
  dev->dbit = dbit;

#if !defined(HAS_PCAP_SENDPACKET) && defined (xBSD) && !defined (__APPLE__)
  /* Tell the kernel that the header is fully-formed when it gets it.
     This is required in order to fake the src address. */
  {
    int one = 1;
    ioctl(pcap_fileno(devi->pcap), BIOCSHDRCMPLT, &one);
  }
#endif /* xBSD */

#if defined (USE_READER_THREAD)
  {
  pthread_attr_t attr;

  ethq_init (&devi->read_queue, 200);         /* initialize FIFO queue */
  pthread_mutex_init (&devi->lock, NULL);
  pthread_attr_init(&attr);
  pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
  pthread_create (&devi->reader_thread, &attr, _eth_reader, (void *)dev);
  pthread_attr_destroy(&attr);
  }
#else /* !defined (USE_READER_THREAD */
#ifdef USE_SETNONBLOCK
  /* set ethernet device non-blocking so pcap_dispatch() doesn't hang */
  if (pcap_setnonblock (devi->pcap, 1, errbuf) == -1) {
    msg = "Eth: Failed to set non-blocking: %s\r\n";
    printf (msg, errbuf);
    if (sim_log) fprintf (sim_log, msg, errbuf);
  }
#endif
#endif /* !defined (USE_READER_THREAD */
  return SCPE_OK;
}

t_stat eth_pcap_close(ETH_DEV* dev)
{
  ETH_PCAP* devi;
  char* msg = "Eth: closed %s\r\n";
  pcap_t *pcap;

  /* make sure device exists */
  if (!dev) return SCPE_UNATT;

  /* get implementation structure */
  devi = (ETH_PCAP*)dev->implementation;

  /* close the device */
  pcap = (pcap_t *)devi->pcap;
  devi->pcap = NULL;
  pcap_close(pcap);
  printf (msg, dev->name);
  if (sim_log) fprintf (sim_log, msg, dev->name);

#if defined (USE_READER_THREAD)
  pthread_join (devi->reader_thread, NULL);
#endif

  return SCPE_OK;
}

t_stat eth_reflect(ETH_DEV* dev, ETH_MAC mac)
{
  ETH_PACK send, recv;
  t_stat status;
  int i;
  struct timeval delay;

  /* build a packet */
  memset (&send, 0, sizeof(ETH_PACK));
  send.len = ETH_MIN_PACKET;                              /* minimum packet size */
  memcpy(&send.msg[0], mac, sizeof(ETH_MAC));             /* target address */
  memcpy(&send.msg[6], mac, sizeof(ETH_MAC));             /* source address */
  send.msg[12] = 0x90;                                    /* loopback packet type */
  for (i=14; i<send.len; i++)
    send.msg[i] = 32 + i;                                 /* gibberish */

  dev->reflections = 0;
  eth_filter(dev, 1, (ETH_MAC *)mac, 0, 0);

  /* send the packet */
  status = eth_write (dev, &send, NULL);
  if (status != SCPE_OK) {
    char *msg;
    msg = "Eth: Error Transmitting packet: %s\r\n"
          "You may need to run as root, or install a libpcap version\r\n"
          "which is at least 0.9 from www.tcpdump.org\r\n";
    printf(msg, strerror(errno));
    if (sim_log) fprintf (sim_log, msg, strerror(errno));
    return status;
  }

  /* if/when we have a sim_os_msleep() we'll use it here instead of this select() */
  delay.tv_sec = 0;
  delay.tv_usec = 50*1000;
  select(0, NULL, NULL, NULL, &delay); /* make sure things settle into the read path */

  /* empty the read queue and count the reflections */
  do {
    memset (&recv, 0, sizeof(ETH_PACK));
    status = eth_pcap_read (dev, &recv, NULL);
    if (memcmp(send.msg, recv.msg, ETH_MIN_PACKET)== 0)
      dev->reflections++;
  } while (recv.len > 0);

  sim_debug(dev->dbit, dev->dptr, "Reflections = %d\n", dev->reflections);
  return dev->reflections;
}

t_stat eth_pcap_write(ETH_DEV* dev, ETH_PACK* packet, ETH_PCALLBACK routine)
{
  ETH_PCAP* devi;
  int status = 1;   /* default to failure */

  /* make sure device exists */
  if (!dev) return SCPE_UNATT;

  /* get implementation structure */
  devi = (ETH_PCAP*)dev->implementation;

  /* make sure packet exists */
  if (!packet) return SCPE_ARG;

  /* make sure packet is acceptable length */
  if ((packet->len >= ETH_MIN_PACKET) && (packet->len <= ETH_MAX_PACKET)) {
    eth_packet_trace (dev, packet->msg, packet->len, "writing");

    /* dispatch write request (synchronous; no need to save write info to dev) */
    status = pcap_sendpacket((pcap_t*)devi->pcap, (u_char*)packet->msg, packet->len);

    /* detect sending of decnet loopback packet */
    if ((status == 0) && DECNET_SELF_FRAME(dev->decnet_addr, packet->msg)) 
      dev->decnet_self_sent += dev->reflections;

  } /* if packet->len */

  /* call optional write callback function */
  if (routine)
    (routine)(status);

  return ((status == 0) ? SCPE_OK : SCPE_IOERR);
}

void eth_callback(u_char* info, const struct pcap_pkthdr* header, const u_char* data)
{
  ETH_DEV*  dev = (ETH_DEV*) info;
  ETH_PCAP* devi = (ETH_PCAP*)dev->implementation;
#ifdef USE_BPF
  int to_me = 1;
#else /* !USE_BPF */
  int to_me = 0;
  int from_me = 0;
  int i;

#ifdef ETH_DEBUG
//  eth_packet_trace (dev, data, header->len, "received");
#endif
  for (i = 0; i < dev->addr_count; i++) {
    if (memcmp(data, dev->filter_address[i], 6) == 0) to_me = 1;
    if (memcmp(&data[6], dev->filter_address[i], 6) == 0) from_me = 1;
  }

  /* all multicast mode? */
  if (dev->all_multicast && (data[0] & 0x01)) to_me = 1;

  /* promiscuous mode? */
  if (dev->promiscuous) to_me = 1;
#endif /* USE_BPF */

  /* detect sending of decnet loopback packet */
  if (DECNET_SELF_FRAME(dev->decnet_addr, data)) {
    /* lower reflection count - if already zero, pass it on */
    if (dev->decnet_self_sent > 0) {
      dev->decnet_self_sent--;
      to_me = 0;
    } 
#ifndef USE_BPF
    else
      from_me = 0;
#endif
  }

#ifdef USE_BPF
  if (to_me) {
#else /* !USE_BPF */
  if (to_me && !from_me) {
#endif
#if defined (USE_READER_THREAD)
    ETH_PACK tmp_packet;

    /* set data in passed read packet */
    tmp_packet.len = header->len;
    memcpy(tmp_packet.msg, data, header->len);
    if (dev->need_crc)
      eth_add_crc32(&tmp_packet);

    eth_packet_trace (dev, tmp_packet.msg, tmp_packet.len, "rcvqd");

    pthread_mutex_lock (&devi->lock);
    ethq_insert(&devi->read_queue, 2, &tmp_packet, 0);
    pthread_mutex_unlock (&devi->lock);
#else
    /* set data in passed read packet */
    dev->read_packet->len = header->len;
    memcpy(dev->read_packet->msg, data, header->len);
    if (dev->need_crc)
      eth_add_crc32(dev->read_packet);

    eth_packet_trace (dev, dev->read_packet->msg, dev->read_packet->len, "reading");

    /* call optional read callback function */
    if (dev->read_callback)
      (dev->read_callback)(0);
#endif
  }
}

t_stat eth_pcap_read(ETH_DEV* dev, ETH_PACK* packet, ETH_PCALLBACK routine)
{
  int status;
  ETH_PCAP* devi;

  /* make sure device exists */

  if (!dev) return SCPE_UNATT;

  /* get implementation structure */
  devi = (ETH_PCAP*)dev->implementation;

  /* make sure packet exists */
  if (!packet) return SCPE_ARG;

#if !defined (USE_READER_THREAD)
  /* set read packet */
  dev->read_packet = packet;
  packet->len = 0;

  /* set optional callback routine */
  dev->read_callback = routine;

  /* dispatch read request to either receive a filtered packet or timeout */
  do {
    status = pcap_dispatch((pcap_t*)devi->pcap, 1, &eth_callback, (u_char*)dev);
  } while ((status) && (0 == packet->len));

#else /* USE_READER_THREAD */

    status = 0;
    pthread_mutex_lock (&devi->lock);
    if (devi->read_queue.count > 0) {
      ETH_ITEM* item = &devi->read_queue.item[devi->read_queue.head];
      packet->len = item->packet.len;
      memcpy(packet->msg, item->packet.msg, packet->len);
      if (routine)
          routine(status);
      ethq_remove(&devi->read_queue);
    }
    pthread_mutex_unlock (&devi->lock);  
#endif

  return SCPE_OK;
}

t_stat eth_pcap_filter(ETH_DEV* dev, int addr_count, ETH_MAC* addresses,
                  ETH_BOOL all_multicast, ETH_BOOL promiscuous)
{
  ETH_PCAP* devi;
  int i;
  bpf_u_int32  bpf_subnet, bpf_netmask;
  char buf[110+66*ETH_FILTER_MAX];
  char errbuf[PCAP_ERRBUF_SIZE];
  char mac[20];
  char* buf2;
  t_stat status;
#ifdef USE_BPF
  struct bpf_program bpf;
  char* msg;
#endif

  /* make sure device exists */
  if (!dev) return SCPE_UNATT;

  /* get implementation structure */
  devi = (ETH_PCAP*)dev->implementation;

  /* filter count OK? */
  if ((addr_count < 0) || (addr_count > ETH_FILTER_MAX))
    return SCPE_ARG;
  else
    if (!addresses) return SCPE_ARG;

  /* set new filter addresses */
  for (i = 0; i < addr_count; i++)
    memcpy(dev->filter_address[i], addresses[i], sizeof(ETH_MAC));
  dev->addr_count = addr_count;

  /* store other flags */
  dev->all_multicast = all_multicast;
  dev->promiscuous   = promiscuous;

  /* print out filter information if debugging */
  if (dev->dptr->dctrl & dev->dbit) {
    sim_debug(dev->dbit, dev->dptr, "Filter Set\n");
    for (i = 0; i < addr_count; i++) {
      char mac[20];
      eth_mac_fmt(&dev->filter_address[i], mac);
      sim_debug(dev->dbit, dev->dptr, "  Addr[%d]: %s\n", i, mac);
    }
    if (dev->all_multicast)
      sim_debug(dev->dbit, dev->dptr, "All Multicast\n");
    if (dev->promiscuous)
      sim_debug(dev->dbit, dev->dptr, "Promiscuous\n");
  }

  /* test reflections */
  if (dev->reflections == -1)
    status = eth_reflect(dev, dev->filter_address[0]);

  /* setup BPF filters and other fields to minimize packet delivery */
  strcpy(buf, "");

  /* construct destination filters - since the real ethernet interface was set
     into promiscuous mode by eth_open(), we need to filter out the packets that
     our simulated interface doesn't want. */
  if (!dev->promiscuous) {
    for (i = 0; i < addr_count; i++) {
      eth_mac_fmt(&dev->filter_address[i], mac);
      if (!strstr(buf, mac))    /* eliminate duplicates */
        sprintf(&buf[strlen(buf)], "%s(ether dst %s)", (*buf) ? " or " : "", mac);
    }
    if (dev->all_multicast)
      sprintf(&buf[strlen(buf)], "%s(ether multicast)", (*buf) ? " or " : "");
  }

  /* construct source filters - this prevents packets from being reflected back 
     by systems where WinPcap and libpcap cause packet reflections. Note that
     some systems do not reflect packets at all. This *assumes* that the 
     simulated NIC will not send out packets with multicast source fields. */
  if ((addr_count > 0) && (dev->reflections > 0)) {
    if (strlen(buf) > 0)
      sprintf(&buf[strlen(buf)], " and ");
    sprintf (&buf[strlen(buf)], "not (");
    buf2 = &buf[strlen(buf)];
    for (i = 0; i < addr_count; i++) {
      if (dev->filter_address[i][0] & 0x01) continue; /* skip multicast addresses */
      eth_mac_fmt(&dev->filter_address[i], mac);
      if (!strstr(buf2, mac))   /* eliminate duplicates */
        sprintf(&buf2[strlen(buf2)], "%s(ether src %s)", (*buf2) ? " or " : "", mac);
    }
    sprintf (&buf[strlen(buf)], ")");
  }
  /* When starting, DECnet sends out a packet with the source and destination
     addresses set to the same value as the DECnet MAC address. This packet is
     designed to find and help diagnose DECnet address conflicts. Normally, this
     packet would not be seen by the sender, only by the other machine that has
     the same DECnet address. If the ethernet subsystem is reflecting packets,
     DECnet will fail to start if it sees the reflected packet, since it thinks
     another system is using this DECnet address. We have to let these packets
     through, so that if another machine has the same DECnet address that we
     can detect it. Both eth_write() and eth_callback() help by checking the
     reflection count - eth_write() adds the reflection count to
     dev->decnet_self_sent, and eth_callback() check the value - if the
     dev->decnet_self_sent count is zero, then the packet has come from another
     machine with the same address, and needs to be passed on to the simulated
     machine. */
  memset(dev->decnet_addr, 0, sizeof(ETH_MAC));
  /* check for decnet address in filters */
  if ((addr_count) && (dev->reflections > 0)) {
    for (i = 0; i < addr_count; i++) {
      eth_mac_fmt(&dev->filter_address[i], mac);
      if (memcmp(mac, "AA:00:04", 8) == 0) {
        memcpy(dev->decnet_addr, &dev->filter_address[i], sizeof(ETH_MAC));
        /* let packets through where dst and src are the same as our decnet address */
        sprintf (&buf[strlen(buf)], " or ((ether dst %s) and (ether src %s))", mac, mac);
        break;
      }
    }
  }
  sim_debug(dev->dbit, dev->dptr, "BPF string is: |%s|\n", buf);


  /* get netmask, which is required for compiling */
  /* XXX: wrong signature. discovered during refactoring. */
  if (pcap_lookupnet(devi->pcap, &bpf_subnet, &bpf_netmask, errbuf)<0) {
      bpf_netmask = 0;
  }

#ifdef USE_BPF
  /* compile filter string */
  if ((status = pcap_compile(devi->pcap, &bpf, buf, 1, bpf_netmask)) < 0) {
    sprintf(errbuf, "%s", pcap_geterr(devi->pcap));
    msg = "Eth: pcap_compile error: %s\r\n";
    printf(msg, errbuf);
    if (sim_log) fprintf (sim_log, msg, errbuf);
    /* show erroneous BPF string */
    msg = "Eth: BPF string is: |%s|\r\n";
    printf (msg, buf);
    if (sim_log) fprintf (sim_log, msg, buf);
  } else {
    /* apply compiled filter string */
    if ((status = pcap_setfilter(devi->pcap, &bpf)) < 0) {
      sprintf(errbuf, "%s", pcap_geterr(devi->pcap));
      msg = "Eth: pcap_setfilter error: %s\r\n";
      printf(msg, errbuf);
      if (sim_log) fprintf (sim_log, msg, errbuf);
    } else {
#ifdef USE_SETNONBLOCK
      /* set file non-blocking */
      status = pcap_setnonblock (devi->pcap, 1, errbuf);
#endif /* USE_SETNONBLOCK */
    }
    pcap_freecode(&bpf);
  }
#endif /* USE_BPF */

  return SCPE_OK;
}
