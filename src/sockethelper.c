
#include <stdio.h>
#include <string.h>

#include <stdlib.h>
#include <stdarg.h>

#include <poll.h>
#include <pthread.h>

#include <stunclient.h>
#include "sockethelper.h"
#include "utils.h"


int
createLocalSocket(int                    ai_family,
                  const struct sockaddr* localIp,
                  int                    ai_socktype,
                  uint16_t               port)
{
  int sockfd;

  int             rv;
  struct addrinfo hints, * ai, * p;
  char            addr[SOCKADDR_MAX_STRLEN];
  char            service[8];

  sockaddr_toString(localIp, addr, sizeof addr, false);

  /* itoa(port, service, 10); */

  snprintf(service, 8, "%d", port);
  /* snprintf(service, 8, "%d", 3478); */


  /* get us a socket and bind it */
  memset(&hints, 0, sizeof hints);
  hints.ai_family   = ai_family;
  hints.ai_socktype = ai_socktype;
  hints.ai_flags    = AI_NUMERICHOST | AI_ADDRCONFIG;


  if ( ( rv = getaddrinfo(addr, service, &hints, &ai) ) != 0 )
  {
    fprintf(stderr, "selectserver: %s ('%s')\n", gai_strerror(rv), addr);
    exit(1);
  }

  for (p = ai; p != NULL; p = p->ai_next)
  {
    if ( sockaddr_isAddrAny(p->ai_addr) )
    {
      /* printf("Ignoring any\n"); */
      continue;
    }

    if ( ( sockfd = socket(p->ai_family, p->ai_socktype,
                           p->ai_protocol) ) == -1 )
    {
      perror("client: socket");
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) < 0)
    {
      printf("Bind failed\n");
      close(sockfd);
      continue;
    }

    if (localIp != NULL)
    {
      struct sockaddr_storage ss;
      socklen_t               len = sizeof(ss);
      if (getsockname(sockfd, (struct sockaddr*)&ss, &len) == -1)
      {
        perror("getsockname");
      }
      else
      {
        if (ss.ss_family == AF_INET)
        {
          ( (struct sockaddr_in*)p->ai_addr )->sin_port =
            ( (struct sockaddr_in*)&ss )->sin_port;
        }
        else
        {
          ( (struct sockaddr_in6*)p->ai_addr )->sin6_port =
            ( (struct sockaddr_in6*)&ss )->sin6_port;
        }
      }
    }
    break;
  }
  int ttl = 60;
  if (setsockopt( sockfd, IPPROTO_IP, IP_RECVTTL, &ttl,sizeof(ttl) ) < 0)
  {
    printf("cannot set recvttl\n");
  }
  else
  {
    printf("socket set to recvttl\n");
  }
  return sockfd;
}

void*
handleRequest(void* ptr)
{
  struct Request* request = (struct Request*)ptr;
  if ( stunlib_isStunMsg(request->buf, request->numbytes) )
  {
    /* Send to STUN, with CB to data handler if STUN packet contations
     * DATA */
    printf("Got stun..\n");
    request->stun_handler(request->socketConfig,
                          (struct sockaddr*)&request->their_addr,
                          request->tInst,
                          request->buf,
                          request->numbytes);
  }
  free(request);
  printf("Finished looking for stun..\n");
  /* pthread_exit(NULL); */
  return NULL;
}


void
fillMSGHdr(struct msghdr*   msgh,
           struct iovec*    iov,
           char*            cbuf,
           size_t           cbufsize,
           unsigned char*   data,
           size_t           datalen,
           struct sockaddr* addr,
           size_t           addr_len)
{
  iov->iov_base = data;
  iov->iov_len  = datalen;

  memset( msgh, 0, sizeof(struct msghdr) );

  msgh->msg_control    = cbuf;
  msgh->msg_controllen = cbufsize;
  msgh->msg_name       = addr;
  msgh->msg_namelen    = addr_len;
  msgh->msg_iov        = iov;
  msgh->msg_iovlen     = 1;
  msgh->msg_flags      = 0;
}


void*
socketListenDemux(void* ptr)
{
  struct pollfd        ufds[10];
  struct listenConfig* config = (struct listenConfig*)ptr;
  /* struct sockaddr_storage their_addr; */
  /* unsigned char           buf[MAXBUFLEN]; */
  /* socklen_t               addr_len; */
  int rv;
  /* int                     numbytes; */
  int i;

  /* int  keyLen = 16; */
  /* char md5[keyLen]; */
  config->thread_no = 0;
  for (i = 0; i < config->numSockets; i++)
  {
    ufds[i].fd     = config->socketConfig[i].sockfd;
    ufds[i].events = POLLIN;
  }

  /*  */

  while (1)
  {
    rv = poll(ufds, config->numSockets, -1);
    if (rv == -1)
    {
      perror("poll");       /* error occurred in poll() */
    }
    else if (rv == 0)
    {
      printf("Timeout occurred! (Should not happen)\n");
    }
    else
    {
      /* check for events on s1: */
      for (i = 0; i < config->numSockets; i++)
      {
        if (ufds[i].revents & POLLIN)
        {
          struct Request* request = malloc( sizeof(struct Request) );
          request->socketConfig = &config->socketConfig[i];
          request->tInst        = config->tInst;
          request->stun_handler = config->stun_handler;
          request->addr_len     = sizeof request->their_addr;

          struct msghdr msg;
          char          c_buf[250];
          struct iovec  iov;

          fillMSGHdr(&msg, &iov, c_buf,
                     sizeof(c_buf), request->buf, MAXBUFLEN,
                     (struct sockaddr*)&request->their_addr, request->addr_len);

          request->numbytes = recvmsg(ufds[i].fd, &msg, 0);

          if (request->numbytes == -1)
          {
            perror("recvmsg");
            exit(1);
          }

          /* See if we can get some ttl info.. */
          struct cmsghdr* cmsg;
          int*            ttlptr       = NULL;
          int             received_ttl = 0;
          for ( cmsg = CMSG_FIRSTHDR(&msg);
                cmsg != NULL;
                cmsg = CMSG_NXTHDR(&msg,cmsg) )
          {
            printf("Cmsg type = %i\n", cmsg->cmsg_type);
            if ( (cmsg->cmsg_level == IPPROTO_IP) &&
                 (cmsg->cmsg_type == IP_TTL) &&
                 (cmsg->cmsg_len) )
            {
              ttlptr       = (int*) CMSG_DATA(cmsg);
              received_ttl = *ttlptr;
              printf("received_ttl = %i \n", received_ttl);
              break;
            }
          }


          int pt = pthread_create(&config->threads[config->thread_no],
                                  NULL,
                                  handleRequest,
                                  (void*)request);
          if (pt)
          {
            perror("Failed to create thread");
            printf(
              "Could not create thread for STUN handling.. (Ret:%i num:%i)\n",
              pt,
              config->thread_no++);
            exit(EXIT_FAILURE);
          }
          else
          {
            config->thread_no++;
            if (config->thread_no + 1 >= MAX_THREADS)
            {
              /* We roll over.. Hopefully the old threads are finished by now..
               * */
              config->thread_no = 0;

            }
          }
        }
      }
    }
  }
}




void
sendPacket(void*                  ctx,
           int                    sockHandle,
           const uint8_t*         buf,
           int                    bufLen,
           const struct sockaddr* dstAddr,
           int                    proto,
           bool                   useRelay,
           uint8_t                ttl)
{
  int32_t numbytes;
  /* char addrStr[SOCKADDR_MAX_STRLEN]; */
  uint32_t sock_ttl;
  uint32_t addr_len;
  (void) ctx;
  (void) proto; /* Todo: Sanity check? */
  (void) useRelay;

  if (dstAddr->sa_family == AF_INET)
  {
    addr_len = sizeof(struct sockaddr_in);
  }
  else
  {
    addr_len = sizeof(struct sockaddr_in6);
  }

  if (ttl > 0)
  {
    /*Special TTL, set it send packet and set it back*/
    int          old_ttl;
    unsigned int optlen;
    if (dstAddr->sa_family == AF_INET)
    {
      getsockopt(sockHandle, IPPROTO_IP, IP_TTL, &old_ttl, &optlen);
    }
    else
    {
      getsockopt(sockHandle, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &old_ttl,
                 &optlen);
    }

    sock_ttl = ttl;

    /* sockaddr_toString(dstAddr, addrStr, SOCKADDR_MAX_STRLEN, true); */
    /* printf("Sending Raw (To: '%s'(%i), Bytes:%i/%i  (Addr size: %u)\n",
     * addrStr, sockHandle, numbytes, bufLen,addr_len); */

    if (dstAddr->sa_family == AF_INET)
    {
      setsockopt( sockHandle, IPPROTO_IP, IP_TTL, &sock_ttl, sizeof(sock_ttl) );
    }
    else
    {
      setsockopt( sockHandle, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &sock_ttl,
                  sizeof(sock_ttl) );
    }

    if ( ( numbytes =
             sendto(sockHandle, buf, bufLen, 0, dstAddr, addr_len) ) == -1 )
    {
      perror("Stun sendto");
      exit(1);
    }
    if (dstAddr->sa_family == AF_INET)
    {
      setsockopt(sockHandle, IPPROTO_IP, IP_TTL, &old_ttl, optlen);
    }
    else
    {
      setsockopt(sockHandle, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &old_ttl, optlen);
    }


  }
  else
  {
    /*Nothing special, just send the packet*/
    if ( ( numbytes =
             sendto(sockHandle, buf, bufLen, 0, dstAddr, addr_len) ) == -1 )
    {
      perror("Stun sendto");
      exit(1);
    }
  }
}
