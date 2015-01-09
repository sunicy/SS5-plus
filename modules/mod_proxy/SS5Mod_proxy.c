/* Socks Server 5
 * Copyright (C) 2002 - 2011 by Matteo Ricchetti - <matteo.ricchetti@libero.it>

 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * B
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include"SS5Main.h"
#include"SS5Defs.h"
#include"SS5Mod_proxy.h"
#include"SS5Mod_socks5.h"

#ifdef SS5_USE_GSSAPI
#include"SS5GSSApi.h"
#endif

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  m->ReceivingData = ReceivingData;
  m->SendingData   = SendingData;
  m->UdpReceivingData = UdpReceivingData;
  m->UdpSendingData   = UdpSendingData;
  
  return OK;
}


INT 
  IFEPOLL( ReceivingData( struct _SS5ClientInfo *ci, struct _SS5ProxyData *pd, struct epoll_event *events ) )
  IFSELECT( ReceivingData( struct _SS5ClientInfo *ci, struct _SS5ProxyData *pd, fd_set *s5array ) )
{
  register UINT i;

  UINT len=0;

  unsigned char *oubuf;

  unsigned char gssHeader[4];

  char logString[128];

  pid_t pid;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /* 
   * Receive data from client
   */
  IFEPOLL( if( events[0].data.fd == ci->Socket ) { )
  IFSELECT( if( FD_ISSET(ci->Socket,s5array) ) { )

    pd->Fd = 0;

#ifdef SS5_USE_GSSAPI
   /*
    * If GSS method, decode proxy data received from client
    */
    if( GSSAPI() && GSSINTEGRITY() ) {

     /*
      * Read GSS Header from the beginning of the receive queue
      */
      pd->TcpRBufLen=recv(ci->Socket,gssHeader,sizeof(gssHeader),MSG_PEEK);
      GET_GSSHEADER_LEN(gssHeader,len,GSS_OFFSET_HLEN)
      len +=4; 

     /*
      * If token is bigger then default buffer size, realloc proxy data buffer
      */
      if( (len > pd->BufSize) && (len < MAX_GSSTOKEN_SIZE) ) {
        pd->Recv=realloc(pd->Recv,(len));
        pd->Send=realloc(pd->Send,(len));
        pd->BufSize=len;
      }

     /*
      * Receive GSS 0x03 token
      */
      memset(pd->Recv,0,pd->BufSize);
      pd->TcpRBufLen = recv(ci->Socket,(void *)pd->Recv,len,0);

      if( (len=pd->TcpRBufLen) ) {
        if( S5GSSApiDecode(ci->GssContext, ci->GssEnc, pd->Recv, &oubuf, &len) ) {

          memcpy(pd->Recv,oubuf,len);
          free(oubuf);
          pd->TcpRBufLen=len;
        }
        else
          return ERR;
      }
    }
    else {
#endif
      memset(pd->Recv,0,pd->BufSize);
      if( (pd->TcpRBufLen = recv(ci->Socket,(void *)pd->Recv,pd->BufSize,0)) == -1 )
        ERRNO(pid)
        
#ifdef SS5_USE_GSSAPI
    }
#endif
  }

  /* 
   * Receive data from application
   */
  IFEPOLL( else if( events[0].data.fd == ci->appSocket ) { )
  IFSELECT( else if( FD_ISSET(ci->appSocket,s5array) ) { )
    memset(pd->Recv,0,pd->BufSize);
    pd->TcpRBufLen = recv(ci->appSocket,pd->Recv,pd->BufSize,0);
    pd->Fd = 1;
  }
  return OK;
} 

INT 
SendingData( struct _SS5ClientInfo *ci, struct _SS5ProxyData *pd )
{
  int len;

  unsigned char *oubuf;

  if( pd->Fd == 1 ) {

    memset(pd->Send,0,pd->BufSize);
    memcpy(pd->Send,pd->Recv,pd->TcpRBufLen);

#ifdef SS5_USE_GSSAPI
   /*
    * If GSS method and at least INTEGRITY is asked for, encode proxy data before sending to client
    */
    if( GSSAPI() && GSSINTEGRITY() ) {
      if( (len=pd->TcpRBufLen) ) {
        if( S5GSSApiEncode(ci->GssContext, ci->GssEnc, pd->Send, &oubuf, &len) ) {

          memcpy(pd->Send,oubuf,len);
          free(oubuf);

          pd->TcpRBufLen=len;
        }
        else
          return ERR;
      }
    }
#endif

    pd->TcpSBufLen = send(ci->Socket,pd->Send,pd->TcpRBufLen,SS5_SEND_OPT);
  }
  else {
    memset(pd->Send,0,pd->BufSize);
    memcpy(pd->Send,pd->Recv,pd->TcpRBufLen);
    pd->TcpSBufLen = send(ci->appSocket,pd->Send,pd->TcpRBufLen,SS5_SEND_OPT);
  }

  return OK;
}

INT 
UdpReceivingData( int t, int rSocket, struct _SS5RequestInfo *ri, struct _SS5ProxyData *pd, struct _SS5ClientInfo *ci )
{
  UINT len;
  UINT fd;

  register int i,j;

  struct timeval tv;

  UINT resolvedHostNumber=1;

  struct _S5HostList resolvedHostList[MAXDNS_RESOLV];

  unsigned short ipA,
                 ipB,
                 ipC,
                 ipD;

  fd_set arrayFd;

  unsigned char *oubuf = NULL;

  struct sockaddr_in clientBindSsin;

  unsigned char gssHeader[4];

  struct in_addr in;

  char logString[128];
  char addr[16];

  pid_t pid;

  IFEPOLL( int kdpfd; )

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  bzero((char *)&clientBindSsin, sizeof(struct sockaddr_in));

  len = sizeof(struct sockaddr_in);
  memset(pd->UdpRecv,0,sizeof(pd->UdpBufSize));

  if( t == 1 ) {
#ifdef SS5_USE_GSSAPI
    if( GSSAPI() && GSSINTEGRITY() ) {

      pd->UdpRBufLen=recvfrom(rSocket,gssHeader,sizeof(gssHeader),MSG_PEEK,(struct sockaddr *)&clientBindSsin, (socklen_t *)&len);
  
      GET_GSSHEADER_LEN(gssHeader,len,GSS_OFFSET_HLEN)
      len +=4;
  
      if( (len > pd->UdpBufSize) && (len < MAX_GSSTOKEN_SIZE) ) {
        pd->UdpRecv=realloc(pd->UdpRecv,(len));
        pd->UdpSend=realloc(pd->UdpSend,(len));
        pd->UdpBufSize=len;
      }
  
      memset(pd->UdpRecv,0,sizeof(pd->UdpRecv));
      if( (pd->UdpRBufLen=recvfrom(rSocket,pd->UdpRecv,pd->UdpBufSize,0,(struct sockaddr *)&clientBindSsin,
          (socklen_t *)&len)) == -1 ) {
  
        ERRNO(pid)
        IFEPOLL( close(kdpfd); )
        return ERR;
      }
  
      /*
       * If GSS method, encode response before sending to client
       */
  
      len=pd->UdpRBufLen;
      if( S5GSSApiDecode(ci->GssContext, ci->GssEnc, pd->UdpRecv, &oubuf, &len) ) {
  
        memcpy(pd->UdpRecv,oubuf,len);
        if( oubuf ) {
          free(oubuf);
          oubuf=NULL;
        }
        pd->UdpRBufLen=len;
      }
      else
        return ERR;
    }
    else {
#endif
      if( (pd->UdpRBufLen=recvfrom(rSocket,pd->UdpRecv,pd->UdpBufSize,0,(struct sockaddr *)&clientBindSsin,
          (socklen_t *)&len)) == -1 ) {

        ERRNO(pid)
        IFEPOLL( close(kdpfd); )
        return ERR;
      }
        
#ifdef SS5_USE_GSSAPI
    }
#endif
        
    if( VERBOSE() ) {
      snprintf(logString,256 - 1,"[%u] [VERB] Receiving UDP response from destination address.",pid);
      LOGUPDATE()
    }
    if( DEBUG() ) {
      in.s_addr=clientBindSsin.sin_addr.s_addr;
      snprintf(logString,256 - 1,"[%u] [DEBU] [PROXY DATA] UDP request received from %s and port %d.",pid,inet_ntoa(in),ntohs(clientBindSsin.sin_port));
      LOGUPDATE()
    }
    /*
     * Set udp request info
     */
    ri->udpATyp=(unsigned char)pd->UdpRecv[3];
    ri->udpFrag=(unsigned char)pd->UdpRecv[2];

    /*
     * Check for fragmentation bit set
     */
    if( ri->udpFrag ) {
      if( VERBOSE() ) {
         snprintf(logString,256 - 1,"[%u] [VERB] UDP fragmentation bit set.",pid);
         LOGUPDATE()
      }
      return( -1 * S5REQUEST_ISERROR);
    }

    /*
     * Get remote peer address and port
     * to set udp client info
     */
    in.s_addr=clientBindSsin.sin_addr.s_addr;
    strncpy(addr,(char *)inet_ntoa(in),sizeof(addr));

    sscanf((const char *)addr,"%hu.%hu.%hu.%hu",&ipA,&ipB,&ipC,&ipD);

    strncpy(ci->udpSrcAddr,addr,sizeof(ci->udpSrcAddr));
    ci->udpSrcPort=ntohs(clientBindSsin.sin_port);

    /*
     * Set udp request info
     */
    switch( ri->udpATyp ) {
      case IPV4:
        ri->udpDstPort=0;
        ri->udpDstPort +=(unsigned char)pd->UdpRecv[8];
        ri->udpDstPort <<=8;
        ri->udpDstPort +=(unsigned char)pd->UdpRecv[9];

        snprintf(ri->udpDstAddr,sizeof(ri->DstAddr),"%hu.%hu.%hu.%hu",(unsigned char)pd->UdpRecv[4],
                                                                    (unsigned char)pd->UdpRecv[5],
                                                                    (unsigned char)pd->UdpRecv[6],
                                                                    (unsigned char)pd->UdpRecv[7]);
       /*
        * Move data after socks header to proxy buffer
        */
        for(i=0;i<((UINT)pd->UdpRBufLen-10);i++)
          pd->UdpSend[i]=pd->UdpRecv[i+10];

        pd->UdpSBufLen=pd->UdpRBufLen-10;
      break;

      case IPV6:
        /* IPV6 is not supported */
        return (-1 * S5REQUEST_ADDNOTSUPPORT);
      break;

      case DOMAIN:
        len=(unsigned char)pd->UdpRecv[4] + 5;
        if( len > sizeof(pd->UdpRecv) )
          len=sizeof(pd->UdpRecv);

        ri->udpDstPort=0;
        ri->udpDstPort +=(unsigned char)pd->UdpRecv[len];
        ri->udpDstPort <<=8;
        ri->udpDstPort +=(unsigned char)pd->UdpRecv[len+1];

        for(i=0,j=5;i<len;i++,j++ )
          ri->udpDstAddr[i]=pd->UdpRecv[j];
        ri->udpDstAddr[i]='\0';

        /*
         * Move data after socks header to proxy buffer
         */
        len=5+2+pd->UdpRecv[4];
        if( len > pd->UdpRBufLen )
          len=pd->UdpRBufLen;

        for(i=0;i<(pd->UdpRBufLen-len);i++)
          pd->UdpSend[i]=pd->UdpRecv[i+len];

        pd->UdpSBufLen=pd->UdpRBufLen-len;
      break;
    }
  }
  else {
   
    if( (pd->UdpRBufLen=recvfrom(rSocket,pd->UdpRecv,pd->UdpBufSize,0,(struct sockaddr *)&clientBindSsin,
        (socklen_t *)&len)) == -1 ) {

      ERRNO(pid)
      IFEPOLL( close(kdpfd); )
      return ERR;
    }
    pd->UdpSBufLen=pd->UdpRBufLen;
  }

    /* VERIFY UDP STRCT ???  */

    /*
     * SS5: Resolve hostname of udp destination address
     */
    if( ri->udpATyp == DOMAIN ) {
      if( DEBUG() ) {
         snprintf(logString,256 - 1,"[%u] [DEBU] FQDN destination address is: %s.",pid,ri->udpDstAddr);
         LOGUPDATE()
      }
      if( S5UdpResolvHostName((struct _SS5RequestInfo *)ri, (struct _S5HostList *)resolvedHostList, &resolvedHostNumber) == ERR ) {
        if( VERBOSE() ) {
           snprintf(logString,256 - 1,"[%u] [VERB] Failed resolving FQDN destination address.",pid);
           LOGUPDATE()
        }

        return( -1 * S5REQUEST_ISERROR);
      }
    }

  return OK;
}

INT 
UdpSendingData( int t, int appSocket, struct _SS5RequestInfo *ri , struct _SS5ProxyData *pd, struct _SS5ClientInfo *ci  )
{
  UINT len, datalen;

  register int i;
 
  unsigned char *oubuf;

  char logString[128];

  pid_t pid;

  struct sockaddr_in applicationSsin;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  len = sizeof(struct sockaddr_in);

  memset((char *)&applicationSsin, 0, sizeof(struct sockaddr_in));
  applicationSsin.sin_family      = AF_INET;


  if( t == 1 ) {
    datalen=pd->UdpSBufLen+10;

    switch( ri->udpATyp ) {
      case IPV4:
      case DOMAIN:
        pd->UdpSend[0]=0;
        pd->UdpSend[1]=0;
        pd->UdpSend[2]=ri->udpFrag;
        pd->UdpSend[3]=ri->udpATyp;
  
        SETADDR(pd->UdpSend,inet_addr(ri->udpDstAddr),4)
        SETPORT_R(pd->UdpSend,ri->udpDstPort,8)
  
      break;
      /*
       *    Socks V5 Header is 22 bytes but IPV6 is not supported
       */
      case IPV6:    return (-1 * S5REQUEST_ADDNOTSUPPORT);    break;
    }
    /*
     * Send response to client
     */
    for(i=0;i<(pd->UdpRBufLen);i++)
      pd->UdpSend[i+10]=pd->UdpRecv[i];

#ifdef SS5_USE_GSSAPI
   /*
    * If GSS method, encode response before sending to client
    */
    if( GSSAPI() && GSSINTEGRITY() ) {
      if( S5GSSApiEncode(ci->GssContext, ci->GssEnc, pd->UdpSend, &oubuf, &datalen) ) {
        memcpy(pd->UdpSend,oubuf,datalen);
        free(oubuf);
      }
      else
        return ERR;
    }
#endif
    applicationSsin.sin_port        = htons(ci->udpSrcPort);
    applicationSsin.sin_addr.s_addr = inet_addr(ci->udpSrcAddr);
  }
  else {
    applicationSsin.sin_port        = htons(ri->udpDstPort);
    applicationSsin.sin_addr.s_addr = inet_addr(ri->udpDstAddr);
    datalen=pd->UdpSBufLen;
  }


  if( (pd->UdpSBufLen=sendto(appSocket,pd->UdpSend,datalen,0,(struct sockaddr *)&applicationSsin,
      (socklen_t)len)) == -1 ) {

    ERRNO(pid)
    return( -1 * S5REQUEST_ISERROR );
  }

  if( VERBOSE() ) {
    snprintf(logString,256 - 1,"[%u] [VERB] Sending UDP request to destination address.",pid);
    LOGUPDATE()
  }
  if( DEBUG() ) {
    snprintf(logString,256 - 1,"[%u] [DEBU] [PROXY DATA] UDP request sent to %s on port %d.",pid,ri->udpDstAddr,ri->udpDstPort);
    LOGUPDATE()
  }


  return OK;
}
