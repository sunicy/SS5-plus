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
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#include"SS5Main.h"
#include"SS5Defs.h"
#include"SS5Mod_socks4.h"
#include"SS5Mod_authorization.h"
#include"SS5Mod_log.h"
#include"SS5OpenLdap.h"

char *ss5ver=SS5_VERSION;

UINT InitModule( struct _module *m )
{
  m->V4RequestParsing=RequestParsing;
  m->V4UpstreamServing=UpstreamServing;
  m->V4ConnectServing=ConnectServing;
  m->V4BindServing=BindServing;

  return OK;
}

UINT RequestParsing(struct _SS5ClientInfo *ci,  struct _SS5Socks5Data *sd, struct _SS5RequestInfo *ri)
{
  UINT i,j;

  char logString[128];

  pid_t pid;

  /*
   * Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /*
   * Receive socks V4 command
   */
  if( (sd->TcpRBytesReceived=recv(ci->Socket,(unsigned short *)&ri->Cmd,1,0)) <= 0 ) {
    ERRNO(pid)
    return ERR;
  }
  if( DEBUG() ) {
    snprintf(logString,128,"[%u] [DEBU] [S4 REQUEST PACKET] Receiving socks command: %d.",pid,ri->Cmd);
    LOGUPDATE()
  }

  /*
   * Validate socks V4 command
   */
  ri->Ver=ci->Ver;

  if( (ri->Cmd > 2) || (ri->Cmd < 1) )
    return ERR;

  /*
   * Receive socks V4 destination port and ip
   */
  if( (sd->TcpRBytesReceived=recv(ci->Socket,sd->TcpRequest,6,0)) <= 0 ) {
    ERRNO(pid)
    return ERR;
  }


  if( !(unsigned char)sd->TcpRequest[2] && !(unsigned char)sd->TcpRequest[3] && 
    !(unsigned char)sd->TcpRequest[4] && (unsigned char)sd->TcpRequest[5] ) {
    /*
     * Destination address is fqdn
     */
    ri->ATyp=DOMAIN;

    ri->DstPort=0;
    ri->DstPort +=(unsigned char)sd->TcpRequest[0];
    ri->DstPort <<=8;
    ri->DstPort +=(unsigned char)sd->TcpRequest[1];

    /*
     * Receive socks V4 username and Fqdn
     */
    if( (sd->TcpRBytesReceived=recv(ci->Socket,sd->TcpRequest,sizeof(sd->TcpRequest),0)) <= 0 ) {
      ERRNO(pid)
      return ERR;
    }

    for(i=0;(ci->Username[i]=sd->TcpRequest[i]);i++);
    ci->Username[i++]='\0';

    if( VERBOSE() ) {
      snprintf(logString,128,"[%u] [DEBU] [S4 REQUEST PACKET] Receiving socks username: %s.",pid,ci->Username);
      LOGUPDATE()
    }

    for(j=0;(ri->DstAddr[j]=sd->TcpRequest[i]);j++,i++ );
    ri->DstAddr[j]='\0';

    if( VERBOSE() ) {
      snprintf(logString,128,"[%u] [DEBU] [S4 REQUEST PACKET] Receiving socks destination ip %s and port: %d.",pid,ri->DstAddr,ri->DstPort);
      LOGUPDATE()
    }

  }
  else {
    /*
     * Destination address is dot notation
     */
    ri->ATyp=IPV4;

    ri->DstPort=0;
    ri->DstPort +=(unsigned char)sd->TcpRequest[0];
    ri->DstPort <<=8;
    ri->DstPort +=(unsigned char)sd->TcpRequest[1];

    snprintf(ri->DstAddr,sizeof(ri->DstAddr),"%hu.%hu.%hu.%hu",(unsigned char)sd->TcpRequest[2],
                                                               (unsigned char)sd->TcpRequest[3],
                                                               (unsigned char)sd->TcpRequest[4],
                                                               (unsigned char)sd->TcpRequest[5]);
    if( DEBUG() ) {
      snprintf(logString,128,"[%u] [DEBU] [S4 REQUEST PACKET] Receiving socks destination ip %s and port: %d.",pid,ri->DstAddr,ri->DstPort);
      LOGUPDATE()
    }

    /*
     * Receive socks V4 username
     */
    if( (sd->TcpRBytesReceived=recv(ci->Socket,sd->TcpRequest,sizeof(sd->TcpRequest),0)) <= 0 ) {
      ERRNO(pid)
      return ERR;
    }
      
    for(i=0;(ci->Username[i]=sd->TcpRequest[i]);i++);
    ci->Username[i]='\0';

    if( DEBUG() ) {
      snprintf(logString,128,"[%u] [DEBU] [S4 REQUEST PACKET] Receiving socks username: %s.",pid,ci->Username);
      LOGUPDATE()
    }
  }

  return OK;
}


UINT UpstreamServing(struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd)
{
  UINT i;

  struct sockaddr_in applicationSsin,
                     bindInterfaceSsin;

  struct in_addr in;

  pid_t pid;

  char logString[128];

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  if ( (ci->appSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    ERRNO(pid)
    return( -1 * S4REQUEST_REJECTED );
  }

  /*
   * SS5: set bind interface if configured
   */
  if( ROUTE() ) {
    if( (in.s_addr=(ULINT)GetRoute(inet_network(ci->SrcAddr), inet_network(ri->DstAddr), ci->Username)) ) {
      if( VERBOSE() ) {
        snprintf(logString,128,"[%u] [VERB] Found route interface.",pid);
        LOGUPDATE()
      }

      memset((char *)&bindInterfaceSsin, 0, sizeof(struct sockaddr_in));

      if( (bindInterfaceSsin.sin_addr.s_addr=in.s_addr) ) {
        bindInterfaceSsin.sin_family      = AF_INET;
        bindInterfaceSsin.sin_port        = htons(0);

        if ( bind(ci->appSocket, (struct sockaddr *)&bindInterfaceSsin, sizeof(struct sockaddr_in)) == -1 ) {
          ERRNO(pid)
          return( -1 * S4REQUEST_REJECTED );
        }
      }
    }
  }

  if( DEBUG() ) {
    in.s_addr=ri->upDstAddr; 
    snprintf(logString,128,"[%u] [DEBU] [S4 UPSTREAM PROXY] Proxy socks 4 request to: %s:%d.",pid,(char *)inet_ntoa(in),ri->upDstPort);
    LOGUPDATE()
  }

  memset((char *)&applicationSsin, 0, sizeof(struct sockaddr_in));
  applicationSsin.sin_family      = AF_INET;
  applicationSsin.sin_port        = htons(ri->upDstPort);
  applicationSsin.sin_addr.s_addr = (ULINT)ri->upDstAddr;

  if( connect(ci->appSocket,(struct sockaddr *)&applicationSsin,sizeof(struct sockaddr_in)) != -1 ) {
    /* 
     * Proxy client connect request towards upstream socks server
     */
    memset((char *)sd->TcpRequest, 0, sizeof(sd->TcpRequest));
    sd->TcpRequest[0]=ri->Ver;
    sd->TcpRequest[1]=ri->Cmd;

    if( send(ci->appSocket,sd->TcpRequest,2,SS5_SEND_OPT) == -1) {
      ERRNO(pid)
      return( -1 * S4REQUEST_REJECTED );
    }

    memset((char *)sd->TcpRequest, 0, sizeof(sd->TcpRequest));

    SETPORT_R(sd->TcpRequest,ri->DstPort,0)
    SETADDR(sd->TcpRequest,inet_addr(ri->DstAddr),2)

    if( send(ci->appSocket,sd->TcpRequest,6,SS5_SEND_OPT) == -1) {
      ERRNO(pid)
      return( -1 * S4REQUEST_REJECTED );
    }

    memset((char *)sd->TcpRequest, 0, sizeof(sd->TcpRequest));

    memcpy(sd->TcpRequest,ci->Username,strlen(ci->Username));

    if( send(ci->appSocket,sd->TcpRequest,strlen(ci->Username)+1,SS5_SEND_OPT) == -1) {
      ERRNO(pid)
      return( -1 * S4REQUEST_REJECTED );
    }
 
    /* 
     * If SOCKS 4A draft, send FQDN at the end of SOCKS 4 request
     */
    if( ri->ATyp == DOMAIN ) {
      memset((char *)sd->TcpRequest, 0, sizeof(sd->TcpRequest));

      memcpy(sd->TcpRequest,ri->DstAddr,strlen(ri->DstAddr));

      if( send(ci->appSocket,sd->TcpRequest,strlen(ri->DstAddr)+1,SS5_SEND_OPT) == -1) {
        ERRNO(pid)
        return( -1 * S4REQUEST_REJECTED );
      }
    }

    if( VERBOSE() ) {
      snprintf(logString,128,"[%u] [VERB] %s V4 request sent to upstream socks.",pid,(ri->Cmd==CONNECT)?"CONNECT":"BIND");
      LOGUPDATE()
    }

    if( ri->Cmd == BIND ) {
      /* 
       * Proxy client bind request towards upstream socks server
       */
      if( (sd->TcpRBytesReceived=recv(ci->appSocket,sd->Response,sizeof(sd->Response),0)) <= 0 ) {
        ERRNO(pid)
        return( -1 * S4REQUEST_REJECTED );
      }
      if( VERBOSE() ) {
        snprintf(logString,128,"[%u] [VERB] BIND V4 request received from upstream socks.",pid);
        LOGUPDATE()
      }
      /* 
       * If ip address equals to 0.0.0.0, replaces it with upstram address
       */
      if( (unsigned char)sd->Response[4] == 0 && (unsigned char)sd->Response[5] == 0 && 
          (unsigned char)sd->Response[6] == 0 && (unsigned char)sd->Response[7] == 0 ) {

        SETADDR_R(sd->Response,ri->upDstAddr,4)
        if( VERBOSE() ) {
          snprintf(logString,128,"[%u] [VERB] BIND V4 request fixup applied.",pid);
          LOGUPDATE()
        }
      }
      if( send(ci->Socket,sd->Response,sd->TcpRBytesReceived,SS5_SEND_OPT) == -1) {
        ERRNO(pid)
        return( -1 * S4REQUEST_REJECTED );
      }
    }
    return OK;
  }
  else {
    return( -1 * S4REQUEST_REJECTED );
  }
  return OK;
}


UINT ConnectServing(struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd)
{
  register UINT i;

  UINT err=S4REQUEST_GRANTED;

  UINT resolvedHostNumber = 0;

  struct in_addr in;

  pid_t pid;

  char logString[128];

  struct _S5HostList resolvedHostList[MAXDNS_RESOLV];

  struct sockaddr_in applicationSsin,
                     bindInterfaceSsin;

  /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /*
   * SS5: Resolve hostname before connecting
   */ 
  if( ri->ATyp == DOMAIN ) {
    if( S5ResolvHostName(ri, (struct _S5HostList *)resolvedHostList, &resolvedHostNumber) == ERR )
      err=S4REQUEST_REJECTED;
  }

  if( err == S4REQUEST_GRANTED ) {
    if ((ci->appSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      ERRNO(pid)
      err=S4REQUEST_REJECTED;
    }
    else {
      /*
       * SS5: set bind interface if configured
       */
      if( ci->framedRoute.sin_addr.s_addr ) {
        memset((char *)&bindInterfaceSsin, 0, sizeof(struct sockaddr_in));
        bindInterfaceSsin.sin_family      = AF_INET;
        bindInterfaceSsin.sin_port        = htons(0);

        bindInterfaceSsin.sin_addr.s_addr=ci->framedRoute.sin_addr.s_addr;

        if ( bind(ci->appSocket, (struct sockaddr *)&bindInterfaceSsin, sizeof(struct sockaddr_in)) == -1 ) {
          ERRNO(pid)
          err=S5REQUEST_ISERROR;
        }
      }
      else if( ROUTE() ) {
        /*
         * SS5: set route interface if present
         */ 
        if( (in.s_addr=(ULINT)GetRoute(inet_network(ci->SrcAddr), inet_network(ri->DstAddr), ci->Username)) ) {
          if( VERBOSE() ) {
            snprintf(logString,128,"[%u] [VERB] Found route interface.",pid);
            LOGUPDATE()
          }

          memset((char *)&bindInterfaceSsin, 0, sizeof(struct sockaddr_in));
          if( (bindInterfaceSsin.sin_addr.s_addr=in.s_addr) )
          {
            bindInterfaceSsin.sin_family      = AF_INET;
            bindInterfaceSsin.sin_port        = htons(0);

            if ( bind(ci->appSocket, (struct sockaddr *)&bindInterfaceSsin, sizeof(struct sockaddr_in)) == -1 ) {
              ERRNO(pid)
              err=S4REQUEST_REJECTED;
            }
          }
        }
      }

      if( err == S4REQUEST_GRANTED ) {
        bzero((char *)&applicationSsin, sizeof(struct sockaddr_in));
        applicationSsin.sin_family      = AF_INET;
        applicationSsin.sin_port        = htons(ri->DstPort);
        applicationSsin.sin_addr.s_addr = inet_addr(ri->DstAddr);
      
        if( connect(ci->appSocket,(struct sockaddr *)&applicationSsin,sizeof(struct sockaddr_in)) == -1 ) {
          ERRNO(pid)
          err=S4REQUEST_REJECTED;
          /*
           * Try connecting to other destinations in case of multiple dns answers
           */
          for(i=1;i<resolvedHostNumber;i++) {
            strncpy(ri->DstAddr,resolvedHostList[i].NextHost,sizeof(ri->DstAddr));
            applicationSsin.sin_addr.s_addr = inet_addr(ri->DstAddr);
       
            if( connect(ci->appSocket,(struct sockaddr *)&applicationSsin,sizeof(struct sockaddr_in)) == 0 ) {
              ERRNO(pid)
              err=S4REQUEST_GRANTED;
              break;
            }
          }
        }
      }
    }
  }
  if( VERBOSE() ) {
    snprintf(logString,128,"[%u] [VERB] Connected to remote host.",pid);
    LOGUPDATE()
  }

  /*
   * Prepare and send socks V4 response
   */
  memset((char *)sd->Response,0,sizeof(sd->Response));
  
  sd->Response[0]=0; //SOCKS4_VERSION;
  sd->Response[1]=err;

  SETADDR(sd->Response,inet_addr(ri->DstAddr),4)
  SETPORT_R(sd->Response,ri->DstPort,2)

  if( send(ci->Socket,sd->Response,8,SS5_SEND_OPT) == -1) {
    ERRNO(pid)
    err=S4REQUEST_REJECTED;
  }

  if( err != S4REQUEST_GRANTED )
     return (-1 * err);
  else
    return OK;
}

UINT BindServing(struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri, struct _SS5Socks5Data *sd)
{
  register int i;

  UINT len;
  IFSELECT( UINT fd; )

  int cb = 0;

  char addr[16];

  char logString[256];

  UINT resolvedHostNumber=1;

  struct _S5HostList resolvedHostList[MAXDNS_RESOLV];

  struct in_addr in;

  IFSELECT( fd_set fdset; )
  IFSELECT( struct timeval tv; )

  struct sockaddr_in applicationSsin,
                     clientBindSsin;

  UINT err=S4REQUEST_GRANTED;

  pid_t pid;

  IFEPOLL( struct epoll_event ev; )
  IFEPOLL( struct epoll_event events[5]; )
  IFEPOLL( int nfds; )
  IFEPOLL( int kdpfd; )

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /*
   * SS5: Resolve hostname before binding 
   */ 
  if( ri->ATyp == DOMAIN ) {
    if( S5ResolvHostName(ri, (struct _S5HostList *)resolvedHostList, &resolvedHostNumber) == ERR ) {
       err=S4REQUEST_REJECTED;
    }
  }

  if( err == S4REQUEST_GRANTED ) {
    /*
     * Create application socket
     */
    if ((ci->appSocket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
      ERRNO(pid)
      err=S4REQUEST_REJECTED;
    }
    else { 
      /*
       * Create client socket for bind
       */
      if ((cb = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        ERRNO(pid)
        err=S4REQUEST_REJECTED;
      }
      else { 
        memset((char *)&clientBindSsin, 0, sizeof(struct sockaddr_in));
        clientBindSsin.sin_family      = AF_INET;
        clientBindSsin.sin_port        = htons(0);

        /*
         * Look for the right interface for binding
         */
        if( S5GetBindIf(ri->DstAddr,addr) == ERR ) {
          /* Match with destination address in socks request */
          clientBindSsin.sin_addr.s_addr = htonl(INADDR_ANY);
        }
        else
          clientBindSsin.sin_addr.s_addr = inet_addr(addr);
      
        /*
         * SS5: set route interface if present
         */ 
        if( ROUTE() ) {
          if( (in.s_addr=(ULINT)GetRoute(inet_network(ci->SrcAddr), inet_network(ri->DstAddr), ci->Username)) )
            if( VERBOSE() ) {
              snprintf(logString,128,"[%u] [VERB] Found route interface.",pid);
              LOGUPDATE()
            }
            clientBindSsin.sin_addr.s_addr = in.s_addr;
        }
      
        if (bind(cb, (struct sockaddr *)&clientBindSsin, sizeof(struct sockaddr_in)) == -1) {
          ERRNO(pid)
          err=S4REQUEST_REJECTED;
        }
        else {
          /*
           * Get clientbind info
           */
          len=sizeof(struct sockaddr);
          getsockname(cb,(struct sockaddr *)&clientBindSsin,&len);
        
          /*
           * SS5: listen for a queue length equal to one
           */ 
          if (listen(cb, 1) == -1) {
            ERRNO(pid)
            err=S4REQUEST_REJECTED;
          }
        }
      }
    }
  }

  /*
   * Send socks response
   */
  memset(sd->Response,0,sizeof(sd->Response));

  sd->Response[0]=0; //SOCKS4_VERSION;
  sd->Response[1]=err;

  SETADDR(sd->Response,clientBindSsin.sin_addr.s_addr,4)
  SETPORT(sd->Response,clientBindSsin.sin_port,2)

  switch( ri->ATyp ) {
    /* 
     *    Socks V4 Header is 8 bytes
     */
    case IPV4:
    case DOMAIN:
      if( send(ci->Socket,sd->Response,8,SS5_SEND_OPT) == -1) {
        ERRNO(pid)
        return (-1 * S4REQUEST_REJECTED);
      }
      break;
    /*
     *    Socks V5 Header is 22 bytes but IPV6 is not supported
     */
    case IPV6:    return (-1 * S4REQUEST_REJECTED);    break;
  }

  if( err == S4REQUEST_GRANTED ) {
    /* 
     * Wait for BIND_TIMEOUT before closing listen port
     */
    if( VERBOSE() ) {
      snprintf(logString,128,"[%u] [VERB] Waiting for remote connection.",pid);
      LOGUPDATE()
    }
    memset((char *)&applicationSsin, 0,sizeof(struct sockaddr_in));
    len = sizeof (struct sockaddr_in);
  
    IFSELECT( FD_ZERO(&fdset); )
    IFSELECT( FD_SET(cb,&fdset); )

    IFSELECT( tv.tv_sec=BIND_TIMEOUT; )
    IFSELECT( tv.tv_usec=0; )

    IFEPOLL( kdpfd=epoll_create(5); )
    IFEPOLL( ev.events = EPOLLIN; )
    IFEPOLL( ev.data.fd = cb; )
    IFEPOLL( epoll_ctl(kdpfd, EPOLL_CTL_ADD, cb, &ev); )

    IFSELECT( if( (fd=select(cb+1,&fdset,NULL,NULL,&tv)) ) { )
    IFEPOLL(  if( (nfds = epoll_wait(kdpfd, events, 5, BIND_TIMEOUT*1000)) ) { )
    IFSELECT( if( FD_ISSET(cb,&fdset) ) { )
    IFEPOLL(  if( events[0].data.fd == cb ) { )
        if ((ci->appSocket = accept(cb, (struct sockaddr *)&applicationSsin, &len)) == -1) {
          ERRNO(pid) 

          IFEPOLL( close(kdpfd); )
          close(cb);
          return (-1 * S4REQUEST_REJECTED);
        }
      }
    }
    else {
      /*
       * Timeout expired accepting connection from remote application
       */
      IFEPOLL( close(kdpfd); )
      close(cb);
      return (-1 * S4REQUEST_REJECTED);
    }

    IFEPOLL( close(kdpfd); )

    if( VERBOSE() ) {
      snprintf(logString,128,"[%u] [VERB] Remote connection accepted.",pid);
      LOGUPDATE()
    }

    /*
    * Socks response packet
    */
    sd->Response[1]=S4REQUEST_GRANTED;

    switch( ri->ATyp ) {
      /*
       *    Socks V4 Header is 8 bytes
       */
      case IPV4:
      case DOMAIN:
        if( send(ci->Socket,sd->Response,8,SS5_SEND_OPT) == -1) {
          ERRNO(pid)
          return (-1 * S4REQUEST_REJECTED);
        }
        break;
      /*
       *    Socks V5 Header is 22 bytes but IPV6 is not supported
       */
      case IPV6:    return (-1 * S4REQUEST_REJECTED);    break;
    }
  }

  if( err != S4REQUEST_GRANTED )
     return (-1 * err);
  else
    return OK;

}


UINT S5GetBindIf( char *s5application, char *s5clientbind )
{
  int index;

  bzero(s5clientbind,16);

  if( (index=S5IfMatch(s5application)) != -1 ) {
    strncpy(s5clientbind,S5Interface[index]->IP,sizeof(S5Interface[index]->IP) - 1);
    return OK;
  }
  return ERR;
}

UINT S5ResolvHostName( struct _SS5RequestInfo *ri, struct _S5HostList *resolvedHostList, UINT *resolvedHostNumber)
{
  register UINT index,count;

  struct addrinfo *result;
  struct addrinfo *res;
  int error;

  char hostname[32], logString[256];

  pid_t pid;

  /*
  * Get child/thread pid
  */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  /* resolve the domain name into a list of addresses */
  if( (error = getaddrinfo(ri->DstAddr, NULL, NULL, &result)) != 0 ) {

    return ERR;
  }
  /*
   * In case of multiple answers, save all
   */
  *resolvedHostNumber=0;
  for (index=0,res = result; res != NULL && index < MAXDNS_RESOLV; res = res->ai_next,index++) {

    if( (error = getnameinfo(res->ai_addr, res->ai_addrlen, hostname, 32, NULL, 0, NI_NUMERICHOST)) == 0 ) {
      if (*hostname && res->ai_family == PF_INET && res->ai_socktype == SOCK_STREAM) {

          strncpy(resolvedHostList[*resolvedHostNumber].NextHost,hostname,sizeof(resolvedHostList[*resolvedHostNumber].NextHost));
          *resolvedHostNumber=*resolvedHostNumber + 1;
      }
    }
  }
  if( result )
    freeaddrinfo(result);

  /* 
   * If request, order dns answers
   */
  if( SS5SocksOpt.DnsOrder ) {
    S5OrderIP(resolvedHostList, resolvedHostNumber);

    if( VERBOSE() ) {
      snprintf(logString,128,"[%u] [VERB] Ordering multiple records dns.",pid);
      LOGUPDATE()

      for(count=0;count<*resolvedHostNumber; count++) {
        snprintf(logString,128,"[%u] [VERB] Resolved %s to %s.",pid,ri->DstAddr,resolvedHostList[count].NextHost);
        LOGUPDATE()
      }
    }
  }

  strncpy(ri->DstAddr,resolvedHostList[0].NextHost,sizeof(ri->DstAddr));

  return OK;
}

UINT S5OrderIP( struct _S5HostList *resolvedHostList, UINT *resolvedHostNumber )
{
  register UINT index;

  UINT swap;
  
  char hostTmp[16];

  do {
    swap=0;
    for(index=0;index<(*resolvedHostNumber)-1;index++)
      if( S5CompIP(resolvedHostList[index].NextHost,resolvedHostList[index+1].NextHost) ) {
        strncpy(hostTmp,resolvedHostList[index+1].NextHost,sizeof(resolvedHostList[index+1].NextHost) - 1);
        strncpy(resolvedHostList[index+1].NextHost,resolvedHostList[index].NextHost,sizeof(resolvedHostList[index].NextHost) - 1);
	strncpy(resolvedHostList[index].NextHost,hostTmp,sizeof(hostTmp) - 1);
	swap=1;
      }
  } while(swap);

  return OK;
}

UINT S5CompIP(char src[16],char dst[16] )
{
 if( (ULINT)inet_network(src) > (ULINT)inet_network(dst) )
    return OK;
  else
    return ERR;
}


UINT S5VerifyBind(struct _SS5ClientInfo *ci, struct _SS5RequestInfo *ri )
{
  if( STREQ(ci->udpSrcAddr,ri->DstAddr,sizeof(ci->udpSrcAddr) - 1) && (ci->udpSrcPort == ri->DstPort) )
    return OK;
  else if ( STREQ(ri->DstAddr,"0.0.0.0",sizeof("0.0.0.0") - 1) && (ci->udpSrcPort == ri->DstPort) )
    return OK;
  else
    return ERR;
}

inline UINT S5IfMatch(char ip[16])
{
  UINT count;

  for(count=0;count<NInterF;count++) {
    if( (ULINT)(inet_network(S5Interface[count]->IP) & inet_network(S5Interface[count]->NetMask)) ==
        (ULINT)(inet_network(ip) & inet_network(S5Interface[count]->NetMask)) )
      return count;
  }

  return -1;
}


inline UINT FileCheck( char *group, char *user )
{
  FILE *groupFile;

  pid_t pid;

  UINT i,l;

  char groupFileName[192];
  char userName[64];

  char logString[128];

   /*
   *    Get child/thread pid
   */
  if( NOTTHREADED() )
    pid=getpid();
  else
    pid=(UINT)pthread_self();

  if( SS5SocksOpt.Profiling == FILE_PROFILING ) {
    strncpy(groupFileName,S5ProfilePath,sizeof(groupFileName));
    STRSCAT(groupFileName,"/");
    STRSCAT(groupFileName,group);

    if( (groupFile = fopen(groupFileName,"r")) == NULL ) {
      ERRNO(pid)
      return ERR;
    }

    /*
     *    Check for username into configuration file for access profile
     */
    while( fscanf(groupFile,"%64s",userName) != EOF ) {
      if( userName[0] != '#' )
        if( STRCASEEQ(userName,user,64) ) {
          fclose(groupFile);
          return OK;
        }
    }
    fclose(groupFile);
    return ERR;
  }
  return ERR;
}


inline UINT S5RouteHash( ULINT sa )
{
  return ( sa % MAXROUTELIST );
}


ULINT GetRoute(ULINT sa, ULINT da, char *uname)
{
  UINT index,nm;
  UINT err = ERR;
  struct _S5RouteNode *node;
  ULINT n_sa;


  /*
   * Look for src route
   */
  for(nm=0;nm<=32;nm +=1) {
    if( nm < 32)
      n_sa=((sa >> nm) << nm);
    else
      n_sa=0;
    index=S5RouteHash( n_sa );

    if( S5RouteList[index] != NULL ) {
      node=S5RouteList[index];

      do {
        if( (node->SrcAddr == n_sa) && (node->Mask == (nm)) && (node->sd == SRC_ROUTE) ) {
  
          if( node->Group[0] != '-' ) {
            /*
             * Look for username into group (file or directory) defined in permit line
             */
            if( SS5SocksOpt.Profiling == FILE_PROFILING )
              err=FileCheck(node->Group,uname);
            else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
              err=DirectoryCheck(node->Group,uname);
            if( err ) {
              return node->SrcIf;
            }
          }
          else
            return node->SrcIf;
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  /*
   * Look for dst route
   */
  for(nm=0;nm<=32;nm +=1) {
    if( nm < 32)
      n_sa=((da >> nm) << nm);
    else
      n_sa=0;
    index=S5RouteHash( n_sa );

    if( S5RouteList[index] != NULL ) {
      node=S5RouteList[index];

      do {
        if( (node->SrcAddr == n_sa) && (node->Mask == (nm)) && (node->sd == DST_ROUTE) ) {
  
          if( node->Group[0] != '-' ) {
            /*
             * Look for username into group (file or directory) defined in permit line
             */
            if( SS5SocksOpt.Profiling == FILE_PROFILING )
              err=FileCheck(node->Group,uname);
            else if( SS5SocksOpt.Profiling == LDAP_PROFILING )
              err=DirectoryCheck(node->Group,uname);
            if( err ) {
              return node->SrcIf;
            }
          }
          else
            return node->SrcIf;
        }
        node=node->next;
      } while(node != NULL );
    }
  }

  return ERR;
}

