#include "ssl_gate_fast.h"
#include <pthread.h>
//#include <mysql.h>
#include <time.h>
#include <fcntl.h>
#include <syslog.h>


void *app_r(void *);
static int application_fd;
static char NAT[1024]={0};
int system_log(char *);
int access_log(char *);
//static int IS_NAT;	

int process_web(int app_sd,int s_timeout,int Cipher,int Forward) 
{

	pthread_t tid;	

	struct sockaddr_in ca;
	int err,res;

	struct sockaddr_in  peeraddr;
	size_t peerlen;
	char *rbuf;

	struct sockaddr_in localaddr;
	size_t locallen;

	char buf[MAX_BUF_SIZE]={0};

	SSL_CTX *ctx;
	SSL_METHOD *ssl_method;
	SSL *ssl;
	static int s_server_session_id_context = 1;

/*	MYSQL mysql;
	MYSQL_RES *Res;
  	MYSQL_ROW row;
*/
  	char query[1024]={0};

	char temp_buf[256]={0};
	char tmp_buf[256]={0};
	char *x_buf;
	char *y_buf;	

	int rsize;
	char *U_ID;
	int port,i,j;
	char *IP;
//	char *IP_port;
	
	time_t *tm;
  	struct tm *tp;

	fd_set set;
  	struct timeval timeout;

	char *nat_ip;


/*	struct hostent *host;
	struct in_addr host_add;
	long int *add;
*/


///////////////////////////////// DB init /////////////////////////////////
/*
  mysql_init(&mysql);
  if(!mysql_real_connect(&mysql,NULL,"root","akfldkelql_38!@",NULL,3306,(char *)NULL,0)) {
                perror("DB connect error\n");
                exit(9);
        }
  if(mysql_query(&mysql, "USE ssl_vpn")){
        perror("DB not exist\n");
        exit(9);
  }
*/
///////////////////////////////////////////////////////////////////////////



///////////////////// peey IP ///////////////////
 peerlen=sizeof(peeraddr);
 err=getpeername(app_sd,(struct sockaddr *)&peeraddr,&peerlen);
          rbuf=calloc(sizeof(char),16);
          rbuf=inet_ntoa(peeraddr.sin_addr);
#ifdef _DEBUG
          printf("peer ip: %s\n",rbuf);
#endif


///////////////////////// prepare ssl connection ////////////////////////////
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
	if(Cipher==0) {
		ssl_method = SSLv23_server_method();
	}
	else {
		ssl_method = TLSv1_server_method();
	}
	ctx = SSL_CTX_new (ssl_method);
	if (!ctx) {
        	 perror("ssl ctx create error\n");
		  system_log("TDI:ssl structure init fail\n");
        	  exit(9);
       	}

	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		perror("certificate import error\n");
		system_log("TDI:certificate import error\n");
          	 exit(3);
        }

	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		perror("private key import error\n");
		system_log("TDI:private key import error\n");
                exit(4);
        }

	if (!SSL_CTX_check_private_key(ctx)) {
      	  perror("Private key does not match the certificate public key\n");
          system_log("TDI:Private key does not match the certificate public key\n"); 	  
          exit(5);
        }		

	SSL_CTX_sess_set_cache_size(ctx,MAX_SSL_CACHE);
	SSL_CTX_set_session_id_context(ctx,(void*)&s_server_session_id_context,sizeof s_server_session_id_context);
	SSL_CTX_set_timeout(ctx,300);
//        SSL_CTX_set_cipher_list(ctx,"ARIA" );

///////////////////////// do server side ssl //////////////////////////////
	ssl = SSL_new(ctx);
	if(ssl==NULL) {
		perror("ssl struct create fail\n");
		system_log("TDI:ssl struct create fail\n");	
		ssl_close(ctx,ssl,app_sd);
		exit(-1);
	}

	err=SSL_set_fd(ssl,app_sd);	
	if(err==-1) {
		perror("ssl handle create fail\n");
		system_log("TDI:ssl handle create fail\n");	
		ssl_close(ctx,ssl,app_sd);
		exit(-1);
	}
	
	SSL_session_reused(ssl);
	err = SSL_accept(ssl);
	if(err==-1) {
		perror("ssl accept fail\n");
		system_log("TDI:ssl accept fail\n");	
		ssl_close(ctx,ssl,app_sd);
		exit(-1);
	}
/*
///////////////////////// SSL request reading //////////////////////////////
        memset(buf,0x00,MAX_BUF_SIZE);
        rsize = SSL_read(ssl,buf,sizeof(buf));
        if(rsize<=0){
                err=SSL_write(ssl,"1",1);
		ssl_close(ctx,ssl,app_sd);
                 exit(0);
        }
#ifdef _DEBUG
        printf("got %d char: \n",rsize);
        printf("%s\n",buf);
#endif
/////////////////////// ssl port attck test//////////////////////////
	if(rsize<5) {
		perror("ssl header parsing error\n");
                        err=SSL_write(ssl,"1",1);
                        ssl_close(ctx,ssl,app_sd);
                        exit(-1);
                }

///////////////////////////////// ssl request header parsing ///////////////
        for(i=5;i<rsize;i++) {
                if(i==(rsize-1)) {
                        perror("ssl header parsing error\n");
                        err=SSL_write(ssl,"1",1);
			ssl_close(ctx,ssl,app_sd);
                        exit(-1);
                }
                if(memcmp(&buf[i]," ",1)==0)
                        break;
        }
        U_ID=calloc(sizeof(char),256);
        memcpy(U_ID,&buf[5],i-5);
        for(j=i+1;j<rsize;j++) {
                if(j==(rsize-1)) {
                        perror("ssl header parsing error\n");
                        err=SSL_write(ssl,"1",1);
			ssl_close(ctx,ssl,app_sd);
                        exit(-1);
                }
                if(memcmp(&buf[j]," ",1)==0)
                        break;
        }
        IP=calloc(sizeof(char),256);
        memcpy(IP,&buf[i+4],j-(i+4));

        memset(temp_buf,0x00,256);
        memcpy(temp_buf,&buf[j+6],rsize-(j+6));
        port=atoi(temp_buf);
*/
	rsize=0;
        memset(buf,0x00,MAX_BUF_SIZE);
        memset(tmp_buf,0x00,256);
        for (;;) {
                rsize = SSL_read(ssl,buf,sizeof(buf));
                if(rsize<=0){
                        err=SSL_write(ssl,"1",1);
                        ssl_close(ctx,ssl,app_sd);
                        exit(0);
                }

        #ifdef _DEBUG
        printf("got %d char: \n",rsize);
        printf("%s\n",buf);
        #endif
        strcat(tmp_buf,buf);
        #ifdef _DEBUG
        printf("%s\n",tmp_buf);
        #endif
                if(rsize>5) {
                        break;
                }
        }

	for(i=5;i<strlen(tmp_buf);i++) {
                if(i==(strlen(tmp_buf)-1)) {
                        perror("ssl header parsing error\n");
                        err=SSL_write(ssl,"1",1);
                        ssl_close(ctx,ssl,app_sd);
                        exit(-1);
                }
                if(memcmp(&tmp_buf[i]," ",1)==0)
                        break;
        }
        U_ID=calloc(sizeof(char),256);
        memcpy(U_ID,&tmp_buf[5],i-5);
        for(j=i+1;j<rsize;j++) {
                if(j==(rsize-1)) {
                        perror("ssl header parsing error\n");
                        err=SSL_write(ssl,"1",1);
                        ssl_close(ctx,ssl,app_sd);
                        exit(-1);
                }
                if(memcmp(&tmp_buf[j]," ",1)==0)
                        break;
        }
        IP=calloc(sizeof(char),256);
        memcpy(IP,&tmp_buf[i+4],j-(i+4));

        memset(temp_buf,0x00,256);
        memcpy(temp_buf,&tmp_buf[j+6],strlen(tmp_buf)-(j+6));
        port=atoi(temp_buf);
/*
	IP_port=calloc(sizeof(char),100);
	strncat(strncat(strncpy(IP_port,IP,strlen(IP)),":",1),temp_buf,strlen(temp_buf));
*/
	if(port!=0) {
        	err=SSL_write(ssl,"0",1);
		if(err==-1) {
			perror("ssl write error\n");
			ssl_close(ctx,ssl,app_sd);
			exit(-1);
		}
	}
#ifdef _DEBUG
printf("\nIP=%s\nport=%d\nU_ID=%s\n",IP,port,U_ID);
#endif

/////////////////// china patch /////////////////////
if(strncmp(IP,"127.0.0.1",9)==0) {
	strcpy(IP,"100.90.90.53");
}
//////////////////////////////////////////////////////////////////////////
///////////////////////////////// NAT setting ///////////////////////////
/*
if((IS_NAT==1)&&(port!=0)) {
        memset(query,0x00,256);
        sprintf(query,"SELECT U_IP FROM USERINFO WHERE U_EMAIL='%s'",U_ID);
	err=mysql_query(&mysql,query);
	if(err){
		fprintf(stderr,"user ip selecting error\n");
		ssl_close(ctx,ssl,app_sd,mysql);
		exit(-1);
	}
	Res=mysql_use_result(&mysql);
	row=mysql_fetch_row(Res);
	if(row==NULL) {
		fprintf(stderr,"user ip not exist\n");
		ssl_close(ctx,ssl,app_sd,mysql);
		exit(-1);
	}
	if(strlen(row[0])==0) {
		mysql_free_result( Res ) ;
		fprintf(stderr,"user ip not exist\n");
                ssl_close(ctx,ssl,app_sd,mysql);
                exit(-1);
	}
	nat_ip=calloc(18,sizeof(char));
	strncpy(nat_ip,row[0],strlen(row[0]));	
	mysql_free_result( Res ) ;
}
*/
//////////////////////////////// Do access control ////////////////////////
/*


       	memset(query,0x00,1024);
       	sprintf(query,"SELECT U_ACCESSTIME FROM USERINFO WHERE U_EMAIL='%s'",U_ID);

       	err=mysql_query(&mysql,query);
       	if(err) {
		perror("accesstime not exsist\n");
		goto another_auth;
//             	perror("DB access time selecting error\n");
//		ssl_close(ctx,ssl,app_sd,mysql);
//             	exit(-1);
	
       	}

       	Res=mysql_use_result(&mysql);
       	row=mysql_fetch_row(Res);
       	if(row==NULL) {
               	perror("DB access time not exist\n");
               	mysql_free_result( Res ) ;
		goto another_auth;

//               	memset(query,0x00,1024);
//               	sprintf(query,"INSERT INTO ACCESSLOG(A_ID,A_SERVERIP,A_PORT,A_EVENT,A_TYPE,A_DATE) VALUES('%s','%s',%d,'%s',%d,NULL)",U_ID,IP,port,DENY,UNABLE_ACCESS_CONTROL,0);
//               	err=mysql_query(&mysql,query);
//               	if(err) {
//               	 	perror("DB access log inserting error\n");
//               	}
//		ssl_close(ctx,ssl,app_sd,mysql);
//               	exit(-1);
//       	}
       	tm=(time_t *)calloc(sizeof(time_t),100);
       	time(tm);
       	tp=localtime(tm);
       	if(strncmp(&row[0][tp->tm_hour],"0",1)!=0) {
               	perror("current time is not accessable\n");
               	mysql_free_result( Res ) ;

               	memset(query,0x00,1024);
               	sprintf(query,"INSERT INTO ACCESSLOG(A_ID,A_SERVERIP,A_PORT,A_EVENT,A_TYPE,A_DATE,A_CLIENTIP) VALUES('%s','%s',%d,'%s',%d,NULL,'%s')",U_ID,IP,port,DENY,ACCESS_TIME_VIOLATION,rbuf);
               	err=mysql_query(&mysql,query);
               	if(err) {
                       	perror("DB access log inserting error\n");
               	}
		ssl_close(ctx,ssl,app_sd,mysql);
               	exit(-1);
       	}
       	mysql_free_result( Res ) ;
////////////////////////////////////////////////////////////////////////////
another_auth:
*/




///////////////////////// updating accesslog /////////////////////////////
//        	memset(query,0x00,1024);
//        	sprintf(query,"%s,%s,%d,%s\n",U_ID,IP,port,rbuf);
//		access_log(query);
//        	err=mysql_query(&mysql,query);
//        	if(err) {
//                	perror("DB access log inserting error\n");
//			ssl_close(ctx,ssl,app_sd,mysql);
//                	exit(-1);
//        	}
//		syslog(LOG_INFO|LOG_USER,"%s,%s,%d,%s",U_ID,IP,port,rbuf);

////////////////////////////////////////////////////////////////////////////



	application_fd=socket(AF_INET,SOCK_STREAM,0);
        if(application_fd==-1) {
                perror("socket error\n");
		ssl_close(ctx,ssl,app_sd);
                exit(-1);
        }
	memset(&localaddr,0x00,sizeof(localaddr));
	localaddr.sin_family = AF_INET;
	localaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  	localaddr.sin_port = htons(0);
	err = bind(application_fd,(struct sockaddr*)&localaddr,sizeof(localaddr));
	if(err==-1) {
		perror("local bind error\n");
		ssl_close(ctx,ssl,app_sd);
                exit(-1);
	}
	
/*	if(IS_NAT==1) {
        	err=getsockname(application_fd,(struct sockaddr *)&localaddr,&locallen);
        	err=ntohs(localaddr.sin_port);
#ifdef _DEBUG
printf("local port:%d\n",err);
#endif

        	memset(NAT,0x00,512);
        	sprintf(NAT,"iptables -t nat -A POSTROUTING -p tcp --sport %d -d %s --dport %d -j SNAT --to %s",err,IP,port,nat_ip);
        	setuid(0);
        	system(NAT);
	}

	mysql_close(&mysql);	
*/

	memset(&ca,0x00,sizeof(ca));
        ca.sin_family = AF_INET;

		ca.sin_addr.s_addr = inet_addr (IP);
//		ca.sin_addr.s_addr = inet_addr ("127.0.0.1");
//		ca.sin_port        = htons     (8888);
		ca.sin_port        = htons     (port);

        	res=connect(application_fd, (struct sockaddr*) &ca, sizeof(ca));
        	if(res<0) {
                	perror("connect error2\n");
			ssl_close(ctx,ssl,app_sd);
                	exit(-1);
        	}



///////////////////////// updating accesslog /////////////////////////////
        	memset(query,0x00,1024);
        	sprintf(query,"%s,%s,%d,%s\n",U_ID,IP,port,rbuf);
		access_log(query);
//        	err=mysql_query(&mysql,query);
//        	if(err) {
//                	perror("DB access log inserting error\n");
//			ssl_close(ctx,ssl,app_sd,mysql);
//                	exit(-1);
//        	}
//		syslog(LOG_INFO|LOG_USER,"%s,%s,%d,%s",U_ID,IP,port,rbuf);

////////////////////////////////////////////////////////////////////////////
/*
	err=getsockname(application_fd,(struct sockaddr *)&localaddr,&locallen);
        err=ntohs(localaddr.sin_port);
#ifdef _DEBUG
printf("local port:%d\n",err);
#endif
	memset(query,0x00,256);
	sprintf(query,"iptables -t nat -A POSTROUTING -p tcp --sport %d -d %s --dport %d -j SNAT --to 10.10.10.10",err,IP,port);
	setuid(0);
        system(query);
*/

/*
	err=write(application_fd,buf,rsize);
        if(err<0) {
	        perror("to serv write error\n");
	        shutdown(application_fd,SHUT_WR);
                ssl_close(ctx,ssl,app_sd,mysql);
//                                exit(-1);
        }
*/

	pthread_create(&tid,NULL,app_r,(void *)ssl);

//	FD_ZERO(&set);
//        FD_SET(app_sd,&set);
//        timeout.tv_sec = 10;
//        timeout.tv_usec =0;

        for(;;) {

		

		memset(&buf,0x00,65535);
                err=SSL_read(ssl,buf,sizeof(buf));
                if(err<0) {
	               	perror("cli read error\n");
			shutdown(application_fd,SHUT_WR);
			ssl_close(ctx,ssl,app_sd);
                }
                if(err==0) {
	                perror("disconnect cli1\n");
                        shutdown(application_fd,SHUT_WR);
                        ssl_close(ctx,ssl,app_sd);
                }

///////////////////////// x-forwarded-for process ////////////////////////////

		if(Forward==1) {
			x_buf=calloc(sizeof(char),65535);
			x_buf=qStrReplace("sn",buf,"Host: ","");
			if(strlen(buf)!=strlen(x_buf)) {
				memset(&temp_buf,0x00,256);
				sprintf(temp_buf,"Alive\nX-Forwarded-For: %s",rbuf);
				y_buf=calloc(sizeof(char),65535);
				y_buf=qStrReplace("sn",buf,"Alive",temp_buf);
				err=write(application_fd,y_buf,err+19+strlen(rbuf));
			}
			else {
				err=write(application_fd,buf,err);
			}
		}
		else {
			err=write(application_fd,buf,err);
		}


#ifdef _DEBUG
//                printf("\napplication client send: %s\n%d\n",buf,err);
                printf("\napplication client send: %d\n",err);
#endif


//                err=write(application_fd,buf,err);
                if(err<0) {
	                perror("to serv write error\n");
			shutdown(application_fd,SHUT_WR);
                        ssl_close(ctx,ssl,app_sd);
                }
#ifdef _DEBUG
                printf("to http server write done \n");
#endif
	}
}



void *app_r(void *ssl_sd)
{
	char buf1[65535]={0};
	int err;

	fd_set set;
        struct timeval timeout;

	FD_ZERO(&set);
        FD_SET(application_fd,&set);
        timeout.tv_sec = s_timeout;
        timeout.tv_usec =0;

	for(;;) {
		memset(buf1,0x00,65535);
		err=select(FD_SETSIZE,&set,NULL,NULL,&timeout);
		if(err==1) {
//			err=read(application_fd,buf1,sizeof(buf1));
			err=recv(application_fd,buf1,sizeof(buf1),NULL);
			if(err<0) {
                        	perror("serv read error\n");
				shutdown((SSL *)ssl_sd,SHUT_WR);
                        	application_close();
                	}
                	if(err==0) {
                        	 perror("disconnect serv1\n");
                               	 shutdown((SSL *)ssl_sd,SHUT_WR);
				 application_close();
                	}

//			fcntl(application_fd, F_SETFL, O_NONBLOCK);
		
#ifdef _DEBUG
//                	printf("application server send: %s\n%d\n",buf1,err);
                	printf("application server send: %d\n",err);
#endif

                	err=SSL_write((SSL *)ssl_sd,buf1,err);
                	if(err<0) {
                        	perror("cli write error\n");
				shutdown((SSL *)ssl_sd,SHUT_WR);
                        	application_close();
                	}
#ifdef _DEBUG
     			printf("to localproxy write done\n");
#endif

		}
		else {
			perror("serv disconnect2\n");
			shutdown((SSL *)ssl_sd,SHUT_WR);
			application_close();
		}

        }
	return(NULL);
}


int ssl_close(SSL_CTX *Ctx,SSL *Ssl,int fd)
{
	char *str;
	SSL_shutdown(Ssl);
/*
	if(IS_NAT==1) {
		str=qStrReplace("sr",NAT,"-A","-D");
		setuid(0);
                system(NAT);
//		qFree();
	}
*/		
//	mysql_close(&Mysql);
//	close(fd);
//	SSL_CTX_free(Ctx);
	exit(0);
}

int application_close()
{
/*
	char *str;
	if(IS_NAT==1) {
                str=qStrReplace("sr",NAT,"-A","-D");
                setuid(0);
                system(NAT);
                qFree();
        }
*/
	exit(0);
}

int system_log(char *log)
{
	FILE *fp;

	fp=fopen("/opt/secuway/sslvpn/full/config/full.log","a");
	system("date '+%Y-%m-%d %H:%M:%S'>>/opt/secuway/sslvpn/full/config/full.log");
	
	fputs(log,fp);
	fclose(fp);

	return;
}

int access_log(char *log)
{
	FILE *fp;

	fp=fopen("/opt/secuway/sslvpn/full/config/tdi_access.log","a");
	
	fputs(log,fp);
	fclose(fp);

	return;
}
