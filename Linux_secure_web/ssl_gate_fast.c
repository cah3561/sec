#include "ssl_gate_fast.h"
#include <sys/wait.h>
#include <mysql.h>
#include <math.h>

#include <sys/resource.h>

void sig_chld(int);
void sig_close(int);
int listen_fd,sd;

char *decode_dec_db(char *);

void main() 
{
  struct sockaddr_in sa_serv;
  struct sockaddr_in *sa_cli;
  int err=0;
  size_t client_len;
//  int listen_fd,sd;
  const int on=1;
  pid_t childpid;
  
  MYSQL mysql;
  MYSQL_RES *res;
  MYSQL_ROW row;
  char query[256]={0};
//  char msg[256]={0};

//  char *IP;
  int port,cipher,forward;

  char *db_pass;
  char p_buf[512]={0};
  char query_db[512]={0};
  FILE *fp;

  struct rlimit rlim;
  rlim.rlim_cur=20480;
  rlim.rlim_max=20480;
  setrlimit(RLIMIT_NOFILE, &rlim);
//  getrlimit(RLIMIT_NOFILE, &rlim);
//  sprintf(msg,"FILE MAX : %lu : %lu\n", rlim.rlim_cur, rlim.rlim_max);
//  system_log(msg);

sleep(5);
//////////////////////////////// db passwd read ///////////////////////////////////
        fp=fopen("/opt/secuway/tomcat/lib/yourskai/dbpool/dbsetting.txt","r");
        if(fp==NULL) {
                perror("dbsetting.txt open fail");
                return(-1);
        }
        memset(query_db,0x00,512);
        fgets(query_db,512,fp);
        memset(query_db,0x00,512);
        fgets(query_db,512,fp);
        memset(query_db,0x00,512);
        fgets(query_db,512,fp);
        memset(query_db,0x00,512);
        fgets(query_db,512,fp);
        memset(p_buf,0x00,512);
        memcpy(p_buf,&query_db[11],strlen(query_db)-11);
        db_pass=decode_dec_db(p_buf);
        memset(p_buf,0x00,512);
        memcpy(p_buf,&db_pass[4],strlen(db_pass)-4);
        fclose(fp);
//////////////////////////////////////////////////////////////////////////////////




///////////////////////////////// DB init /////////////////////////////////
  mysql_init(&mysql);
  if(!mysql_real_connect(&mysql,NULL,"root",p_buf,NULL,3306,(char *)NULL,0)) {
                perror("DB connect error\n");
                exit(9);
        }
  if(mysql_query(&mysql, "USE ssl_vpn_full")){
        perror("DB not exist\n");
        exit(9);
  }
///////////////////////////////////////////////////////////////////////////


/////////////////////// get sys conf /////////////////////////////////////
  memset(query,0x00,256);
  strcpy(query,"SELECT S_PORT_TDI,S_SESSIONTIMEOUT,S_CIPHER,S_WEB_XFORWARD  FROM SYSTEMCONF WHERE S_ID='1'");

        err=mysql_query(&mysql,query);
        if(err){
                perror("system conf selecting error\n");
                memset(query,0x00,256);
                strcpy(query,"INSERT INTO SYSTEMLOG(E_EVENT,E_DATE) VALUES('TDI:system info loading fail',now())");

                err=mysql_query(&mysql,query);
                if(err) {
                        perror("DB error log inserting error\n");
                        exit(9);
                }
                exit(9);
        }

        res=mysql_use_result(&mysql);
        row=mysql_fetch_row(res);
        if(row==NULL) {
                perror("system conf not exist\n");
                memset(query,0x00,256);
                strcpy(query,"INSERT INTO SYSTEMLOG(E_EVENT,E_DATE) VALUES('TDI:system info loading fail',now())");

                err=mysql_query(&mysql,query);
                if(err) {
                        perror("DB error log inserting error\n");
                        exit(9);
                }
                exit(9);
        }
//        strncpy(IP,row[0],strlen(row[0]));
        port=atoi(row[0]);
	s_timeout=atoi(row[1]);
	if((strcmp(row[2],"BF-CBC"))||(strcmp(row[2],"AES-256-CBC"))) {
		cipher=0;
	}
	else {
		cipher=1;
	}

	forward=atoi(row[3]);
//	IS_NAT=atoi(row[2]);
        mysql_free_result( res ) ;
//  nthreads=DB_getIpPortNthread(IP,&port);
//  if(nthreads==-1) {
//      exit(9);
//  }
#ifdef _DEBUG
  printf("port: %d\n",port);
  printf("s_timeout: %d\n",s_timeout);
  printf("forward: %d\n",forward);
#endif




  /**********************************************************/
  /* prepare TCP connection */
  listen_fd = socket(AF_INET,SOCK_STREAM,0);
  if(listen_fd==-1){
        perror("socket make error\n");
        memset(query,0x00,256);
        strcpy(query,"INSERT INTO SYSTEMLOG(E_EVENT,E_DATE) VALUES('TDI:socket init fail',now())");

        err=mysql_query(&mysql,query);
        if(err) {
                perror("DB error log inserting error\n");
                exit(9);
        }
        exit(1);
  }  
  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

  memset(&sa_serv,0x00,sizeof(sa_serv));
  sa_serv.sin_family = AF_INET;
//  sa_serv.sin_addr.s_addr = inet_addr(IP);
  sa_serv.sin_addr.s_addr = htonl(INADDR_ANY); 
  sa_serv.sin_port = htons(port);
  err = bind(listen_fd,(struct sockaddr*)&sa_serv,sizeof(sa_serv));
  if(err==-1) {
	 perror("bind error\n");
         memset(query,0x00,256);
         strcpy(query,"INSERT INTO SYSTEMLOG(E_EVENT,E_DATE) VALUES('TDI:socket binding fail',now())");

         err=mysql_query(&mysql,query);
         if(err) {
               perror("DB error log inserting error\n");
               exit(9);
         }
         exit(0);
  }

  err = listen(listen_fd,128);
  if(err==-1){
          perror("socket listen error\n");
          memset(query,0x00,256);
          strcpy(query,"INSERT INTO SYSTEMLOG(E_EVENT,E_DATE) VALUES('TDI:socket listen error',now())");

          err=mysql_query(&mysql,query);
          if(err) {
                perror("DB error log inserting error\n");
                exit(9);
          }
          exit(0);
  } 

mysql_close(&mysql);

  signal(SIGCHLD,sig_chld);
  signal(SIGPIPE,SIG_IGN);
  signal(SIGINT,sig_close);
  signal(SIGHUP,sig_close);
  signal(SIGTERM,sig_close);
   
  for(;;) {
	client_len=sizeof(sa_cli);	
  	sd=accept(listen_fd,(struct sockaddr*)&sa_cli,&client_len);
	if(sd<0) {
		perror("accept error\n");
		exit(-1);
	}

	if((childpid=fork())==0) {
		close(listen_fd);
		process_web(sd,s_timeout,cipher,forward);
		exit(0);
	}
close(sd);
  }

}  


void
sig_chld(int signo)
{
	pid_t pid;
	int stat;

	while ((pid = waitpid(-1, &stat, WNOHANG)) > 0);
		//   printf ("child %d terminated \n", pid);

	return;
}

void sig_close(int signo)
{
	close(listen_fd);
	exit(0);
}


char *decode_dec_db(char *b64message)
{
        BIO *bio,*b64,*b64_d,*encode_bio,*decode_bio;
        BUF_MEM *bptr;

        char Decoded[256]={0};
        int err=0;

        unsigned char key[33] = {0};
        unsigned char iv[16] = "0123456789112233";
        unsigned char iv1[16] = "0123456789012345";
        int declen,tmplen;
        unsigned char plain_buf[1024] = {0};

        FILE *fp;
        unsigned char key1[64] = {0};
        unsigned char key2[32] = {0};
        char temp[128]={0};

        char dk[32];

        fp=fopen("/opt/secuway/sslvpn/full/config/.keyfile","r");
        if(fp==NULL) {
                perror(".keyfile open fail");
                return(-1);
        }
        fgets(temp,33,fp);
        strncpy(&key2[0],temp,32);
        fclose(fp);
        fp=fopen("/opt/secuway/sslvpn/full/config/en_key","r");
        if(fp==NULL) {
                perror("en_key open fail");
                return(-1);
        }
        memset(temp,0x00,128);
        fgets(temp,65,fp);
        strncpy(&key1[0],temp,64);
        fclose(fp);

        bio = BIO_new_mem_buf(key1, -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

        err=BIO_read(bio, Decoded, strlen(key1));

        BIO_free_all(bio);

        memset(dk,0x00,32);
        if(!PKCS5_PBKDF2_HMAC(key2,strlen(key2),iv,16,1003,EVP_sha256(),sizeof(dk), dk)){
                perror("PBKDF2 fail\n");
                exit(-1);
        }

        EVP_CIPHER_CTX ctx;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_DecryptInit(&ctx,EVP_aes_256_cbc(),dk,iv1);
        memset(plain_buf,0x00,1024);
        if(!EVP_DecryptUpdate(&ctx, plain_buf, &declen,Decoded, err)) {
                perror("decrypt error\n");
                return(NULL);
        }
        if(!EVP_DecryptFinal(&ctx,plain_buf+declen,&tmplen)) {
                perror("decrypt final error\n");
                return(NULL);
        }
        declen+=tmplen;
        plain_buf[declen] = '\0';
        EVP_CIPHER_CTX_cleanup(&ctx);
        strncpy(&plain_buf[0],"dusr",4);
        strncpy(&key[0],plain_buf,33);

        memset(Decoded,0x00,256);
        bio = BIO_new_mem_buf(b64message, -1);
        b64 = BIO_new(BIO_f_base64());
        bio = BIO_push(b64, bio);
        BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
        err=BIO_read(bio, Decoded, strlen(b64message));
        BIO_free_all(bio);

        memset(plain_buf,0x00,1024);
        declen=0;
        tmplen=0;
        EVP_CIPHER_CTX_init(&ctx);
        EVP_DecryptInit(&ctx,EVP_aes_256_cbc(),key,iv);
        if(!EVP_DecryptUpdate(&ctx, plain_buf, &declen,Decoded, err)) {
                perror("decrypt error\n");
                return(NULL);
        }
        if(!EVP_DecryptFinal(&ctx,plain_buf+declen,&tmplen)) {
                perror("decrypt final error\n");
                return(NULL);
        }
        declen+=tmplen;
        plain_buf[declen] = '\0';
        EVP_CIPHER_CTX_cleanup(&ctx);
        return(plain_buf);
}
