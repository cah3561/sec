#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <mariadb/mysql.h>

#include <openssl/sha.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

char *enc_encode(char *);

int main(void) {
 char content[32];
 long m,n;
 long length;
 char ID[32];
 char PASSWD[30];
 int i,j;

 MYSQL mysql;
 char query[512]={0};

 unsigned char digest[SHA256_DIGEST_LENGTH];
 char mdString[SHA256_DIGEST_LENGTH*2+1];
 SHA256_CTX ctx;

 char *ENC_ID;

 

 /* POST������� ��û�� ���ڿ��� ũ�⸦ ���Ѵ� */
 char *content_len = getenv("CONTENT_LENGTH");

 /* ���ڿ��� ũ��� ���ڿ� �����̹Ƿ� ������ ��ȯ�Ѵ� */
 sscanf(content_len, "%ld", &length);

 /* ǥ���Է½�Ʈ��(stdin)���κ��� ��û ���ڿ��� �о�´� */
 fgets(content, length+2, stdin);

 printf("Content-Type:text/html;charset=euc-kr\n\n");

 printf("<html><head><title> ID,passwd </title></head>\n");
 printf("<body><center>\n");
 printf("<h3>post ��û ID,passwd</h3>\n");

 printf("���޵� �Ķ���� : %s <br>\n ���ڼ� : %d \n", content, strlen(content));

//strcpy(content,"id=foxyfeel&passwd=1234567");
//printf("conntent: %s\n",content);
/* �Ķ������ contents parsing */

 for(i=0;i<=strlen(content);i++) {
	if(strncmp(&content[i],"pass",4)==0) {
		break;
	}
 }

 memset(ID,0x00,32);
 strncpy(ID,&content[3],i-4);

 memset(PASSWD,0x00,30);
 strncpy(PASSWD,&content[i+7],strlen(content)-(i+7));

 printf("<br>ID: %s<br>PASSWD: %s<br>",ID,PASSWD);

 /* openssl sha256 hash */
 SHA256_Init(&ctx);
 SHA256_Update(&ctx, PASSWD, strlen(PASSWD));
 SHA256_Final(digest, &ctx);
 for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
	sprintf(&mdString[i*2], "%02x", digest[i]);
 }
 printf("<br>SHA256 digest: %s<br>", mdString);

 

 /* ID encrypt */
 ENC_ID = enc_encode(ID);





 /* DB insert */
 mysql_init(&mysql);
 if(!mysql_real_connect(&mysql,"127.0.0.1","root","ktz337u962","testdb",3306,(char *)NULL,0)) {
	printf("<br>DB connect error<br>");
	exit(-1);
 }
 if(mysql_query(&mysql, "USE testdb")){
	printf("<br>use DB connect error1<br>");
	exit(-1);
 }
 memset(query,0x00,512);
 sprintf(query,"INSERT INTO user_info(ID,passwd) values('%s','%s')",ENC_ID,mdString);
 if(mysql_query(&mysql,query)) {
	printf("<br>DB insert error<br>");
	exit(-1);
 }
 mysql_close(&mysql);
 

/*
 if(content==NULL) {
  printf("<p>������������ ���޵� �Ķ���� ���ڿ��� �����ϴ�.<br>\n");
  printf("<p>��û���� 2���� ���� �Է��ϰ� �ٽ� �غ�����.<br>\n");
 }
 else if(sscanf(content, "m=%ld&n=%ld", &m, &n)!=2)
  printf("<p>�Ķ������ ���� �����̾�� �մϴ�<br>.\n");
 else
  printf("<p>��� ���: %ld * %ld = %ld.\n", m,n,m*n);
*/
 printf("</center></body>\n");

 return 0;

}

char *enc_encode(char *Encode)
{
        BIO *bio,*b64,*encode_bio;
        BUF_MEM *bptr;

        char *Encoded;
        unsigned char buf[1024]={0};
        int enclen=0;
        int tmplen=0;

        int err=0;

        unsigned char key[32] = "secuwiz1234567890*&^%$#@!sslvpn~";
        EVP_CIPHER_CTX *ctx;
        ctx=EVP_CIPHER_CTX_new();
        EVP_EncryptInit(ctx,EVP_aes_256_cbc(),key,NULL);

        if(!EVP_EncryptUpdate(ctx, buf, &enclen,Encode, strlen(Encode))) {
                perror("encrypt error\n");
                return(NULL);
        }
        if(!EVP_EncryptFinal(ctx,buf+enclen,&tmplen)) {
                perror("encrypt final error\n");
                return(NULL);
        }

        enclen+=tmplen;
/********************************************************************************/
/*              base64 encodeing                                                */
        Encoded=calloc(sizeof(char),256);
        b64=BIO_new(BIO_f_base64());
        bio=BIO_new(BIO_s_mem());
        b64=BIO_push(b64,bio);
        err=BIO_write(b64,buf,enclen);
        BIO_flush(b64);
        BIO_get_mem_ptr(b64,&bptr);


        memcpy(Encoded,bptr->data,bptr->length-1);
        BIO_free_all(bio);
        EVP_CIPHER_CTX_cleanup(ctx);
        return(Encoded);
}
