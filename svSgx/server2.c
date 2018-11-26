

#include "../test.h"
//#include <openssl/bn.h>
//#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <string.h>
#include <openssl/hmac.h>


void split_first(char *str, char **in, char **end){
  int i=0;
  *in = &str[0];

  for (i=0;str[i]!=' '&&str[i+1]!='\0';i++);
  str[i]='\0';
  *end=str+i+1;
  for (i;str[i]!=' '&&str[i+1]!='\0';i++);
  str[i]='\0';


}

int string_equals(unsigned char* str1, unsigned char* str2){
  int i=0;
  for (;str1[i]!='\0'&&str2[i]!='\0';i++){
    if (str1[i]!=str2[i]){

      return 0;
    }
  }
  return 1;
}

const char* out_file_name(char* id){
  char* file="/sgx_files/client_list/";
  int dir_size=get_string_size(file);
  int id_size=get_string_size(id);
  int size_file=id_size+dir_size+1;
  int i=0;
  int j=0;
  char *file_name= (char*)malloc (size_file*sizeof(char));




  for (i=0;i<dir_size;i++){
    file_name[i]=file[i];
  }

  //printf ("----->%d\n",id_size);

  for (j=0;j<id_size;i++,j++ ){
    file_name[i]=id[j];
  }

  file_name[i]=(char)0;

  return (const char*)file_name;

}

void encrypt( FILE *ofp,FILE *key,FILE *ive,unsigned char *data)
{
    //Get file size



    //set back to normal
    int fsize=get_string_size(data);
    int outLen1 = 0; int outLen2 = 0;

    unsigned char *outdata = malloc(fsize*2);
    unsigned char *ckey = malloc(1 * sizeof(char));
    unsigned char *ivec = malloc(1 * sizeof(char));
    char c;
    int n=1;
    while ((c = fgetc(key)) != EOF)
    {
        n++;
        ckey= (unsigned char *) realloc(ckey, n);
        ckey[n-2]=c;

    }

    n=1;
    while ((c = fgetc(ive)) != EOF)
    {
      n++;
      ivec= (unsigned char *) realloc(ivec, n);
      ivec[n-2]=c;
    }






    //Set up encryption
    EVP_CIPHER_CTX ctx;
    EVP_EncryptInit(&ctx,EVP_aes_128_cbc(),ckey,ivec);
    EVP_EncryptUpdate(&ctx,outdata,&outLen1,data,fsize);
    EVP_EncryptFinal(&ctx,outdata + outLen1,&outLen2);
    fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);

    free((void*)outdata);
    free((void*)ckey);
    free((void*)ivec);

}

unsigned char* decrypt(FILE *ifp, FILE *key,FILE *ive)
{
    //Get file size
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    //set back to normal
    fseek(ifp, 0L, SEEK_SET);

    int outLen1 = 0; int outLen2 = 0;
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize);
    unsigned char *ckey = malloc(1 * sizeof(char));
    unsigned char *ivec = malloc(1 * sizeof(char));
    char c;
    int n=1;
    while ((c = fgetc(key)) != EOF)
    {
        n++;
        ckey= (unsigned char *) realloc(ckey, n);
        ckey[n-2]=c;

    }

    n=1;
    while ((c = fgetc(ive)) != EOF)
    {
      n++;
      ivec= (unsigned char *) realloc(ivec, n);
      ivec[n-2]=c;
    }

    //Read File
    fread(indata,sizeof(char),fsize, ifp);//Read Entire File

    //setup decryption
    EVP_CIPHER_CTX ctx;
    EVP_DecryptInit(&ctx,EVP_aes_128_cbc(),ckey,ivec);
    EVP_DecryptUpdate(&ctx,outdata,&outLen1,indata,fsize);
    EVP_DecryptFinal(&ctx,outdata + outLen1,&outLen2);

    free((void*)indata);
    free((void*)ckey);
    free((void*)ivec);

    return outdata;
    //fwrite(outdata,sizeof(char),outLen1 + outLen2,ofp);


}

void enc_test( char *id, unsigned char *data){
  FILE  *fOUT,*key,*ive;
  const char* name_file=out_file_name(id);



  fOUT = fopen(name_file, "wb"); //File to be written; cipher text
  key=fopen("/sgx_files/fpga_key.txt","rb");
  ive=fopen("/sgx_files/fpga_ivec.txt","rb");



  encrypt(fOUT,key,ive,data);

  fclose(fOUT);
  fclose(key);
  fclose(ive);
  free((void*)name_file);
}




int dec_test(char *id, unsigned char *data){//int substitui o bool que nao tem por padrao
  FILE *fIN, *key,*ive;
  const char* name_file=out_file_name(id);
  fIN = fopen(name_file, "rb");//File to be written; cipher text
  if (!fIN){
    return false;
  }


  key=fopen("/sgx_files/fpga_key.txt","rb");
  ive=fopen("/sgx_files/fpga_ivec.txt","rb");

  unsigned char* decrypted= decrypt(fIN,key,ive);

  fclose(fIN);

  fclose(key);
  fclose(ive);
  free((void*)name_file);

  int is_valid=string_equals(data,decrypted);
  free((void*)decrypted);
  return is_valid;
}


int hmac_test(unsigned char *data){
  FILE *key_file=fopen("/sgx_files/keyhmac.txt","rb");
  unsigned char *ckey = malloc(1 * sizeof(char));

  char c;
  int n=1;
  while ((c = fgetc(key_file)) != EOF)
  {
      n++;
      ckey= (unsigned char *) realloc(ckey, n);
      ckey[n-2]=c;

  }
  ckey[n-1]='\0';

  int is_valid=validade_hmac(ckey,data);
  free(ckey);

  fclose(key_file);
  return is_valid;

}




int get_string_size(char *str){
  int i=0;
  for(i;str[i]!='\0';i++);

  return i;
}

void get_hex_hmac(unsigned char *key,unsigned char *data,char *final_message){

  unsigned char *result;
  int result_len = 32;
  int i;
  static char res_hexstring[32];



  result = HMAC(EVP_sha256(), key, strlen((char *)key), data, strlen((char *)data), NULL, NULL);
  for (i = 0; i < result_len; i++) {
    sprintf(&(res_hexstring[i * 2]), "%02x", result[i]);
  }
  strcat((char *restrict) final_message,  (char *restrict)res_hexstring);
}

char * friendly_hmac(unsigned char* message,unsigned char* id){
  FILE *key_file=fopen("/sgx_files/keyhmac.txt","rb");
  unsigned char *ckey = malloc(1 * sizeof(char));
  //puts((const char*)message);
  char c;
  int n=1;
  while ((c = fgetc(key_file)) != EOF)
  {
      n++;
      ckey= (unsigned char *) realloc(ckey, n);
      ckey[n-2]=c;

  }


  ckey[n-1]='\0';


  int rand_number=rand();
  char str_number[25];
  char* final_message=(char*)calloc(strlen((const char*)message)+120,sizeof(char));
  unsigned char* data=(unsigned char*)calloc(255,sizeof(char));
  sprintf(str_number, "%d:", rand_number);

  strcpy((char * restrict)final_message,(char *restrict)message);
  strcat((char * restrict)final_message, (char * restrict)str_number);
  strcpy((char * restrict)data,(char *restrict)id);
  strcat((char * restrict)data,(char *restrict)str_number);


  get_hex_hmac(ckey,data,final_message);
  //puts((const char*)final_message);
  //puts ((const char*)data);





  //puts((const char*)final_message);
  free (data);
  free(ckey);
  fclose(key_file);
  return final_message;
}

int auth_hmac(unsigned char *key,unsigned char *data ,unsigned char *expected ){


  unsigned char *result;
  int result_len = 32;
  int i;
  static char res_hexstring[32];



  result = HMAC(EVP_sha256(), key, strlen((char *)key), data, strlen((char *)data), NULL, NULL);
  for (i = 0; i < result_len; i++) {
    sprintf(&(res_hexstring[i * 2]), "%02x", result[i]);
  }
  ////printf("-------------\n");
  //puts((const char*)key);
  //puts((const char*)data);
  //puts((const char*)expected);
  //puts((const char*)res_hexstring);
  //printf("-----************------------\n");


  return strcmp((char *) res_hexstring, (char *) expected) == 0;
}

int validade_hmac(unsigned char *key,unsigned char *data){
  int spaces=0;
  unsigned char *p;
  for (p=data;*p!="\0"&&spaces!=4;p++){
    if(*p==' '){
      spaces++;
    }
  }

  if(spaces!=4)
    return 0;

  *(p-1)=(unsigned char)0;
  //puts((const char*)data);
  //printf("---------------------\n");
  //puts((const char*)p);
  //printf("---------------------\n");
  //puts((const char*)key);

  return auth_hmac(key, data,p);

}


void enclave_main()
{
    //enc_test();
    //dec_test();
    srand((unsigned) time(NULL));

    int port = 5566;
    int srvr_fd;
    int clnt_fd;
    char buf[256];
    struct sockaddr_in addr;

    srvr_fd = socket(PF_INET, SOCK_STREAM, 0);

    if (srvr_fd == -1) {
        sgx_exit(NULL);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srvr_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        sgx_exit(NULL);
    }

    if (listen(srvr_fd, 10) != 0) {
        sgx_exit(NULL);
    }

    while (1) {
        int allocated =0;
        char *message;


        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        clnt_fd = accept(srvr_fd, (struct sockaddr *)&addr, &len);
        if (clnt_fd < 0) {
            //puts("ERROR on accept\n");
            continue;
        }

        memset(buf, 0, 256);
        //int n = sgx_read(clnt_fd, buf, 255);
        int n = recv(clnt_fd, buf, 255, 0);

        if (n < 0){
            puts("ERROR on read\n");
            message=(char*)"ERROR on read:";
        }else if(get_string_size(buf)>2){
          char *data,*str=buf+2;
          char op=buf[0];
          char *id;

          //puts (buf);


          ////printf("%c\n",op);
          ////puts(id);
          ////puts(data);
          if (!hmac_test((unsigned char*)buf)){
            message=(char*)"bad format:";
          }else if (op=='0'){

            //printf("------------------------\n");
            //puts((const char*)str);
            split_first(str, &id, &data);


            //puts((const char*)id);
            //puts((const char*)data);

            message=(char*)"Successfully saved:";

            enc_test(id,(unsigned char*)data);
            message=friendly_hmac((unsigned char*)message, (unsigned char*)id);
            allocated=1;
          }else if(op=='1'){


            //puts((const char*)str);
            split_first(str, &id, &data);


            //puts((const char*)id);
            //puts((const char*)data);
            //printf("------------------------\n");


            ////puts(data);
            if(dec_test(id,(unsigned char*)data)){
              message=(char*)"Successfully login:";
              message=friendly_hmac((unsigned char*)message, (unsigned char*)id);

            }
            else{
              message=(char*)"wrong login or password:";
              message=friendly_hmac((unsigned char*)message, (unsigned char*)id);
              allocated=1;

            }
          }else{
            message=(char*)"Unkdown operation:";
          }
        }else{

          message="buff error:";
        }
        //n = sgx_write(clnt_fd, "Successfully received", 21);


        n = send(clnt_fd,message, strlen((const char*)message), 0);

        if (allocated){
          free(message);
        }


        if (n < 0)
            puts("ERROR on write\n");

        close(clnt_fd);

    }



    close(srvr_fd);

    sgx_exit(NULL);
}
