#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
#define BUFFER_LENGTH 2560              ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

int main(){
   int ret, fd;
   char stringToSend[BUFFER_LENGTH]={};
   /*fd = open("/dev/ebbchar", O_RDWR);
   if (fd < 0){
      perror("Failed to open the device...");
      return errno;
   }*/
   FILE *re;
   re = fopen("config.txt","r");
   char ch;
   long long int ip;

   int i = 0,j = 0;
   int a,b,c,d,e;
   char temp[256]={};
   while((ch = fgetc(re))!= EOF){
    if(i<9){
      temp[i]=ch;
    }
    else if (i==9){
      temp[i]=' ';
      strcat(stringToSend,temp);
      printf("%s",temp);
      memset(temp,0,255);
    }
    else{
      if(ch!='_'){
        temp[j]=ch;
        j++;
      }
      else
      {
        sscanf(temp, "%u.%u.%u.%u:%u", &a, &b, &c, &d, &e);
        unsigned long long int ip = a*(256*256*256)+b*(256*256)+c*(256)+d;
        char t[20]={};
        sprintf(t,"%lld:%lld_",ip,e);
        printf("%s\n",t);
        j=0;
      }
    }

 i++;
  }
    //write(fd,stringToSend,strlen(stringToSend));
    printf("%ld",strlen(stringToSend));
}
