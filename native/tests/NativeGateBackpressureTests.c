#include "NativeGate.h"
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#define TOTAL (512 * 1024)
struct writer { int fd; };
static void *write_then_close(void *opaque) {
    struct writer *w=opaque;
    unsigned char data[8192];
    for (size_t i=0;i<sizeof(data);i++) data[i]=(unsigned char)(i % 251);
    size_t sent=0;
    while(sent<TOTAL) {
        size_t offset=sent % sizeof(data);
        ssize_t n=write(w->fd,data+offset,sizeof(data)-offset);
        if(n<0 && errno==EINTR) continue;
        assert(n>0);sent+=(size_t)n;
    }
    close(w->fd);return NULL;
}
static void scenario(int reverse) {
    ng_gate *g=ng_create();ng_test_enable(g);
    assert(ng_renew(g,1,3000000000ULL)==0);
    int client[2],upstream[2];assert(socketpair(AF_UNIX,SOCK_STREAM,0,client)==0);
    assert(socketpair(AF_UNIX,SOCK_STREAM,0,upstream)==0);
    int small=4096;
    assert(setsockopt(reverse?client[1]:upstream[0],SOL_SOCKET,SO_SNDBUF,&small,sizeof(small))==0);
    assert(ng_test_adopt_pair(g,client[1],upstream[0])==0);
    struct writer w={.fd=reverse?upstream[1]:client[0]};pthread_t writer;
    assert(pthread_create(&writer,NULL,write_then_close,&w)==0);
    usleep(150000); // force relay backpressure before peer closure is observed
    size_t received=0;unsigned char data[8192];int receiver=reverse?client[0]:upstream[1];
    for(;;) {
        ssize_t n=read(receiver,data,sizeof(data));
        if(n<0 && errno==EINTR)continue;
        assert(n>=0);if(!n)break;
        for(ssize_t i=0;i<n;i++) assert(data[i]==(unsigned char)(((received+(size_t)i)%8192)%251));
        received+=(size_t)n;
    }
    pthread_join(writer,NULL);
    assert(received==TOTAL);
    close(receiver);ng_lock(g);ng_destroy(g);
}
int main(void) { alarm(8);scenario(0);scenario(1);puts("bidirectional backpressure and peer-close tests passed");return 0; }
