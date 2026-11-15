/* Synthetic parser mutation check. No game bytes are required. */
#include "platform_ipf.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned be32(const unsigned char *p) {
    return (unsigned)p[0]<<24|(unsigned)p[1]<<16|(unsigned)p[2]<<8|p[3];
}
static void put32(unsigned char *p,unsigned v) {
    p[0]=v>>24;p[1]=v>>16;p[2]=v>>8;p[3]=v;
}
static unsigned crc(const unsigned char *p,size_t n,int header) {
    unsigned c=~0U;size_t i;unsigned j;
    for(i=0;i<n;i++) {
        c^=(header && i>=8 && i<12)?0:p[i];
        for(j=0;j<8;j++)c=(c>>1)^((0U-(c&1U))&0xedb88320U);
    }
    return ~c;
}
static void repair(unsigned char *p,size_t n) {
    size_t at=0;
    while(at+12<=n) {
        unsigned len=be32(p+at+4),payload=0;
        if(len<12 || len>n-at)return;
        if(p[at]=='D' && p[at+1]=='A' && p[at+2]=='T' && p[at+3]=='A' && len==28) {
            payload=be32(p+at+12);
            if(payload>n-at-len)return;
            put32(p+at+20,crc(p+at+len,payload,0));
        }
        put32(p+at+8,crc(p+at,len,1));at+=len+payload;
    }
}
static int check(const unsigned char *p,size_t n) {
    IpfAnalysis a={0};M68kDiagList diagnostics={0};unsigned t,s;
    int result=ipf_analyze(p,n,&a,m68k_diag_sink(&diagnostics));
    if(result==0) {
        for(t=0;t<a.track_count;t++)for(s=0;s<a.tracks[t].sector_count;s++) {
            const unsigned char *data=(const unsigned char *)1;size_t size=999;
            if(ipf_read_instance(&a,t,s,&data,&size)==IPF_READ_OK) {
                assert(data && size);{volatile unsigned char last=data[size-1];(void)last;}
            } else assert(!data && !size);
        }
    } else assert(!a.tracks && !a.track_count && !a.chunks);
    ipf_destroy(&a);ipf_destroy(&a);return result;
}
int main(int argc,char **argv) {
    int arg;check(NULL,0);check(NULL,100);
    for(arg=1;arg<argc;arg++) {
        FILE *f=fopen(argv[arg],"rb");long n;unsigned char *p,*copy;size_t i;unsigned b;
        assert(f && !fseek(f,0,SEEK_END));n=ftell(f);assert(n>0 && n<65536);rewind(f);
        p=malloc(n);copy=malloc(n);assert(p && copy);assert(fread(p,1,n,f)==(size_t)n);fclose(f);
        assert(!check(p,n));
        for(i=0;i<=(size_t)n;i++)check(p,i);
        for(i=0;i<(size_t)n;i++)for(b=0;b<8;b++) {
            size_t j;for(j=0;j<(size_t)n;j++)copy[j]=p[j];copy[i]^=1U<<b;
            check(copy,n);repair(copy,n);check(copy,n);
        }
        free(p);free(copy);
    }
    return 0;
}
