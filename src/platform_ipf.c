#include "platform_ipf.h"
#include "json_builder.h"
#include "platform_common.h"
#include <stdlib.h>
#include <string.h>
#define IPF_MAX_BYTES (32U*1024U*1024U)
#define IPF_MAX_CHUNKS 4096U
#define IPF_MAX_TRACKS 512U
#define IPF_MAX_BLOCKS 1024U
#define IPF_MAX_TRACK_BITS (2U*1024U*1024U)
#define IPF_DECODE_BUDGET (64U*1024U*1024U)
static uint32_t be32(const unsigned char *p) { return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3]; }
static int fits(size_t s,size_t n,size_t end) { return s<=end && n<=end-s; }
static uint32_t crc32_bytes(const unsigned char *p,size_t n,int header) {
    uint32_t c=UINT32_MAX;size_t i;unsigned j;
    for(i=0;i<n;i++) { c^=(header && i>=8 && i<12)?0:p[i];for(j=0;j<8;j++) c=(c>>1)^((0U-(c&1U))&0xedb88320U); }
    return c^UINT32_MAX;
}
static uint16_t crc16_byte(uint16_t c,unsigned b) {
    unsigned i;c^=(uint16_t)(b<<8);for(i=0;i<8;i++) c=(uint16_t)((c<<1)^((c&0x8000U)?0x1021U:0));return c;
}
int ipf_is_image(const unsigned char *p,size_t n) { return p && n>=4 && !memcmp(p,"CAPS",4); }
void ipf_destroy(IpfAnalysis *a) {
    uint32_t t,b,s;if(!a)return;
    for(t=0;t<a->track_count;t++) {
        IpfTrack *v=&a->tracks[t];
        if(v->blocks)for(b=0;b<v->block_count;b++)free(v->blocks[b].bits);
        if(v->sectors)for(s=0;s<v->sector_count;s++)free(v->sectors[s].data);
        free(v->blocks);free(v->sectors);
    }
    free(a->tracks);free(a->chunks);memset(a,0,sizeof(*a));
}
static unsigned bit(const unsigned char *p,uint32_t n) { return (p[n/8]>>(7-n%8))&1U; }
static void putbit(unsigned char *p,uint32_t *n,unsigned v) { if(v)p[*n/8]|=(unsigned char)(0x80U>>(*n%8));++*n; }
/* Only data streams are expanded. A possibly unspecified first clock cell is
 * never used as a sync mark. Exact gaps, density, splice and flags stay in the
 * source descriptors; this API does not simulate rotational/controller timing. */
static int decode_block(const IpfAnalysis *a,IpfTrack *t,IpfBlock *b,size_t *budget) {
    uint32_t p=b->words[7],out=0,previous=0,limit=b->words[0];
    const unsigned char *data=a->data+t->data_offset;int bit_mode=(b->words[5]&4U)!=0;
    /* CAPS encoder 1 stores byte lengths where SPS encoder 2 stores a gap
     * offset/cell type. See Keir Fraser's official Disk-Utilities
     * libdisk/container/ipf.c, ipf_block and ENC_CAPS, commit
     * aa616ccde1e46b5badb742234a4b90e2c15e5b67. Stream counts are bytes in
     * the supported legacy revision; do not reinterpret SPS flags as sizes. */
    int supported_layout=a->info[1]==1
        ? a->info[2]==1 && b->words[2]==((uint64_t)limit+7U)/8U &&
          b->words[3]==((uint64_t)b->words[1]+7U)/8U && b->words[5]==0
        : a->info[1]==2 && b->words[3]==1 && !(b->words[5]&~7U);
    b->stream_offset=t->data_offset+p;b->stream_end=IPF_NONE;
    if(!limit)return 0;
    if(!supported_layout || b->words[4]!=1 || t->image[2]!=2 || t->image[12]) {
        b->decode_status=IPF_BLOCK_UNSUPPORTED;return 0;
    }
    if(limit>IPF_MAX_TRACK_BITS || !fits(*budget,(limit+7U)/8,IPF_DECODE_BUDGET))return -1;
    *budget+=(limit+7U)/8;b->bits=calloc((limit+7U)/8,1);if(!b->bits)return -1;
    for(;;) {
        uint32_t code,vc,count=0,nbytes,nbits,i;unsigned kind;
        if(p>=t->data_size)return -1;
        code=data[p++];vc=code>>5;kind=code&31U;
        if(vc>4 || !fits(p,vc,t->data_size))return -1;
        for(i=0;i<vc;i++)count=(count<<8)|data[p++];
        if(!kind) { if(count || out!=limit)return -1;b->stream_end=t->data_offset+p;return 0; }
        if(kind==5) { b->decode_status=IPF_BLOCK_WEAK;free(b->bits);b->bits=NULL;return 0; }
        if(kind!=1 && kind!=2 && kind!=3) {
            b->decode_status=IPF_BLOCK_UNSUPPORTED;free(b->bits);b->bits=NULL;return 0;
        }
        if(!count || (!bit_mode && count>UINT32_MAX/8))return -1;
        nbits=bit_mode?count:count*8;nbytes=nbits/8+(nbits%8!=0);
        if(!fits(p,nbytes,t->data_size) || nbits>(limit-out)/(kind==1?1U:2U))return -1;
        for(i=0;i<nbits;i++) {
            unsigned v=bit(data+p,i);
            if(kind!=1)putbit(b->bits,&out,!(previous||v));
            putbit(b->bits,&out,v);previous=v;
        }
        p+=nbytes;
    }
}
static uint16_t word_bits(const unsigned char *p,uint32_t at) {
    uint16_t w=0;unsigned i;for(i=0;i<16;i++)w=(uint16_t)((w<<1)|bit(p,at+i));return w;
}
static unsigned decode_mfm(const unsigned char *p,uint32_t at) {
    unsigned i,b=0;for(i=0;i<8;i++)b=(b<<1)|bit(p,at+2*i+1);return b;
}
static int mfm_clock_ok(const unsigned char *p,uint32_t at,unsigned previous) {
    unsigned i;for(i=0;i<8;i++) { unsigned d=bit(p,at+2*i+1);if(bit(p,at+2*i)!=!(previous||d))return 0;previous=d; }return 1;
}
static int sync_at(const unsigned char *p,uint32_t at) {
    return word_bits(p,at)==0x4489 && word_bits(p,at+16)==0x4489 && word_bits(p,at+32)==0x4489;
}
static int append_sector(IpfTrack *t,IpfSector **out) {
    IpfSector *p;if(t->sector_count>=256)return -1;
    p=realloc(t->sectors,(t->sector_count+1)*sizeof(*p));if(!p)return -1;
    t->sectors=p;*out=&p[t->sector_count++];memset(*out,0,sizeof(**out));return 0;
}
static int scan_block(IpfTrack *t,IpfBlock *b,uint32_t bi,size_t *budget) {
    uint32_t p=0,limit=b->words[0];const unsigned char *raw=b->bits;IpfSector *pending=NULL;
    if(!raw) { if(b->decode_status)t->incomplete=1;return 0; }
    while(p+64<=limit) {
        unsigned mark,i,previous;uint16_t crc;
        if(!sync_at(raw,p)) { ++p;continue; }
        mark=decode_mfm(raw,p+48);
        if(mark==0xfe && p+160>limit) { t->incomplete=1; p+=64; continue; }
        if(mark==0xfe && p+160<=limit) {
            unsigned values[7];
            if(append_sector(t,&pending))return -1;
            pending->block_index=bi;pending->id_bit=p;pending->data_bit=IPF_NONE;pending->end_bit=p+160;pending->flags=IPF_SECTOR_NO_DATA;
            crc=0xffff;for(i=0;i<3;i++)crc=crc16_byte(crc,0xa1);previous=1;
            for(i=0;i<7;i++) { values[i]=decode_mfm(raw,p+48+16*i);crc=crc16_byte(crc,values[i]);if(!mfm_clock_ok(raw,p+48+16*i,previous))pending->flags|=IPF_SECTOR_CLOCK;previous=values[i]&1; }
            pending->c=(uint8_t)values[1];pending->h=(uint8_t)values[2];pending->r=(uint8_t)values[3];pending->n=(uint8_t)values[4];pending->id_crc=(uint16_t)(values[5]<<8|values[6]);
            if(crc)pending->flags|=IPF_SECTOR_ID_CRC;
            if(pending->n<=7)pending->size=128U<<pending->n;
            /* ADLS is a documented IBM-MFM extension. Keep exact CHRN; do not
             * treat arbitrary high size IDs as a masked standard sector. */
            else if(pending->c==247 && pending->h==247 && pending->r>=245 && pending->r<=250 && pending->n==(pending->r==250?246:247))pending->size=pending->r==250?512:1024;
            else pending->flags|=IPF_SECTOR_UNSUPPORTED_SIZE;
            p+=160;continue;
        }
        if((mark==0xfb || mark==0xf8) && pending && !pending->data && pending->size) {
            uint32_t n=pending->size,end;
            if((uint64_t)p+48U+16U*((uint64_t)n+3U)>limit) { p+=64;continue; }
            end=p+48+16*(n+3);
            if(!fits(*budget,n,IPF_DECODE_BUDGET))return -1;
            *budget+=n;
            pending->data=malloc(n);if(!pending->data)return -1;
            pending->data_bit=p;pending->end_bit=end;pending->mark=(uint8_t)mark;pending->flags&=~IPF_SECTOR_NO_DATA;
            if(mark==0xf8)pending->flags|=IPF_SECTOR_DELETED;
            crc=0xffff;for(i=0;i<3;i++)crc=crc16_byte(crc,0xa1);previous=1;
            for(i=0;i<n+3;i++) { unsigned v=decode_mfm(raw,p+48+16*i);crc=crc16_byte(crc,v);if(!mfm_clock_ok(raw,p+48+16*i,previous))pending->flags|=IPF_SECTOR_CLOCK;previous=v&1;
                if(i && i<=n)pending->data[i-1]=(unsigned char)v;
                if(i==n+1)pending->data_crc=(uint16_t)(v<<8);
                if(i==n+2)pending->data_crc|=(uint16_t)v;
            }
            if(crc)pending->flags|=IPF_SECTOR_DATA_CRC;
            p=end;pending=NULL;continue;
        }
        p+=64;
    }
    return 0;
}
int ipf_analyze(const unsigned char *data,size_t size,IpfAnalysis *out,M68kDiagSink diagnostics) {
    IpfAnalysis a={0};size_t pos=0,budget=0;uint32_t i,j;const char *error="invalid IPF header";int have_info=0;
    if(out)memset(out,0,sizeof(*out));
    if(!out || !ipf_is_image(data,size) || size>IPF_MAX_BYTES)goto fail;
    a.data=data;a.size=size;
    while(pos<size) {
        IpfChunk *chunk;uint32_t n,crc;
        error="invalid IPF chunk bounds or CRC";
        if(!fits(pos,12,size) || a.chunk_count>=IPF_MAX_CHUNKS)goto fail;
        n=be32(data+pos+4);crc=be32(data+pos+8);
        if(n<12 || !fits(pos,n,size) || crc32_bytes(data+pos,n,1)!=crc)goto fail;
        for(i=0;i<4;i++)if(!((data[pos+i]>='A'&&data[pos+i]<='Z')||(data[pos+i]>='0'&&data[pos+i]<='9')||data[pos+i]==' '))goto fail;
        chunk=realloc(a.chunks,(a.chunk_count+1)*sizeof(*chunk));if(!chunk)goto fail;a.chunks=chunk;chunk=&a.chunks[a.chunk_count++];memset(chunk,0,sizeof(*chunk));
        memcpy(chunk->tag,data+pos,4);chunk->offset=(uint32_t)pos;chunk->size=n;chunk->crc=crc;
        if(!memcmp(chunk->tag,"CAPS",4)) { if(pos || n!=12)goto fail; }
        else if(!memcmp(chunk->tag,"INFO",4)) {
            if(have_info || n!=96)goto fail;
            have_info=1;a.info_offset=(uint32_t)pos;
            for(i=0;i<21;i++)a.info[i]=be32(data+pos+12+4*i);
        } else if(!memcmp(chunk->tag,"IMGE",4)) {
            IpfTrack *t;if(n!=80 || a.track_count>=IPF_MAX_TRACKS)goto fail;
            t=realloc(a.tracks,(a.track_count+1)*sizeof(*t));if(!t)goto fail;a.tracks=t;t=&a.tracks[a.track_count++];memset(t,0,sizeof(*t));
            t->image_offset=(uint32_t)pos;t->data_offset=IPF_NONE;for(i=0;i<17;i++)t->image[i]=be32(data+pos+12+4*i);
        } else if(!memcmp(chunk->tag,"DATA",4)) {
            uint32_t bytes;if(n!=28)goto fail;bytes=be32(data+pos+12);
            if(!fits(pos+n,bytes,size) || be32(data+pos+16)>((uint64_t)bytes*8) || crc32_bytes(data+pos+n,bytes,0)!=be32(data+pos+20))goto fail;
            chunk->payload_size=bytes;
        }
        pos+=n+chunk->payload_size;
    }
    error="missing or incompatible IPF geometry";
    if(!have_info || !a.track_count || a.info[0]!=1 || a.info[6]>a.info[7] || a.info[8]>a.info[9] || a.info[7]>255 || a.info[9]>1)goto fail;
    for(i=0;i<a.track_count;i++) {
        IpfTrack *t=&a.tracks[i];uint32_t matches=0,k;uint64_t bits=0,databits=0,gapbits=0;
        error="missing or ambiguous IPF DATA identity";
        for(j=0;j<a.chunk_count;j++)if(!memcmp(a.chunks[j].tag,"DATA",4) && be32(data+a.chunks[j].offset+24)==t->image[13]) {
            ++matches;t->data_offset=a.chunks[j].offset+a.chunks[j].size;t->data_size=a.chunks[j].payload_size;t->data_crc=be32(data+a.chunks[j].offset+20);
        }
        if(matches!=1)goto fail;
        error="invalid IPF track/block bounds";
        if(t->image[0]<a.info[6] || t->image[0]>a.info[7] || t->image[1]<a.info[8] || t->image[1]>a.info[9] || t->image[9]>IPF_MAX_TRACK_BITS || t->image[10]>IPF_MAX_BLOCKS || t->image[10]>t->data_size/32)goto fail;
        t->block_count=t->image[10];
        if(t->block_count) { t->blocks=calloc(t->block_count,sizeof(*t->blocks));if(!t->blocks)goto fail; }
        for(k=0;k<t->block_count;k++) {
            IpfBlock *b=&t->blocks[k];b->descriptor_offset=t->data_offset+32*k;
            for(j=0;j<8;j++)b->words[j]=be32(data+b->descriptor_offset+4*j);
            b->gap_offset=IPF_NONE;
            if(a.info[1]==2 && (b->words[5]&3U)) { if(b->words[2]<t->block_count*32 || b->words[2]>=t->data_size)goto fail;b->gap_offset=t->data_offset+b->words[2]; }
            if(b->words[0] && (b->words[7]<t->block_count*32 || b->words[7]>=t->data_size))goto fail;
            b->track_bit_start=t->image[9]?(uint32_t)((t->image[6]+bits)%t->image[9]):0;
            databits+=b->words[0];gapbits+=b->words[1];bits+=b->words[0]+(uint64_t)b->words[1];
            if(a.info[1]!=1 && a.info[1]!=2) { b->decode_status=IPF_BLOCK_UNSUPPORTED;t->incomplete=1;continue; }
            if(decode_block(&a,t,b,&budget) || scan_block(t,b,k,&budget))goto fail;
        }
        if(t->block_count && (databits!=t->image[7] || gapbits!=t->image[8] || bits!=t->image[9]))goto fail;
        if(t->image[2]!=2 || t->image[12])t->incomplete=1;
    }
    *out=a;return 0;
fail:
    ipf_destroy(&a);m68k_diag_add(diagnostics,M68K_DIAG_SEVERITY_ERROR,M68K_DIAG_CODE_PLATFORM_DISK_FAILED,error);return -1;
}
unsigned ipf_read_block(const IpfAnalysis *a,size_t ti,size_t bi,const unsigned char **data,size_t *size) {
    const IpfBlock *b;if(data)*data=NULL;if(size)*size=0;
    if(!a || ti>=a->track_count || bi>=a->tracks[ti].block_count)return IPF_READ_NOT_FOUND;
    b=&a->tracks[ti].blocks[bi];
    if(a->tracks[ti].image[2]!=2 || a->tracks[ti].image[12] ||
       b->decode_status!=IPF_BLOCK_OK || !b->bits || !b->words[0])return IPF_READ_UNSUPPORTED;
    if(data)*data=b->bits;
    if(size)*size=((size_t)b->words[0]+7U)/8U;
    return IPF_READ_OK;
}
unsigned ipf_read_instance(const IpfAnalysis *a,size_t ti,size_t si,const unsigned char **data,size_t *size) {
    const IpfSector *s;if(data)*data=NULL;if(size)*size=0;
    if(!a || ti>=a->track_count || si>=a->tracks[ti].sector_count)return IPF_READ_NOT_FOUND;
    s=&a->tracks[ti].sectors[si];if(s->flags&IPF_SECTOR_NO_DATA)return IPF_READ_NO_DATA;
    if(a->tracks[ti].image[2]!=2 || a->tracks[ti].image[12] || s->flags&IPF_SECTOR_UNSUPPORTED_SIZE)return IPF_READ_UNSUPPORTED;
    if(s->flags)return IPF_READ_STATUS;
    if(!s->data)return IPF_READ_NO_DATA;
    if(data)*data=s->data;
    if(size)*size=s->size;
    return IPF_READ_OK;
}
unsigned ipf_read_chrn(const IpfAnalysis *a,unsigned track,unsigned side,unsigned c,unsigned h,unsigned r,unsigned n,const unsigned char **data,size_t *size) {
    size_t ti,si,found_t=0,found_s=0;unsigned matches=0,tracks=0;
    if(data)*data=NULL;
    if(size)*size=0;
    if(!a)return IPF_READ_NOT_FOUND;
    for(ti=0;ti<a->track_count;ti++)if(a->tracks[ti].image[0]==track && a->tracks[ti].image[1]==side) {
        ++tracks;if(a->tracks[ti].incomplete)return IPF_READ_UNSUPPORTED;
        for(si=0;si<a->tracks[ti].sector_count;si++) { const IpfSector *s=&a->tracks[ti].sectors[si];if(s->c==c&&s->h==h&&s->r==r&&s->n==n) { ++matches;found_t=ti;found_s=si; } }
    }
    if(tracks>1 || matches>1)return IPF_READ_AMBIGUOUS;
    if(!matches)return IPF_READ_NOT_FOUND;
    return ipf_read_instance(a,found_t,found_s,data,size);
}
int ipf_inspect_json(const IpfAnalysis *a,char **out) {
    JsonBuilder b={0};uint32_t ti,bi,si,ci;char hash[65];if(out)*out=NULL;
    if(!out || !a || !a->data || json_builder_create(&b))return -1;
    if(m68k_platform_sha256_hex(a->data,a->size,hash))goto fail;
    if(json_builder_appendf(&b,"{\"platform\":\"physical-disk\",\"format_kind\":\"ipf\",\"filesystem_status\":\"not_analyzed\",\"entry_count\":0,\"entries\":[],\"image_size\":%zu,\"image_sha256\":\"%s\",\"fdc_emulation\":false,\"gaps_expanded\":false,\"timing_source\":\"original bit counts, cell types and gap streams\",\"info_words\":[",a->size,hash))goto fail;
    for(ci=0;ci<21;ci++)if(json_builder_appendf(&b,"%s%u",ci?",":"",a->info[ci]))goto fail;
    if(json_builder_append(&b,"],\"chunks\":["))goto fail;
    for(ci=0;ci<a->chunk_count;ci++) { const IpfChunk *c=&a->chunks[ci];if(json_builder_appendf(&b,"%s{\"tag\":\"%s\",\"offset\":%u,\"size\":%u,\"payload_size\":%u,\"crc\":%u}",ci?",":"",c->tag,c->offset,c->size,c->payload_size,c->crc))goto fail; }
    if(json_builder_append(&b,"],\"tracks\":["))goto fail;
    for(ti=0;ti<a->track_count;ti++) {
        const IpfTrack *t=&a->tracks[ti];
        if(json_builder_appendf(&b,"%s{\"index\":%u,\"track\":%u,\"side\":%u,\"image_offset\":%u,\"data_offset\":%u,\"data_size\":%u,\"density_type\":%u,\"start_bit\":%u,\"track_bits\":%u,\"flags\":%u,\"incomplete\":%s,\"image_words\":[",ti?",":"",ti,t->image[0],t->image[1],t->image_offset,t->data_offset,t->data_size,t->image[2],t->image[6],t->image[9],t->image[12],t->incomplete?"true":"false"))goto fail;
        for(ci=0;ci<17;ci++)if(json_builder_appendf(&b,"%s%u",ci?",":"",t->image[ci]))goto fail;
        if(json_builder_append(&b,"],\"blocks\":["))goto fail;
        for(bi=0;bi<t->block_count;bi++) {
            const IpfBlock *v=&t->blocks[bi];if(json_builder_appendf(&b,"%s{\"index\":%u,\"descriptor_offset\":%u,\"stream_offset\":%u,\"stream_end\":%lld,\"gap_offset\":%lld,\"track_bit_start\":%u,\"decode_status\":%u,\"words\":[",bi?",":"",bi,v->descriptor_offset,v->stream_offset,v->stream_end==IPF_NONE?-1LL:(long long)v->stream_end,v->gap_offset==IPF_NONE?-1LL:(long long)v->gap_offset,v->track_bit_start,v->decode_status))goto fail;
            for(ci=0;ci<8;ci++)if(json_builder_appendf(&b,"%s%u",ci?",":"",v->words[ci]))goto fail;
            if(json_builder_append(&b,"]}"))goto fail;
        }
        if(json_builder_append(&b,"],\"sectors\":["))goto fail;
        for(si=0;si<t->sector_count;si++) {
            const IpfSector *s=&t->sectors[si];if(json_builder_appendf(&b,"%s{\"index\":%u,\"block_index\":%u,\"id_bit\":%u,\"data_bit\":%lld,\"end_bit\":%u,\"id_track\":%u,\"id_head\":%u,\"id_sector\":%u,\"id_size\":%u,\"id_crc\":%u,\"data_crc\":%u,\"size\":%u,\"flags\":%u,\"stable_read_result\":%u",si?",":"",si,s->block_index,s->id_bit,s->data_bit==IPF_NONE?-1LL:(long long)s->data_bit,s->end_bit,s->c,s->h,s->r,s->n,s->id_crc,s->data_crc,s->size,s->flags,ipf_read_instance(a,ti,si,NULL,NULL)))goto fail;
            if(s->data) { if(m68k_platform_sha256_hex(s->data,s->size,hash)||json_builder_appendf(&b,",\"decoded_sha256\":\"%s\"",hash))goto fail; }
            if(json_builder_append(&b,"}"))goto fail;
        }
        if(json_builder_append(&b,"]}"))goto fail;
    }
    if(json_builder_append(&b,"]}"))goto fail;
    *out=json_builder_build(&b);json_builder_destroy(&b);return *out?0:-1;
fail:json_builder_destroy(&b);return -1;
}
