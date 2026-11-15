#ifndef PLATFORM_IPF_H
#define PLATFORM_IPF_H
#include "m68k_diagnostics.h"
#include <stddef.h>
#include <stdint.h>
#ifdef _WIN32
#define IPF_API __declspec(dllexport)
#else
#define IPF_API
#endif
#define IPF_NONE UINT32_MAX
/* Source bytes remain immutable and caller-owned. Decoded blocks/sectors are
 * owned by the analysis. Block data is decoded; gap streams are retained by
 * source coordinates, not fabricated into a flattened disk or FDC model. */
typedef struct IpfChunk { char tag[5]; uint32_t offset, size, crc, payload_size; } IpfChunk;
typedef struct IpfBlock {
    uint32_t words[8], descriptor_offset, stream_offset, stream_end, gap_offset;
    uint32_t track_bit_start, decode_status;
    unsigned char *bits;
} IpfBlock;
typedef struct IpfSector {
    uint32_t block_index, id_bit, data_bit, end_bit, size, flags;
    uint16_t id_crc, data_crc;
    uint8_t c,h,r,n,mark;
    unsigned char *data;
} IpfSector;
typedef struct IpfTrack {
    uint32_t image[17], image_offset, data_offset, data_size, data_crc;
    uint32_t block_count, sector_count, incomplete;
    IpfBlock *blocks;
    IpfSector *sectors;
} IpfTrack;
typedef struct IpfAnalysis {
    const unsigned char *data; size_t size;
    uint32_t info[21], info_offset, chunk_count, track_count;
    IpfChunk *chunks; IpfTrack *tracks;
} IpfAnalysis;
enum { IPF_BLOCK_OK=0, IPF_BLOCK_UNSUPPORTED=1, IPF_BLOCK_WEAK=2 };
enum { IPF_SECTOR_ID_CRC=1, IPF_SECTOR_DATA_CRC=2, IPF_SECTOR_NO_DATA=4,
    IPF_SECTOR_DELETED=8, IPF_SECTOR_CLOCK=16, IPF_SECTOR_UNSUPPORTED_SIZE=32 };
enum { IPF_READ_OK=0, IPF_READ_NOT_FOUND=1, IPF_READ_AMBIGUOUS=2,
    IPF_READ_NO_DATA=3, IPF_READ_UNSUPPORTED=4, IPF_READ_STATUS=5 };
IPF_API int ipf_is_image(const unsigned char *data, size_t size);
IPF_API int ipf_analyze(const unsigned char *data, size_t size, IpfAnalysis *out, M68kDiagSink diagnostics);
IPF_API void ipf_destroy(IpfAnalysis *analysis);
/* Explicit physical indexes can identify a stable block even when another
 * block is unsupported. CHRN selection instead requires a complete inventory. */
IPF_API unsigned ipf_read_instance(const IpfAnalysis *analysis, size_t track_index, size_t sector_index,
    const unsigned char **out_data, size_t *out_size);
IPF_API unsigned ipf_read_chrn(const IpfAnalysis *analysis, unsigned track, unsigned side,
    unsigned id_track, unsigned id_head, unsigned id_sector, unsigned id_size,
    const unsigned char **out_data, size_t *out_size);
IPF_API int ipf_inspect_json(const IpfAnalysis *analysis, char **out_json);
#endif
