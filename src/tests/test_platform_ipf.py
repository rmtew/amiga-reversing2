"""IPF container and stored-MFM reads, using synthetic redistributable media.

No claims about FDC timing, reconstructed gaps or whole-machine boot.
"""
from __future__ import annotations
import binascii
import ctypes as C
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path
import struct
import unittest
import zlib
import zipfile
from src.tests._platform_disk_test_utils import PlatformDiskTestCaseMixin, _diag_has_errors
from amiga_reversing.disasm.mapped_execution import assemble_ipf_blocks, assemble_ipf_sectors
from amiga_reversing.disasm.stx_recovery import inspect_ipf, recover_ipf, read_ipf


def chunk(tag, data=b'', payload=b''):
    raw = tag + struct.pack('>II', 12+len(data), 0) + data
    raw = raw[:8]+struct.pack('>I', zlib.crc32(raw))+raw[12:]
    return raw+payload


def mfm(data, previous=1):
    result=bytearray()
    for value in data:
        word=0
        for shift in range(7,-1,-1):
            bit=(value>>shift)&1
            word=(word<<2)|((not(previous or bit))<<1)|bit
            previous=bit
        result+=word.to_bytes(2,'big')
    return bytes(result)


def marked(mark, data, bad_crc=False):
    body=bytes([mark])+data
    crc=binascii.crc_hqx(b'\xa1'*3+body,65535) ^ int(bad_crc)
    return bytes.fromhex('448944894489')+mfm(body+crc.to_bytes(2,'big'))


def sample(kind, data, count=None):
    count=len(data) if count is None else count
    n=max(1,(count.bit_length()+7)//8)
    return bytes([(n<<5)|kind])+count.to_bytes(n,'big')+data


def fixture(*, body=b'A'*128, chrn=(0,0,1,0), mark=251, id_bad=False, data_bad=False,
            duplicate=False, weak=False, density=2, flags=0, encoder=2, gap=False,
            bit_mode=False, no_data=False, stream_override=None, extra_weak=False,
            legacy_layout=False, bad_legacy_size=False, encoder_revision=1):
    raw=marked(254,bytes(chrn),id_bad)
    if not no_data: raw+=marked(mark,body,data_bad)
    if duplicate:raw*=2
    if bit_mode:
        shifted=(int.from_bytes(raw,'big')<<7).to_bytes(len(raw)+1,'big')
        stream=sample(1,shifted,len(raw)*8+1)+b'\0';bits=len(raw)*8+1
    else:
        stream=sample(1,raw)+b'\0';bits=len(raw)*8
    if weak:stream=sample(5,b'')+b'\0'
    if stream_override is not None:stream=stream_override
    gap_stream=b'\x21\x01\x4e\0' if gap and not legacy_layout else b''
    words=[bits,16 if gap else 0,32 if gap else 0,1,1,(4 if bit_mode else 0)|(1 if gap else 0),0,32+len(gap_stream)]
    if legacy_layout:
        words[2:4]=[(bits+7)//8+int(bad_legacy_size),2 if gap else 0]
        words[5]=4 if bit_mode else 0
    descriptors=struct.pack('>8I',*words)
    if extra_weak:
        words[7]+=32
        if gap:words[2]+=32
        descriptors=struct.pack('>8I',*words)+struct.pack('>8I',16,0,0,1,1,0,0,words[7]+len(stream))
    payload=descriptors+gap_stream+stream+(sample(5,b'')+b'\0' if extra_weak else b'')
    total_bits=bits+(16 if extra_weak else 0)
    im=[0,0,density,1,0,0,0,total_bits,words[1],total_bits+words[1],2 if extra_weak else 1,0,flags,1,0,0,0]
    info=[1,encoder,encoder_revision,3000,1,0,0,0,0,0,0,0,1,2,0,0,0,0,0,0,0]
    return (chunk(b'CAPS')+chunk(b'INFO',struct.pack('>21I',*info))+
            chunk(b'IMGE',struct.pack('>17I',*im))+
            chunk(b'DATA',struct.pack('>4I',len(payload),len(payload)*8,zlib.crc32(payload),1),payload))


class IpfTests(PlatformDiskTestCaseMixin, unittest.TestCase):
    def test_legacy_caps_sizes_and_exact_packed_cells_without_gap_fabrication(self):
        data=fixture(encoder=1,legacy_layout=True,gap=True)
        a=inspect_ipf(data);t=a['tracks'][0];block=t['blocks'][0]
        raw=marked(254,b'\0\0\1\0')+marked(251,b'A'*128)
        self.assertEqual(block['words'][2:4],[len(raw),2])
        self.assertEqual(block['decode_status'],0)
        self.assertEqual(block['gap_offset'],-1)
        self.assertFalse(a['gaps_expanded']);self.assertFalse(a['fdc_emulation'])
        self.assertEqual(assemble_ipf_blocks(data,[(0,0)],len(raw)),raw)
        self.assertEqual(assemble_ipf_blocks(data,[(0,0),(0,0)],2*len(raw)),raw*2)
        self.assertEqual(assemble_ipf_sectors(data,[(0,0)],128),b'A'*128)

    def test_legacy_layout_flags_revision_and_sizes_are_not_sps_aliases(self):
        for kwargs in [dict(bad_legacy_size=True),dict(bit_mode=True),dict(encoder_revision=2)]:
            with self.subTest(kwargs=kwargs):
                data=fixture(encoder=1,legacy_layout=True,**kwargs)
                a=inspect_ipf(data)
                self.assertEqual(a['tracks'][0]['blocks'][0]['decode_status'],1)
                with self.assertRaises(ValueError):assemble_ipf_blocks(data,[(0,0)],4096)

    def test_block_reads_are_bounded_and_all_or_none(self):
        data=fixture()
        for pairs,limit in [([(0,0)],1), ([(0,0),(0,1)],4096), ([(999,0)],4096),
                            ([],4096), ([(True,0)],4096), ([(0,-1)],4096)]:
            with self.subTest(pairs=pairs,limit=limit):
                with self.assertRaises(ValueError):assemble_ipf_blocks(data,pairs,limit)
        for kwargs in [dict(weak=True),dict(density=3),dict(flags=1)]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):assemble_ipf_blocks(fixture(**kwargs),[(0,0)],4096)

    def test_block_reads_retain_partial_byte_packing_and_explicit_sibling_identity(self):
        data=fixture(bit_mode=True)
        raw=marked(254,b'\0\0\1\0')+marked(251,b'A'*128)
        expected=(int.from_bytes(raw,'big')<<7).to_bytes(len(raw)+1,'big')
        self.assertEqual(assemble_ipf_blocks(data,[(0,0)],len(expected)),expected)
        self.assertEqual(inspect_ipf(data)['tracks'][0]['blocks'][0]['words'][0],len(raw)*8+1)
        sibling=fixture(extra_weak=True)
        self.assertEqual(assemble_ipf_blocks(sibling,[(0,0)],len(raw)),raw)
        with self.assertRaises(ValueError):assemble_ipf_blocks(sibling,[(0,1)],4096)

    def test_implied_first_clock_is_a_documented_convention_not_splice_evidence(self):
        values=bytes([0x42])*144
        data=fixture(stream_override=sample(2,values)+b'\0')
        self.assertEqual(assemble_ipf_blocks(data,[(0,0)],288),mfm(values,previous=0))
        self.assertNotEqual(mfm(values,previous=0),mfm(values,previous=1))

    def test_legacy_gap_samples_are_literal_mfm_data_before_raw_sync(self):
        # Official Copperline v1.1.0 src/ipf.rs documents data-stream types
        # 2 and 3 as literal unencoded bytes, both MFM-expanded. This is not
        # a descriptor gap stream, nor a count of one repeated fill byte.
        sync=bytes.fromhex('44894489')
        values=bytes([0x58])*129
        stream=sample(3,bytes(13))+sample(1,sync)+sample(2,values)+b'\0'
        data=fixture(encoder=1,legacy_layout=True,stream_override=stream)
        expected=mfm(bytes(13),previous=0)+sync+mfm(values,previous=1)
        self.assertEqual(len(expected),288)
        self.assertEqual(assemble_ipf_blocks(data,[(0,0)],288),expected)

    def inspect_failure(self,data):
        raw=(C.c_ubyte*len(data)).from_buffer_copy(data)
        result=self.library.platform_disk_inspect_buffer_json(b'atari-st-disk',raw,len(data))
        try:
            self.assertTrue(_diag_has_errors(result.diagnostics))
            self.assertFalse(result.text)
        finally:self.library.platform_disk_free_text(result.text)

    def test_stable_physical_read_and_both_platform_routes(self):
        data=fixture(gap=True)
        for platform in ['atari-st-disk','amiga-disk']:
            a=self.inspect_disk_buffer(platform,data)
            self.assertEqual(a['format_kind'],'ipf')
            self.assertFalse(a['fdc_emulation']);self.assertFalse(a['gaps_expanded'])
            t=a['tracks'][0];s=t['sectors'][0];block=t['blocks'][0]
            self.assertEqual(s['stable_read_result'],0)
            self.assertEqual(s['decoded_sha256'],hashlib.sha256(b'A'*128).hexdigest())
            self.assertNotIn('offset',s)
            self.assertEqual(block['gap_offset'],t['data_offset']+32)
            self.assertEqual(block['words'][1],16)
        self.assertEqual(assemble_ipf_sectors(data,[(0,0)],128),b'A'*128)
        with self.assertRaisesRegex(ValueError,'bound'):assemble_ipf_sectors(data,[(0,0)],127)
        with self.assertRaises(ValueError):assemble_ipf_sectors(data,[(0,0),(0,9)],4096)

    def test_exceptional_sectors_preserved_and_not_silently_read(self):
        for kw,flag in [(dict(id_bad=True),1),(dict(data_bad=True),2),(dict(no_data=True),4),
                        (dict(mark=248),8),(dict(chrn=(0,0,1,240)),32)]:
            with self.subTest(kw=kw):
                data=fixture(**kw);s=inspect_ipf(data)['tracks'][0]['sectors'][0]
                self.assertTrue(s['flags']&flag)
                with self.assertRaises(ValueError):assemble_ipf_sectors(data,[(0,0)],4096)

    def test_unsupported_streams_and_density_retained(self):
        for kw,status in [(dict(weak=True),2),(dict(density=3),1),(dict(flags=1),1),
                          (dict(encoder=1),1),(dict(stream_override=sample(4,b'X')+b'\0'),1)]:
            with self.subTest(kw=kw):
                t=inspect_ipf(fixture(**kw))['tracks'][0]
                self.assertTrue(t['incomplete']);self.assertEqual(t['blocks'][0]['decode_status'],status)
                self.assertEqual(t['sectors'],[])

    def test_bit_mode_and_nonbyte_sync(self):
        data=fixture(bit_mode=True);s=inspect_ipf(data)['tracks'][0]['sectors'][0]
        self.assertEqual((s['id_bit'],s['flags']),(1,0))
        self.assertEqual(assemble_ipf_sectors(data,[(0,0)],128),b'A'*128)

    def test_adls_size_extension_requires_exact_documented_identity(self):
        for r,n,length in [(245,247,1024),(250,246,512)]:
            data=fixture(body=b'Z'*length,chrn=(247,247,r,n))
            self.assertEqual(assemble_ipf_sectors(data,[(0,0)],2048),b'Z'*length)
        for chrn in [(246,247,245,247),(247,247,249,246),(0,0,1,247)]:
            s=inspect_ipf(fixture(chrn=chrn))['tracks'][0]['sectors'][0]
            self.assertTrue(s['flags']&32)

    def test_duplicate_identity_retained_and_recovery_refuses_guess(self):
        data=fixture(duplicate=True);a=inspect_ipf(data)
        self.assertEqual(len(a['tracks'][0]['sectors']),2)
        self.assertEqual(assemble_ipf_sectors(data,[(0,1)],128),b'A'*128)
        plan=dict(schema_version=1,kind='ipf_cpu_recovery',image_sha256=a['image_sha256'],memory_size=4096,
                  evidence='synthetic fixture',inputs=[dict(id='x',track_start=0,track_count=1,side=0,
                  sector_ids=[1],id_track=0,id_head=0,id_sizes=[0])],actions=[])
        with self.assertRaisesRegex(ValueError,'ambiguous'):recover_ipf(data,plan)

    def test_chrn_selection_refuses_hidden_candidates_in_unsupported_blocks(self):
        data=fixture(extra_weak=True);a=inspect_ipf(data)
        self.assertTrue(a['tracks'][0]['incomplete'])
        # An explicit known instance can be read. A CHRN query cannot prove
        # uniqueness when another block could contain the same identity.
        self.assertEqual(assemble_ipf_sectors(data,[(0,0)],128),b'A'*128)
        plan=dict(schema_version=1,kind='ipf_cpu_recovery',image_sha256=a['image_sha256'],memory_size=4096,
                  evidence='synthetic fixture',inputs=[dict(id='x',track_start=0,track_count=1,side=0,
                  sector_ids=[1],id_track=0,id_head=0,id_sizes=[0])],actions=[])
        with self.assertRaisesRegex(ValueError,'incomplete'):recover_ipf(data,plan)

    def test_container_crc_payload_crc_truncation_and_bad_stream_bounds(self):
        good=fixture()
        for n in [0,4,11,12,107,108,187,188,len(good)-1]:self.inspect_failure(good[:n])
        for i in [9,24,130,210,len(good)-1]:
            bad=bytearray(good);bad[i]^=1;self.inspect_failure(bytes(bad))
        for stream in [b'\x21\xff',b'\x21\x01\xff\0',b'\0',b'\xe1'+b'\xff'*7]:
            self.inspect_failure(fixture(stream_override=stream))

    def test_clock_error_preserves_data_but_refuses_stable_read(self):
        raw=bytearray(marked(254,bytes([0,0,1,0]))+marked(251,b'A'*128))
        raw[6]^=128  # Clock cell only. Decoded ID and its CRC remain unchanged.
        data=fixture(stream_override=sample(1,raw)+b'\0')
        sector=inspect_ipf(data)['tracks'][0]['sectors'][0]
        self.assertEqual(sector['flags'],16)
        with self.assertRaises(ValueError):assemble_ipf_sectors(data,[(0,0)],128)

    def test_private_archive_selection(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'disk.zip'
            with zipfile.ZipFile(path,'w') as archive:archive.writestr('disk.ipf',fixture())
            data,origin=read_ipf(path)
            self.assertEqual(data,fixture());self.assertEqual(origin['member'],'disk.ipf')
            with zipfile.ZipFile(path,'a') as archive:archive.writestr('other.ipf',fixture())
            with self.assertRaisesRegex(ValueError,'select one'):read_ipf(path)
            self.assertEqual(read_ipf(path,'disk.ipf')[0],fixture())

    @unittest.skipUnless(os.getenv('SGII_IPF_IMAGE'), 'set SGII_IPF_IMAGE to the private SPS 3000 input')
    def test_retail_st_handoff_opt_in(self):
        root=Path(__file__).resolve().parents[2]
        data,_=read_ipf(Path(os.environ['SGII_IPF_IMAGE']))
        plan=json.loads((root/'targets/starglider2_retail/recovery_plan.json').read_text())
        report,outputs=recover_ipf(data,plan)
        self.assertEqual(report['kind'],'ipf_cpu_recovery_result')
        self.assertEqual(len(outputs['main_at_st_handoff.bin']),419308)
        self.assertEqual(hashlib.sha256(outputs['main_at_st_handoff.bin']).hexdigest(),
                         '20c19400180d7e846b78aa615b68446293f8ca54015c4f4a42a77f03b24e8260')
        mapping=report['inputs']['main_dma']['source_ranges']
        self.assertEqual(len(mapping),450)
        self.assertTrue(all(x['source_kind']=='ipf_data_block' and 'image_offset' not in x for x in mapping))

    def test_mfm_sample_decoding(self):
        # Stream data samples use native MFM expansion rather than raw bit copy.
        header=bytes([254,0,0,1,0]);hc=binascii.crc_hqx(b'\xa1'*3+header,65535).to_bytes(2,'big')
        body=bytes([251])+b'A'*128;dc=binascii.crc_hqx(b'\xa1'*3+body,65535).to_bytes(2,'big')
        sync=bytes.fromhex('448944894489')
        stream=sample(1,sync)+sample(2,header+hc)+sample(1,sync)+sample(2,body+dc)+b'\0'
        for encoder,legacy in [(2,False),(1,True)]:
            self.assertEqual(assemble_ipf_sectors(fixture(stream_override=stream,encoder=encoder,legacy_layout=legacy),[(0,0)],128),b'A'*128)


    @unittest.skipUnless(os.getenv('IPF_SANITIZERS'), 'set IPF_SANITIZERS=1 for ASan/UBSan mutations')
    def test_native_mutations(self):
        root=Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as temp:
            exe=Path(temp)/'ipf-sanitize'
            backend=root/'src/build'
            subprocess.run(['cc','-std=c11','-g','-Wall','-Wextra','-Werror',
                '-fsanitize=address,undefined','-Isrc','src/platform_ipf.c','src/m68k_diagnostics.c',
                'src/tests/ipf_sanitizer_driver.c','-L'+str(backend),'-lamiga_backend',
                '-Wl,-rpath,'+str(backend),'-o',str(exe)],cwd=root,check=True)
            paths=[]
            for i,data in enumerate([fixture(),fixture(gap=True),fixture(bit_mode=True),fixture(weak=True),
                                     fixture(encoder=1,legacy_layout=True),
                                     fixture(encoder=1,legacy_layout=True,bad_legacy_size=True)]):
                path=Path(temp)/f'{i}.ipf';path.write_bytes(data);paths.append(str(path))
            subprocess.run([str(exe),*paths],check=True,timeout=45)


if __name__=='__main__':unittest.main()
