"""Converged native selector proofs feed callback discovery, not render text."""
import pytest

from amiga_reversing.disasm import c_backend
from tests.test_base_candidates import candidate_artifact
from tests.test_typed_index_symbol_compensation import exact


def fixture(*, selector=None, cells=None, domain='mapped_source', count=9, pointer=True, prefix=''):
    selector = selector if selector is not None else ''' move.w d0,d1
 andi.w #$0f00,d1
 lsr.w #8,d1
 add.w d1,d1
 add.w d1,d1
 cmpi.w #32,d1
 bls.w selected
 moveq #32,d1
selected:
'''
    cells = cells or ['first','second']*4+['first']
    code=' lea.l cells(pc),a4\n lea.l view(pc),a0\n'+prefix+selector+''' move.l 0(a4,d1.w),6(a0)
 movea.l 6(a0),a1
 jsr (a1)
 rts
cells: dc.l '''+','.join(cells)+'''
view: dcb.b 12,0
first: moveq #7,d0
 rts
second: moveq #9,d0
 rts
'''
    field={'name': 'drawAddress','type': 'APTR'if pointer else'LONG','offset': 0,'size': 4}
    if pointer:field.update(value_kind='target_pointer',pointer_address_domain=domain)
    raw,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',' SECTION code,code\n ORG 0\n'+code)
    start=len(raw)-4*len(cells)-12-8
    entities=[]
    for n in range(count):
        e={'hunk': 0,'addr': start+4*n,'end': start+4*n+4,'type': 'data','unit': 'long','name': 'cells'if n==0 else None,
               'struct_name': 'Cell','field_name': 'drawAddress','field_type': field['type'],'c_type': field['type'],
               'seed_origin': 'manual_analysis','review_status': 'seeded','citation': 'Synthetic checked source owner'}
        if pointer:e.update(value_kind='target_pointer',pointer_address_domain=domain)
        if n==0:e.update(source_owner_start=start,source_owner_size=4*count)
        entities.append(e)
    return code,{'custom_structs': [{'name': 'Cell','size': 4,'fields': [field]}],'seeded_entities': entities}


def calls(a):
    rows=a.query_payload('instructions',limit=100)['items'];site=next(r['source_offset']for r in rows if r['mnemonic']=='jsr')
    return a.query_payload('edges',source_offset=site,direction='outgoing',limit=100)['items']


@pytest.mark.parametrize('branch', ['bls.w', 'ble.w'])
def test_clamped_source_pointer_selector_reaches_control_discovery(tmp_path, branch):
    code,metadata=fixture()
    code=code.replace('bls.w selected', branch+' selected')
    with candidate_artifact(tmp_path,code,[],metadata) as (a,raw):
        accesses=a.analysis_payload()[0]['sections'][0]['recovered_platform_typed_accesses']
        source=next(r for r in accesses if r['root_struct_name']=='Cell')
        assert source['word_index']['index_domain']['upper_bound']==32
        edges=calls(a)
        assert len([e for e in edges if e['kind']=='call'and e['status']=='resolved'])==2
        assert any(e['kind']=='call'and e['status']=='unresolved'for e in edges)
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('updates',[
    {'count':8},
    {'domain':'legacy'},
    {'prefix':' movea.l d3,a4\n'},
    {'prefix':' movea.l d3,a0\n'},
    {'cells':['cells']*9},
    {'selector':' move.w d0,d1\n'},
    {'selector':' move.w d0,d1\n andi.w #$0f00,d1\n lsr.w #8,d1\n add.w d1,d1\n add.w d1,d1\n'},
    {'selector':' move.w d0,d1\n cmpi.w #32,d1\n ble.w selected\n moveq #32,d1\nselected:\n'},
    {'selector':' move.w d0,d1\n andi.w #$0f00,d1\n lsr.w #8,d1\n add.w d1,d1\n add.w d1,d1\n cmpi.w #32,d1\n bls.w selected\n moveq #32,d1\nselected: move.w d3,d1\n'},
    {'pointer':False},
    {'cells':['first']*8+['0']},
    {'cells':['first']*8+['$700000']},
])
def test_unproved_or_incompatible_source_read_does_not_admit_targets(tmp_path,updates):
    code,metadata=fixture(**updates)
    with candidate_artifact(tmp_path,code,[],metadata) as (a,raw):
        assert not [e for e in calls(a)if e['kind']=='call'and e['status']=='resolved']
        exact(a,raw,tmp_path)


def test_store_value_fixed_point_is_not_limited_to_eight_source_passes(tmp_path):
    count=12
    code=(' lea.l slots(pc),a0\n lea.l callback(pc),a1\n'
          +f' move.l a1,{4*(count-1)}(a0)\n bra.w link{count-1}\n')
    for n in range(1,count):
        code+=f'link{n}: move.l {4*n}(a0),{4*(n-1)}(a0)\n bra.w '+('dispatch'if n==1 else f'link{n-1}')+'\n'
    code+='dispatch: movea.l 0(a0),a1\n jsr (a1)\n rts\ncallback: moveq #7,d0\n rts\nslots: dcb.b 48,0\n'
    with candidate_artifact(tmp_path,code,[]) as (a,raw):
        edges=calls(a)
        assert len([e for e in edges if e['kind']=='call'and e['status']=='resolved'])==1
        assert any(e['kind']=='call'and e['status']=='unresolved'for e in edges)
        exact(a,raw,tmp_path)


def test_newly_admitted_body_can_supply_the_next_selector_proof(tmp_path):
    code,metadata=fixture(cells=['first']*9)
    original,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',' SECTION code,code\n ORG 0\n'+code)
    code=code.replace('first: moveq #7,d0\n rts\n','first: bsr.w loader\n rts\n')
    second_start=len(original)+2
    selector=''' move.w d0,d1
 andi.w #$0f00,d1
 lsr.w #8,d1
 add.w d1,d1
 add.w d1,d1
 cmpi.w #32,d1
 bls.w other_selected
 moveq #32,d1
other_selected:
'''
    code+='othercells: dc.l '+','.join(['third']*9)+'''\notherview: dcb.b 12,0
loader: lea.l othercells(pc),a4
 lea.l otherview(pc),a0
'''+selector+''' move.l 0(a4,d1.w),6(a0)
 movea.l 6(a0),a1
 jsr (a1)
 rts
third: moveq #11,d0
 rts
'''
    import copy
    others=copy.deepcopy(metadata['seeded_entities'])
    first_start=others[0]['addr']
    for e in others:
        e['addr']+=second_start-first_start;e['end']+=second_start-first_start
        if 'source_owner_start'in e:e['source_owner_start']=second_start;e['name']='othercells'
    metadata['seeded_entities']+=others
    with candidate_artifact(tmp_path,code,[],metadata) as (a,raw):
        rows=a.query_payload('instructions',limit=100)['items']
        sites=[r['source_offset']for r in rows if r['mnemonic']=='jsr']
        assert len(sites)==2
        for site in sites:
            edges=a.query_payload('edges',source_offset=site,direction='outgoing',limit=100)['items']
            assert len([e for e in edges if e['kind']=='call'and e['status']=='resolved'])==1
            assert any(e['kind']=='call'and e['status']=='unresolved'for e in edges)
        exact(a,raw,tmp_path)


def append_fixture(rows, *, reset=True, clobber=False):
    code,metadata=fixture()
    original,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',' SECTION code,code\n ORG 0\n'+code)
    old_start=metadata['seeded_entities'][0]['addr']
    code=code.replace(' move.l 0(a4,d1.w),6(a0)', ''' move.w d0,(a0)+
 move.w d0,(a0)+
 move.w d0,(a0)+
 move.l 0(a4,d1.w),(a0)+
 move.w d0,(a0)+''')
    if rows>1:
        code=code.replace(' move.w d0,d1',f' moveq #{rows-1},d2\nappend:\n move.w d0,d1',1)
        code=code.replace(' movea.l 6(a0),a1', ' dbf d2,append\n lea.l view(pc),a0\n movea.l 6(a0),a1')
    else:code=code.replace(' movea.l 6(a0),a1',' lea.l view(pc),a0\n movea.l 6(a0),a1')
    if not reset:code=code.replace(' lea.l view(pc),a0\n movea.l 6(a0),a1',' movea.l 6(a0),a1')
    if clobber:code=code.replace(' move.w d0,(a0)+',' movea.l d3,a0\n move.w d0,(a0)+',1)
    code=code.replace('dcb.b 12,0',f'dcb.b {12*rows},0')
    raw,_=c_backend.assemble_platform_source_text_with_c_backend('amiga-raw',' SECTION code,code\n ORG 0\n'+code)
    start=len(raw)-36-12*rows-8
    for e in metadata['seeded_entities']:
        e['addr']+=start-old_start;e['end']+=start-old_start
        if 'source_owner_start'in e:e['source_owner_start']=start
    return code,metadata


@pytest.mark.parametrize('rows',[1,16])
def test_checked_source_values_flow_into_postincrement_record_appends(tmp_path,rows):
    code,metadata=append_fixture(rows)
    with candidate_artifact(tmp_path,code,[],metadata) as (a,raw):
        assert len([e for e in calls(a)if e['kind']=='call'and e['status']=='resolved'])==2
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('updates',[{'reset':False},{'clobber':True}])
def test_store_witness_is_not_a_postloop_receiver_or_an_unknown_owner(tmp_path,updates):
    code,metadata=append_fixture(16,**updates)
    with candidate_artifact(tmp_path,code,[],metadata) as (a,raw):
        assert not [e for e in calls(a)if e['kind']=='call'and e['status']=='resolved']
        exact(a,raw,tmp_path)


@pytest.mark.parametrize('initial',['first','0'])
def test_known_source_cell_stores_are_not_lost_to_an_initial_image_read(tmp_path,initial):
    code,metadata=fixture(selector=' moveq #0,d1\n',cells=[initial]*9,
                          prefix=' lea.l second(pc),a2\n move.l a2,0(a4)\n')
    with candidate_artifact(tmp_path,code,[],metadata) as (a,raw):
        edges=calls(a);known=[e for e in edges if e['kind']=='call'and e['status']=='resolved']
        # Initial contents are candidates, not a constness/liveness claim. The
        # validated cell write must also reach the actual consumed field.
        assert len(known)==(2 if initial=='first'else 1)
        assert any(e['kind']=='call'and e['status']=='unresolved'for e in edges)
        exact(a,raw,tmp_path)


def test_missing_source_owner_does_not_get_a_control_selector_proof(tmp_path):
    code,metadata=fixture()
    metadata['seeded_entities'][0].pop('source_owner_start')
    metadata['seeded_entities'][0].pop('source_owner_size')
    with candidate_artifact(tmp_path,code,[],metadata) as (a,raw):
        assert not [e for e in calls(a)if e['kind']=='call'and e['status']=='resolved']
        exact(a,raw,tmp_path)


def test_bounded_data_read_without_a_control_consumer_does_not_admit_code(tmp_path):
    code,metadata=fixture()
    code=code.replace(' jsr (a1)',' move.l a1,d3')  # Same instruction extent.
    with candidate_artifact(tmp_path,code,[],metadata) as (a,raw):
        start=metadata['seeded_entities'][0]['addr']
        first=int.from_bytes(raw[start:start+4],'big')
        assert first not in {r['source_offset']for r in a.query_payload('instructions',limit=100)['items']}
        exact(a,raw,tmp_path)
