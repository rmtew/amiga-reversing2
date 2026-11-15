"""The shared native export has one proven retail platform variation."""
import os
from pathlib import Path
import pytest
from tools.build_starglider2_retail_pair import shared_source,build,EXPECTED,ROOT


def test_source_variant_changes_only_the_declared_flag_directive():
 source='section code,code\nplatform_entry_flags:\n\tdc.b $00\nnext:\n dc.b $01\n'
 assert shared_source(source)==source.replace('dc.b $00','dc.b SGII_RETAIL_PLATFORM_HIGH')


@pytest.mark.parametrize('source',[
 'section code,code\n',
 'platform_entry_flags:\n dc.b $80\n',
 'platform_entry_flags:\n dc.b $00\nplatform_entry_flags:\n dc.b $00\n',
])
def test_unrecognized_or_ambiguous_native_source_is_refused(source):
 with pytest.raises(ValueError,match='expected one'):shared_source(source)


@pytest.mark.skipif(not os.getenv('SGII_RETAIL_VASM'),reason='set SGII_RETAIL_VASM to the external assembler')
def test_both_retail_targets_rebuild_from_the_shared_native_export(tmp_path):
 result=build(Path(os.environ['SGII_RETAIL_VASM']),tmp_path/'pair',
              Path(os.environ['SGII_RETAIL_RENDERED_SOURCE']))
 assert {k:v['sha256'] for k,v in result.items()}==EXPECTED
 assert all(v['size']==419308 for v in result.values())
