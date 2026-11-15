"""Bulk seeding preserves mapped-memory bounds, known bytes and write policy."""
import ctypes
import pytest
from amiga_reversing.disasm.mapped_execution import MappedExecution

def bare_memory():
 c=MappedExecution.__new__(MappedExecution)
 c.memory=(ctypes.c_uint8*32)(*([0xa5]*32));c.known=bytearray(32);c.writable=bytearray([1,0]*16);c.failed=False
 return c

@pytest.mark.parametrize('data',(b'\x00\xff\x80',bytearray(b'\x00\xff\x80'),memoryview(b'\x00\xff\x80'),[0,255,128]))
def test_seed_copies_exact_bytes_and_marks_only_seeded_range(data):
 c=bare_memory();policy=bytes(c.writable);c.seed(7,data)
 assert bytes(c.memory)==b'\xa5'*7+b'\x00\xff\x80'+b'\xa5'*22
 assert c.known==bytearray(7)+bytearray(b'\1'*3)+bytearray(22) and bytes(c.writable)==policy
 assert c.read(7,3)==b'\x00\xff\x80'
 with pytest.raises(ValueError,match='unknown'):c.read(6,4)
 c.seed(8,b'XY');assert c.read(7,3)==b'\x00XY'

@pytest.mark.parametrize('address,data',((-1,b'X'),(32,b'X'),(31,b'XX'),(True,b'X')))
def test_invalid_span_does_not_touch_memory_or_policy(address,data):
 c=bare_memory();before=(bytes(c.memory),bytes(c.known),bytes(c.writable))
 with pytest.raises(ValueError,match='outside'):c.seed(address,data)
 assert (bytes(c.memory),bytes(c.known),bytes(c.writable))==before


def test_empty_end_seed_and_failed_state_keep_original_contract():
 c=bare_memory();c.seed(32,b'');assert not any(c.known)
 c.failed=True
 with pytest.raises(ValueError,match='failed execution'):c.seed(0,b'X')
 assert bytes(c.memory)==b'\xa5'*32 and not any(c.known)
