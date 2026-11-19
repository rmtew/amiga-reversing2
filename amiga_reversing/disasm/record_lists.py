"""Lossless heterogeneous record presentation over one packed primitive owner.

An explicit ordered type schedule reuses ordinary bound record arrays. This is
not a byte parser, type inference, pointer interpretation or overlap override.
"""

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json

from .record_arrays import record_shape, validate_record_array, preserves_primitive_grid

_ELEMENT_KEYS = ('layout_id', 'offset', 'width', 'kind', 'array_count',
                 'array_stride', 'name', 'representation', 'type_binding',
                 'reference_interpretation', 'provenance')
_FIELD_KEYS = {'name', 'type', 'offset', 'size', 'value_kind',
               'pointer_address_domain', 'pointer_symbol_group'}


def record_list_plan(types, runs, layout):
    if not isinstance(types, list) or not types or not isinstance(runs, list) or not runs:
        raise ValueError('record list requires explicit types and ordered runs')
    shapes = {}
    for t in types:
        if (not isinstance(t, Mapping) or set(t) != {'name', 'size', 'fields'}
                or not isinstance(t['fields'], list)
                or any(not isinstance(f, Mapping) or set(f) - _FIELD_KEYS for f in t['fields'])):
            raise ValueError('record list requires flat checked record definitions')
        shape = record_shape(t)
        if shape['name'] in shapes:
            raise ValueError('record list has duplicate type definitions')
        shapes[shape['name']] = shape
    width = layout['source_end'] - layout['source_start']
    normalized, cursor, used = [], 0, set()
    for run in runs:
        if not isinstance(run, Mapping) or set(run) != {'record_type', 'count'}:
            raise ValueError('record list runs require only record_type and count')
        name, count = run['record_type'], run['count']
        if not isinstance(name, str) or name not in shapes or type(count) is not int or not 0 < count <= 0xFFFFFFFF:
            raise ValueError('record list run needs a known type and positive uint32 count')
        size = shapes[name]['size']
        if count > (width - cursor) // size:
            raise ValueError('record list exceeds the complete owner extent')
        used.add(name)
        if normalized and normalized[-1]['record_type'] == name:
            normalized[-1]['count'] += count
        else:
            normalized.append(dict(record_type=name, count=count))
        cursor += size * count
    if cursor != width or used != shapes.keys():
        raise ValueError('record list must consume its owner exactly and use every type')
    identity = dict(layout_id=layout['layout_id'], source_start=layout['source_start'],
                    source_end=layout['source_end'], types=sorted(shapes.values(), key=lambda t: t['name']), runs=normalized)
    list_id = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return shapes, normalized, list_id


def validate_record_list(payload, layout):
    shapes, runs, list_id = record_list_plan(payload['custom_structs'], payload['runs'], layout)
    elements = payload['data_block_elements']
    if not isinstance(elements, list) or len(elements) != len(runs):
        raise ValueError('record list lost its exact ordered partition')
    modes = [(e.get('type_binding') or {}).get('record_list_field_presentation') for e in elements]
    if not (all(mode is None for mode in modes) or all(mode is True for mode in modes)):
        raise ValueError('record list must use one explicit presentation across its partition')
    prior = layout.get('elements', [])
    source = payload['source_array']
    if not isinstance(source, Mapping):
        raise ValueError('record list requires its inspected primitive source array')
    width = layout['source_end'] - layout['source_start']
    unit = source.get('array_stride')
    if (source.get('layout_id') != layout['layout_id'] or source.get('offset') != 0
            or source.get('width') != width or source.get('kind') != 'array'
            or type(unit) is not int or unit not in {1, 2, 4}
            or type(source.get('array_count')) is not int or source['array_count'] * unit != width
            or any(source.get(k) is not None for k in ('type_binding', 'reference_interpretation', 'representation'))
            or layout.get('pointer_table')):
        raise ValueError('record list requires one complete unbound primitive array')
    primitive = len(prior) == 1 and prior[0].get('type_binding') is None
    if primitive:
        if any(prior[0].get(k) != source.get(k) for k in _ELEMENT_KEYS):
            raise ValueError('record list primitive provenance differs from actual prior state')
    elif len(prior) != len(elements):
        raise ValueError('record list cannot replace existing element contracts')
    cursor = 0
    for index, (run, element) in enumerate(zip(runs, elements)):
        shape, count = shapes[run['record_type']], run['count']
        span = shape['size'] * count
        presentation = (element.get('type_binding') or {}).get('record_list_field_presentation')
        if presentation is not None and presentation is not True:
            raise ValueError('record list field presentation must be explicit true or legacy absent')
        if (element.get('layout_id') != layout['layout_id']
                or element.get('offset') != cursor or element.get('width') != span
                or element.get('array_count') != count or element.get('array_stride') != shape['size']
                or not preserves_primitive_grid(shape, unit)):
            raise ValueError('record list must preserve each primitive leaf and exact run extent')
        provenance = dict(record_list_id=list_id, record_list_run=index,
                          record_list_source_array=deepcopy(dict(source)))
        if element.get('provenance') not in (None, provenance):
            raise ValueError('record list partition provenance differs')
        element['provenance'] = provenance
        if index == 0 and source.get('name') is not None:
            if element.get('name') not in (None, source['name']):
                raise ValueError('record list cannot replace its source name')
            element['name'] = source['name']
        if not primitive:
            old = prior[index]
            if old.get('provenance') != provenance:
                raise ValueError('record list cannot reinterpret an existing partition')
            validate_record_array(element, shape, {**layout, 'elements': [old]})
        else:
            validate_record_array(element, shape, {**layout, 'elements': []})
        # Historical declarations retain their original compact projection.
        # New catalog declarations explicitly request the existing field path;
        # preserve that checked presentation update after shape/identity reuse.
        if presentation is True:
            element['type_binding']['record_list_field_presentation'] = True
        cursor += span
    return shapes
