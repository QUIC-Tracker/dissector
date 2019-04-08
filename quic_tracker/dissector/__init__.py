#
#   QUIC-Tracker
#   Copyright (C) 2017-2018  Maxime Piraux
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License version 3
#   as published by the Free Software Foundation.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
import builtins
import os
import struct
import socket
import itertools
from copy import deepcopy

import yaml


def get_root_path():
    return os.path.abspath(os.path.dirname(__file__))


def join_root(*paths):
    return os.path.join(get_root_path(), *paths)


class ParseError(ValueError):
    pass


def parse_packet(buffer, context):
    last_e = None
    for p in sorted(os.listdir(join_root('protocols')), reverse=True):
        with open(join_root('protocols', p)) as f:
            try:
                return p, parse_packet_with(buffer[:], protocol=yaml.load(f), context=context)
            except Exception as e:
                last_e = e
                continue
    raise last_e


def parse_packet_with(buffer, protocol, context):
    top_level = protocol.pop('top')
    last_e = None
    for top_struct in top_level:
        try:
            ret, inc, _ = parse_structure_type(buffer[:], top_struct, protocol, 0, context)
            if inc < len(buffer):
                raise ParseError('There are bytes left unparsed in the buffer')
            return [(top_struct, ('', ret[1], 0, inc), 0, inc)]
        except ParseError as e:
            last_e = e
            pass
    if last_e:
        raise last_e
    return []


def yield_structures(buffer, struct_name, protocol, start_idx, context):
    next_struct = struct_name
    while next_struct and buffer:
        if next_struct not in protocol:
            ret, inc, next_struct = parse_structure_type(buffer, next_struct, protocol, start_idx, context)
            yield ret, inc
        else:
            ret, inc, next_struct = parse_structure(buffer, protocol[next_struct], protocol, start_idx, context)
            yield (struct_name, ret), inc
        buffer = buffer[inc:]
        start_idx += inc


def parse_structure_type(buffer, type_name, protocol, start_idx, context):
    def get_struct_type(structure_description):
        for field, args in (list(d.items())[0] for d in structure_description):
            if field == 'type':
                return args

    structures = []
    for k, v in protocol.items():
        s_type = get_struct_type(v)
        if (type(s_type) == list and type_name in s_type) or type_name == s_type or type_name == k:
            structures.append((k, v))

    for struct_name, struct_description in structures:
        try:
            struct, inc, next_struct = parse_structure(buffer, struct_description, protocol, start_idx, context)
            return (struct_name, struct, start_idx, start_idx + inc), inc, next_struct
        except ParseError as e:
            #print('%s: %s' % (struct_name, e))
            continue
    raise ParseError('No structure could be parsed for type {}, first byte was {}'.format(type_name, buffer[0]))


def parse_structure(buffer, structure_description, protocol, start_idx, context):
    structure = []
    struct_triggers = {}
    i = 0
    previous_len = 0
    next_struct = None
    repeating = False
    successful_repeated = False

    structure_description = deepcopy(list(reversed(structure_description)))
    while structure_description and buffer:
        field, args = list(structure_description.pop().items())[0]
        field_ctx = context.get(field, {})

        if field == 'next':
            next_struct = struct_triggers.get(field, args)
            continue
        elif field == 'type':
            continue

        values = struct_triggers.get(field, {}).get('values', args.get('values', field_ctx.get('values')))
        parse = struct_triggers.get(field, {}).get('parse', args.get('parse', field_ctx.get('parse')))
        conditions = struct_triggers.get(field, {}).get('conditions',args.get('conditions', field_ctx.get('conditions')))
        triggers = struct_triggers.get(field, {}).get('triggers', args.get('triggers', field_ctx.get('triggers')))
        fallback = struct_triggers.get(field, {}).get('fallback', args.get('fallback', field_ctx.get('fallback')))
        length = struct_triggers.get(field, {}).get('length', field_ctx.get('length'))
        if length is not None and 'parse' in args:
            length //= 8
        if length is None:
            length = args.get('length')
        byte_length = struct_triggers.get(field, {}).get('byte_length', args.get('byte_length', field_ctx.get('byte_length')))
        if length is None and byte_length is not None and not parse:
            length = byte_length * 8
        format = struct_triggers.get(field, {}).get('format', args.get('format', field_ctx.get('format')))
        if format in vars(builtins):
            if format == 'hex':
                format = lambda x: hex(x) if type(x) is int else '0x' + x.hex()
            elif format == 'bytes':
                format = lambda x: bytearray(x) if type(x) is not int else x.to_bytes((x.bit_length() // 8) + 1, byteorder='big')
            elif format == 'int':
                format = lambda x: int(x) if type(x) not in (bytearray, bytes) else int.from_bytes(x, 'big')
            elif format == 'ip':
                format = socket.inet_ntoa
            elif format == 'ipv6':
                format = lambda x: socket.inet_ntop(socket.AF_INET6, bytearray(x))
            else:
                format = vars(builtins)[format]
        elif format == 'ip':
            format = socket.inet_ntoa
        elif format == 'ipv6':
            format = lambda x: socket.inet_ntop(socket.AF_INET6, bytearray(x))
        else:
            format = lambda x: x

        if 'repeated' in args and len(buffer) >= length//4:
            repeating = True

        if conditions:
            if not all(verify_condition(structure, field, formula) for c in conditions for field, formula in c.items()):
                continue

        if parse:
            parse_buf = buffer
            if byte_length:
                parse_buf = buffer[:byte_length]

            total_parsed = 0
            for _ in range(length if length is not None else 1):
                try:
                    for ret, inc in yield_structures(parse_buf, parse, protocol, start_idx + i, context):
                        structure.append((field, ret, start_idx + i, start_idx + i + inc))
                        i += inc
                        total_parsed += inc
                        buffer = buffer[inc:]
                        parse_buf = parse_buf[inc:]
                except ParseError as e:
                    if not fallback:
                        raise
                    if parse_buf:
                        if 'byte_length' in struct_triggers.get(field, {}):
                            struct_triggers[field]['byte_length'] = byte_length - total_parsed
                        struct_triggers.get(field, {}).pop('parse', None)
                        structure_description.append({field: fallback})
                        break
            continue
        elif length:
            if length == 'varint':
                val, length = read_varint(buffer)
            elif length == 'pn':
                val, length = read_pn(buffer)
            elif length == '*':
                val = buffer
                length = len(buffer) * 8
            elif length >= 8:
                val = read(buffer, length//8)
            else:
                mask = (0xff << (8 - length)) & 0xff
                val = (buffer[0] & mask) >> (8 - length)
                if previous_len < 8 <= previous_len + length and (previous_len + length) % 8 == 0:
                    length = previous_len + length
                else:
                    buffer = buffer[:]
                    buffer[0] = (buffer[0] << length) & 0xff
                    if previous_len < 8:
                        length = previous_len + length

            try:
                if values is not None:
                    if type(values) is dict:
                        err = ParseError('Value %s for field %s does not fulfill conditions %s' % (str(val), str(field), str(values)))
                        for op, v in values.items():
                            if op == 'eq' and not is_equal(v, val):
                                raise err
                            elif op == 'neq' and is_equal(v, val):
                                raise err
                    elif (type(values) is list and val not in values) or (type(values) is not list and val != values):
                        raise ParseError('Value %s for field %s not acceptable (%s)' % (str(val), str(field), str(values)))
            except ParseError as e:
                if not (repeating and successful_repeated):
                    raise
                continue

            structure.append((field, format(val), start_idx + i, start_idx + i + (length//8 or 1)))

            if length >= 8:
                buffer = buffer[length//8:]
                i += length//8

        if triggers:
            save_to_context = set()
            for trigger_field, actions in itertools.chain.from_iterable(t.items() for t in triggers):
                if 'save_to_context' in actions:
                    save_to_context.add(trigger_field)
                    del actions['save_to_context']

                for attribute, action in actions.items():
                    d = struct_triggers.get(trigger_field, {})
                    if action == 'set':
                        val = format(val)
                        d[attribute] = val * 8 if attribute == 'length' else val
                        if val is 0:
                            structure_description = list(filter(lambda x: next(iter(x.items()))[0] != trigger_field, structure_description))
                    elif action == 'dec':
                        if d.get(attribute) > 0:
                            d[attribute] -= 1
                            if d[attribute] is 0:
                                structure_description = list(filter(lambda x: next(iter(x.items()))[0] != trigger_field, structure_description))
                    elif type(action) is dict:
                        try:
                            d[attribute] = action[val]
                        except KeyError:
                            raise ParseError('Unable to find corresponding value for %d' % val)
                    struct_triggers[trigger_field] = d

            for field in save_to_context:
                context[field] = struct_triggers[field]

        if repeating:
            successful_repeated = True
            structure_description.append({field: args})

        previous_len = length

    if not buffer and not repeating and structure_description:
        for field, args in list(structure_description.pop().items()):
            if field == 'next':
                continue
            field_ctx = context.get(field, {})
            length = struct_triggers.get(field, {}).get('length', field_ctx.get('length', args.get('length')))
            conditions = struct_triggers.get(field, {}).get('conditions', args.get('conditions', field_ctx.get('conditions'))) or []
            if not length or length == '*' or not all(verify_condition(structure, field, formula) for c in conditions for field, formula in c.items()):
                continue
            raise ParseError('The structure has not been fully parsed')

    return structure, i, next_struct


def read(buffer, length):
    _len_to_format_char = {
        1: 'B',
        2: 'H',
        4: 'I',
        8: 'Q',
    }
    if length not in _len_to_format_char or len(buffer) < length:
        if length <= len(buffer):
            return buffer[:length]
        raise ParseError('{} bytes cannot be read from a {}-byte long buffer'.format(length, len(buffer)))
    return struct.unpack('!'+_len_to_format_char.get(length), buffer[:length])[0]


def read_varint(buffer):
    length = 2 ** ((buffer[0] & 0xc0) >> 6)
    varint_buf = buffer[:length]
    varint_buf[0] &= 0x3f
    return read(varint_buf, length), length * 8


def read_pn(buffer):
    pattern = (buffer[0] & 0xc0) >> 6
    if pattern == 0:
        length = 1
    elif pattern == 2:
        length = 2
    elif pattern == 3:
        length = 4
    else:
        raise ParseError('Unknown PN pattern {}'.format(pattern))

    pnbuf = buffer[:length]
    pnbuf[0] &= 0x3f

    return read(pnbuf, length), length * 8


def verify_condition(structure, field, formula):
    for f, v, _, _ in structure:
        if f == field:
            if 'eq' in formula:
                return is_equal(v, formula['eq'])
            elif 'neq' in formula:
                return not is_equal(v, formula['neq'])
            elif 'in' in formula:
                return v in formula['in']
    return False


def is_equal(expected, actual):
    try:
        if type(actual) is int:
            return actual == int(expected, base=0)
    except:
        pass
    return actual == expected

