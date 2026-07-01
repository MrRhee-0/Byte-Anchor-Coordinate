import argparse
import hashlib
import json
from pathlib import Path
import sys


MAGIC = b"BACR"
VERSION = 1

OP_CONST = 1
OP_LINE = 2
OP_CURVE = 3
OP_PERIOD = 4
OP_CALL = 5
OP_JOIN = 6

OP_NAMES = {
    OP_CONST: "CONST",
    OP_LINE: "LINE",
    OP_CURVE: "CURVE",
    OP_PERIOD: "PERIOD",
    OP_CALL: "CALL",
    OP_JOIN: "JOIN",
}


class DecodeError(Exception):
    pass


class Reader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def remaining(self):
        return len(self.data) - self.offset

    def read_byte(self):
        if self.offset >= len(self.data):
            raise DecodeError("unexpected end of input")
        value = self.data[self.offset]
        self.offset += 1
        return value

    def read_bytes(self, count):
        if count < 0 or self.offset + count > len(self.data):
            raise DecodeError("unexpected end of input")
        value = self.data[self.offset : self.offset + count]
        self.offset += count
        return value

    def read_varuint(self):
        shift = 0
        value = 0
        while True:
            byte = self.read_byte()
            value |= (byte & 0x7F) << shift
            if byte < 0x80:
                return value
            shift += 7
            if shift > 70:
                raise DecodeError("varuint is too long")

    def read_signed(self):
        return zigzag_decode(self.read_varuint())


def read_input_bytes(path):
    with open(path, "rb") as handle:
        data = handle.read()
    return data


def write_bytes(path, data):
    with open(path, "wb") as handle:
        handle.write(data)


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).digest()


def validate_decoded_packet(
    decoded,
    original_length,
    original_sha256,
    root_rule_id,
    rules,
    h_value_count,
    relation_packet_length,
    reader,
):
    if len(decoded) != original_length:
        raise DecodeError("decoded length does not match header")

    if sha256_bytes(decoded) != original_sha256:
        raise DecodeError("decoded sha256 does not match header")

    if reader.remaining() != 0:
        raise DecodeError("trailing bytes after BACR payload")

    return {
        "data": decoded,
        "original_length": original_length,
        "original_sha256": original_sha256,
        "root_rule_id": root_rule_id,
        "rules": rules,
        "h_value_count": h_value_count,
        "relation_packet_size": relation_packet_length,
    }


def encode_varuint(value):
    if value < 0:
        raise ValueError("varuint cannot encode a negative integer")
    encoded = []
    while True:
        byte = value & 0x7F
        value = value >> 7
        if value:
            encoded.append(byte | 0x80)
        else:
            encoded.append(byte)
            break
    return bytes(encoded)


def varuint_size(value):
    return len(encode_varuint(value))


def zigzag_encode(value):
    if value >= 0:
        return value * 2
    return (-value * 2) - 1


def zigzag_decode(value):
    if value % 2 == 0:
        return value // 2
    return -((value + 1) // 2)


def encode_signed(value):
    return encode_varuint(zigzag_encode(value))


def signed_size(value):
    return varuint_size(zigzag_encode(value))


def bytes_to_bgh(data):
    b_values = list(data)
    g_values = []
    h_values = []
    for index in range(len(b_values) - 1):
        g_values.append(b_values[index + 1] - b_values[index])
    for index in range(len(g_values) - 1):
        h_values.append(g_values[index + 1] - g_values[index])
    return b_values, g_values, h_values


def const_length(values, start):
    end = start + 1
    while end < len(values) and values[end] == values[start]:
        end += 1
    return end - start


def line_length(values, start):
    if start + 1 >= len(values):
        return 1
    step = values[start + 1] - values[start]
    end = start + 2
    while end < len(values) and values[end] - values[end - 1] == step:
        end += 1
    return end - start


def curve_length(values, start):
    if start + 2 >= len(values):
        return 1
    second_step = values[start + 2] - (2 * values[start + 1]) + values[start]
    end = start + 3
    while end < len(values):
        next_second = values[end] - (2 * values[end - 1]) + values[end - 2]
        if next_second != second_step:
            break
        end += 1
    return end - start


def period_candidate(values, start, max_period):
    best_period = 0
    best_count = 0
    remaining = len(values) - start
    limit = min(max_period, remaining // 2)
    for period_length in range(2, limit + 1):
        count = period_length
        while count < remaining:
            if values[start + count] != values[start + (count % period_length)]:
                break
            count += 1
        if count >= period_length * 2 and count >= 8:
            if count > best_count:
                best_period = period_length
                best_count = count
    return best_period, best_count


def rule_key(rule):
    op_tag = rule[0]
    if op_tag == OP_PERIOD or op_tag == OP_JOIN:
        return (op_tag, tuple(rule[1]), rule[2]) if op_tag == OP_PERIOD else (op_tag, tuple(rule[1]))
    return tuple(rule)


def add_rule(rules, rule_index, rule):
    key = rule_key(rule)
    existing = rule_index.get(key)
    if existing is not None:
        return existing
    rule_id = len(rules)
    rules.append(rule)
    rule_index[key] = rule_id
    return rule_id


def estimated_rule_payload_size(rule):
    op_tag = rule[0]
    if op_tag == OP_CONST:
        return 1 + signed_size(rule[1]) + varuint_size(rule[2])
    if op_tag == OP_LINE:
        return 1 + signed_size(rule[1]) + signed_size(rule[2]) + varuint_size(rule[3])
    if op_tag == OP_CURVE:
        return (
            1
            + signed_size(rule[1])
            + signed_size(rule[2])
            + signed_size(rule[3])
            + varuint_size(rule[4])
        )
    if op_tag == OP_PERIOD:
        size = 1 + varuint_size(len(rule[1])) + varuint_size(rule[2])
        for value in rule[1]:
            size += signed_size(value)
        return size
    if op_tag == OP_CALL:
        return 1 + varuint_size(rule[1]) + varuint_size(rule[2])
    if op_tag == OP_JOIN:
        size = 1 + varuint_size(len(rule[1]))
        for child_id in rule[1]:
            size += varuint_size(child_id)
        return size
    raise ValueError("unknown rule operation")


def choose_law_rule(values, start):
    remaining = len(values) - start
    candidates = []

    const_count = const_length(values, start)
    if const_count >= 2:
        candidates.append([const_count, [OP_CONST, values[start], const_count]])

    line_count = line_length(values, start)
    if line_count >= 4:
        candidates.append(
            [line_count, [OP_LINE, values[start], values[start + 1] - values[start], line_count]]
        )

    curve_count = curve_length(values, start)
    if curve_count >= 5:
        first_step = values[start + 1] - values[start]
        second_step = values[start + 2] - (2 * values[start + 1]) + values[start]
        candidates.append(
            [curve_count, [OP_CURVE, values[start], first_step, second_step, curve_count]]
        )

    period_length, period_count = period_candidate(values, start, 32)
    if period_count:
        period_values = values[start : start + period_length]
        candidates.append([period_count, [OP_PERIOD, period_values, period_count]])

    if not candidates:
        return [OP_CONST, values[start], 1], 1

    best_rule = None
    best_count = 0
    best_score = None
    for count, rule in candidates:
        raw_size = 0
        for offset in range(count):
            raw_size += 1 + signed_size(values[start + offset]) + 1
        rule_size = estimated_rule_payload_size(rule)
        score = raw_size - rule_size
        if best_score is None or score > best_score or (score == best_score and count > best_count):
            best_score = score
            best_rule = rule
            best_count = count

    if best_score is not None and best_score > 0:
        return best_rule, best_count
    return [OP_CONST, values[start], 1], 1


def build_law_rules(h_values):
    rules = []
    rule_index = {}
    stream = []
    index = 0
    while index < len(h_values):
        rule, count = choose_law_rule(h_values, index)
        rule_id = add_rule(rules, rule_index, rule)
        stream.append(rule_id)
        index += count
    return rules, rule_index, stream


def span_occurrences(stream, span):
    occurrences = []
    span_length = len(span)
    index = 0
    while index <= len(stream) - span_length:
        if tuple(stream[index : index + span_length]) == span:
            occurrences.append(index)
            index += span_length
        else:
            index += 1
    return occurrences


def replace_occurrences(stream, span, occurrences, rule_id):
    span_length = len(span)
    occurrence_map = {}
    for position in occurrences:
        occurrence_map[position] = True
    output = []
    index = 0
    while index < len(stream):
        if occurrence_map.get(index):
            output.append(rule_id)
            index += span_length
        else:
            output.append(stream[index])
            index += 1
    return output


def find_repeated_span(stream, rules):
    best = None
    max_span = min(48, len(stream) // 2)
    for span_length in range(max_span, 1, -1):
        seen = {}
        order = []
        for index in range(0, len(stream) - span_length + 1):
            span = tuple(stream[index : index + span_length])
            if span not in seen:
                seen[span] = []
                order.append(span)
            seen[span].append(index)
        for span in order:
            positions = []
            last_end = -1
            for position in seen[span]:
                if position >= last_end:
                    positions.append(position)
                    last_end = position + span_length
            if len(positions) < 2:
                continue
            original_size = 0
            for child_id in span:
                original_size += varuint_size(child_id)
            original_size = original_size * len(positions)
            new_id = len(rules)
            join_rule = [OP_JOIN, list(span)]
            replacement_size = (varuint_size(new_id) * len(positions)) + estimated_rule_payload_size(
                join_rule
            )
            benefit = original_size - replacement_size
            if benefit <= 0:
                continue
            candidate = [benefit, positions[0], span, positions, join_rule]
            if best is None:
                best = candidate
            elif benefit > best[0] or (benefit == best[0] and positions[0] < best[1]):
                best = candidate
    return best


def apply_repeated_span_rules(rules, rule_index, stream):
    iterations = 0
    while iterations < 1000:
        match = find_repeated_span(stream, rules)
        if match is None:
            break
        rule_id = add_rule(rules, rule_index, match[4])
        stream = replace_occurrences(stream, match[2], match[3], rule_id)
        iterations += 1
    return stream


def find_adjacent_repeat(stream, rules):
    best = None
    max_span = min(48, len(stream) // 2)
    for index in range(len(stream)):
        limit = min(max_span, (len(stream) - index) // 2)
        for span_length in range(1, limit + 1):
            span = stream[index : index + span_length]
            repeat_count = 1
            cursor = index + span_length
            while cursor + span_length <= len(stream):
                if stream[cursor : cursor + span_length] != span:
                    break
                repeat_count += 1
                cursor += span_length
            if repeat_count < 2:
                continue
            original_size = 0
            for child_id in span:
                original_size += varuint_size(child_id)
            original_size = original_size * repeat_count
            if span_length == 1:
                join_rule = None
                call_target_id = span[0]
                added_size = 1 + varuint_size(call_target_id) + varuint_size(repeat_count)
                new_id = len(rules)
                replacement_size = varuint_size(new_id) + added_size
            else:
                join_rule = [OP_JOIN, list(span)]
                call_target_id = len(rules)
                call_rule_size = 1 + varuint_size(call_target_id) + varuint_size(repeat_count)
                call_id = len(rules) + 1
                replacement_size = (
                    varuint_size(call_id)
                    + estimated_rule_payload_size(join_rule)
                    + call_rule_size
                )
            benefit = original_size - replacement_size
            if benefit <= 0:
                continue
            candidate = [benefit, index, span_length, repeat_count, span, join_rule]
            if best is None:
                best = candidate
            elif benefit > best[0] or (benefit == best[0] and index < best[1]):
                best = candidate
    return best


def apply_call_rules(rules, rule_index, stream):
    iterations = 0
    while iterations < 1000:
        match = find_adjacent_repeat(stream, rules)
        if match is None:
            break
        span_length = match[2]
        repeat_count = match[3]
        span = match[4]
        if span_length == 1:
            call_target_id = span[0]
        else:
            call_target_id = add_rule(rules, rule_index, match[5])
        call_id = add_rule(rules, rule_index, [OP_CALL, call_target_id, repeat_count])
        before = stream[: match[1]]
        after = stream[match[1] + (span_length * repeat_count) :]
        stream = before + [call_id] + after
        iterations += 1
    return stream


def collect_reachable(rule_id, rules, reachable):
    if reachable.get(rule_id):
        return
    reachable[rule_id] = True
    rule = rules[rule_id]
    if rule[0] == OP_CALL:
        collect_reachable(rule[1], rules, reachable)
    elif rule[0] == OP_JOIN:
        for child_id in rule[1]:
            collect_reachable(child_id, rules, reachable)


def remap_rule(rule, id_map):
    op_tag = rule[0]
    if op_tag == OP_CALL:
        return [OP_CALL, id_map[rule[1]], rule[2]]
    if op_tag == OP_JOIN:
        return [OP_JOIN, [id_map[child_id] for child_id in rule[1]]]
    if op_tag == OP_PERIOD:
        return [OP_PERIOD, list(rule[1]), rule[2]]
    return list(rule)


def prune_rules(root_rule_id, rules):
    reachable = {}
    collect_reachable(root_rule_id, rules, reachable)
    id_map = {}
    new_rules = []
    for old_id, rule in enumerate(rules):
        if reachable.get(old_id):
            id_map[old_id] = len(new_rules)
            new_rules.append(rule)
    remapped_rules = []
    for rule in new_rules:
        remapped_rules.append(remap_rule(rule, id_map))
    return id_map[root_rule_id], remapped_rules


def compact_rule_ids(root_rule_id, rules):
    frequencies = {}
    for rule_id in range(len(rules)):
        frequencies[rule_id] = 0
    frequencies[root_rule_id] = frequencies[root_rule_id] + 1
    for rule in rules:
        if rule[0] == OP_CALL:
            frequencies[rule[1]] = frequencies[rule[1]] + 1
        elif rule[0] == OP_JOIN:
            for child_id in rule[1]:
                frequencies[child_id] = frequencies[child_id] + 1

    ordered_ids = list(range(len(rules)))
    ordered_ids.sort(key=lambda rule_id: (-frequencies[rule_id], rule_id))
    id_map = {}
    for new_id, old_id in enumerate(ordered_ids):
        id_map[old_id] = new_id

    compacted = []
    for old_id in ordered_ids:
        compacted.append(remap_rule(rules[old_id], id_map))
    return id_map[root_rule_id], compacted


def build_rules(h_values):
    if not h_values:
        return None, []
    rules, rule_index, stream = build_law_rules(h_values)
    stream = apply_repeated_span_rules(rules, rule_index, stream)
    stream = apply_call_rules(rules, rule_index, stream)
    if len(stream) == 1:
        root_rule_id = stream[0]
    else:
        root_rule_id = add_rule(rules, rule_index, [OP_JOIN, stream])
    root_rule_id, rules = prune_rules(root_rule_id, rules)
    return compact_rule_ids(root_rule_id, rules)


def encode_rule(rule):
    op_tag = rule[0]
    output = bytes([op_tag])
    if op_tag == OP_CONST:
        return output + encode_signed(rule[1]) + encode_varuint(rule[2])
    if op_tag == OP_LINE:
        return output + encode_signed(rule[1]) + encode_signed(rule[2]) + encode_varuint(rule[3])
    if op_tag == OP_CURVE:
        return (
            output
            + encode_signed(rule[1])
            + encode_signed(rule[2])
            + encode_signed(rule[3])
            + encode_varuint(rule[4])
        )
    if op_tag == OP_PERIOD:
        output += encode_varuint(len(rule[1]))
        for value in rule[1]:
            output += encode_signed(value)
        return output + encode_varuint(rule[2])
    if op_tag == OP_CALL:
        return output + encode_varuint(rule[1]) + encode_varuint(rule[2])
    if op_tag == OP_JOIN:
        output += encode_varuint(len(rule[1]))
        for child_id in rule[1]:
            output += encode_varuint(child_id)
        return output
    raise ValueError("unknown rule operation")


def encode_h_relation_packet(root_rule_id, rules):
    output = encode_varuint(root_rule_id) + encode_varuint(len(rules))
    for rule in rules:
        output += encode_rule(rule)
    return output


def decode_rule(reader):
    op_tag = reader.read_byte()
    if op_tag == OP_CONST:
        return [OP_CONST, reader.read_signed(), reader.read_varuint()]
    if op_tag == OP_LINE:
        return [OP_LINE, reader.read_signed(), reader.read_signed(), reader.read_varuint()]
    if op_tag == OP_CURVE:
        return [
            OP_CURVE,
            reader.read_signed(),
            reader.read_signed(),
            reader.read_signed(),
            reader.read_varuint(),
        ]
    if op_tag == OP_PERIOD:
        period_length = reader.read_varuint()
        values = []
        for _ in range(period_length):
            values.append(reader.read_signed())
        return [OP_PERIOD, values, reader.read_varuint()]
    if op_tag == OP_CALL:
        return [OP_CALL, reader.read_varuint(), reader.read_varuint()]
    if op_tag == OP_JOIN:
        child_count = reader.read_varuint()
        children = []
        for _ in range(child_count):
            children.append(reader.read_varuint())
        return [OP_JOIN, children]
    raise DecodeError("unknown rule operation")


def expand_rule(rule_id, rules, memo, active=None):
    if active is None:
        active = set()

    existing = memo.get(rule_id)
    if existing is not None:
        return list(existing)

    if rule_id < 0 or rule_id >= len(rules):
        raise DecodeError("rule id out of range")

    if rule_id in active:
        raise DecodeError("cyclic rule reference")

    active.add(rule_id)
    rule = rules[rule_id]
    op_tag = rule[0]
    output = []

    if op_tag == OP_CONST:
        for _ in range(rule[2]):
            output.append(rule[1])

    elif op_tag == OP_LINE:
        for index in range(rule[3]):
            output.append(rule[1] + (index * rule[2]))

    elif op_tag == OP_CURVE:
        value = rule[1]
        step = rule[2]
        for index in range(rule[4]):
            output.append(value)
            if index + 1 < rule[4]:
                value = value + step
                step = step + rule[3]

    elif op_tag == OP_PERIOD:
        if len(rule[1]) == 0 and rule[2] > 0:
            raise DecodeError("non-empty period expansion has empty period")
        for index in range(rule[2]):
            output.append(rule[1][index % len(rule[1])])

    elif op_tag == OP_CALL:
        child = expand_rule(rule[1], rules, memo, active)
        for _ in range(rule[2]):
            output.extend(child)

    elif op_tag == OP_JOIN:
        for child_id in rule[1]:
            output.extend(expand_rule(child_id, rules, memo, active))

    else:
        raise DecodeError("unknown rule operation")

    active.remove(rule_id)
    memo[rule_id] = list(output)
    return output


def reconstruct_from_h(b0, g0, h_values, original_length):
    if original_length == 0:
        return b""
    if original_length == 1:
        return bytes([b0])
    b_values = [b0]
    g_value = g0
    for index in range(original_length - 1):
        next_value = b_values[-1] + g_value
        if next_value < 0 or next_value > 255:
            raise DecodeError("reconstructed byte out of range")
        b_values.append(next_value)
        if index < len(h_values):
            g_value = g_value + h_values[index]
    return bytes(b_values)


def encode_bacr(data):
    b_values, g_values, h_values = bytes_to_bgh(data)
    relation_packet = b""
    root_rule_id = None
    rules = []
    payload = b""

    if len(data) == 0:
        payload = b"\x00"
    elif len(data) == 1:
        payload = bytes([b_values[0]])
    elif len(data) == 2:
        payload = bytes([b_values[0]]) + encode_signed(g_values[0])
    else:
        root_rule_id, rules = build_rules(h_values)
        relation_packet = encode_h_relation_packet(root_rule_id, rules)
        payload = bytes([b_values[0]]) + encode_signed(g_values[0]) + relation_packet

    header = (
        MAGIC
        + bytes([VERSION])
        + encode_varuint(len(data))
        + sha256_bytes(data)
        + encode_varuint(len(relation_packet))
    )
    return header + payload, root_rule_id, rules, len(relation_packet), len(h_values)


def decode_bacr(data):
    reader = Reader(data)
    if reader.read_bytes(4) != MAGIC:
        raise DecodeError("bad magic")

    version = reader.read_byte()
    if version != VERSION:
        raise DecodeError("unsupported version")

    original_length = reader.read_varuint()
    original_sha256 = reader.read_bytes(32)
    relation_packet_length = reader.read_varuint()

    root_rule_id = None
    rules = []

    if original_length == 0:
        if relation_packet_length != 0:
            raise DecodeError("empty carrier has nonzero relation packet length")
        marker = reader.read_byte()
        if marker != 0:
            raise DecodeError("bad empty carrier marker")
        decoded = b""
        return validate_decoded_packet(
            decoded,
            original_length,
            original_sha256,
            root_rule_id,
            rules,
            0,
            relation_packet_length,
            reader,
        )

    if original_length == 1:
        if relation_packet_length != 0:
            raise DecodeError("one-byte carrier has nonzero relation packet length")
        b0 = reader.read_byte()
        decoded = bytes([b0])
        return validate_decoded_packet(
            decoded,
            original_length,
            original_sha256,
            root_rule_id,
            rules,
            0,
            relation_packet_length,
            reader,
        )

    if original_length == 2:
        if relation_packet_length != 0:
            raise DecodeError("two-byte carrier has nonzero relation packet length")
        b0 = reader.read_byte()
        g0 = reader.read_signed()
        decoded = reconstruct_from_h(b0, g0, [], original_length)
        return validate_decoded_packet(
            decoded,
            original_length,
            original_sha256,
            root_rule_id,
            rules,
            0,
            relation_packet_length,
            reader,
        )

    b0 = reader.read_byte()
    g0 = reader.read_signed()
    relation_bytes = reader.read_bytes(relation_packet_length)
    relation_reader = Reader(relation_bytes)

    root_rule_id = relation_reader.read_varuint()
    rule_count = relation_reader.read_varuint()

    for _ in range(rule_count):
        rules.append(decode_rule(relation_reader))

    if relation_reader.remaining() != 0:
        raise DecodeError("trailing relation packet bytes")

    h_values = expand_rule(root_rule_id, rules, {})
    expected_h_count = original_length - 2

    if len(h_values) != expected_h_count:
        raise DecodeError("expanded H length mismatch")

    decoded = reconstruct_from_h(b0, g0, h_values, original_length)

    return validate_decoded_packet(
        decoded,
        original_length,
        original_sha256,
        root_rule_id,
        rules,
        len(h_values),
        relation_packet_length,
        reader,
    )


def rule_counts_by_type(rules):
    counts = {
        "CONST": 0,
        "LINE": 0,
        "CURVE": 0,
        "PERIOD": 0,
        "CALL": 0,
        "JOIN": 0,
    }
    for rule in rules:
        name = OP_NAMES.get(rule[0], "UNKNOWN")
        if name not in counts:
            counts[name] = 0
        counts[name] += 1
    return counts


def status_for(exact_match, length_equal, sha_equal, bacr_size, original_size):
    if not exact_match or not length_equal or not sha_equal:
        return "FAILED"
    if bacr_size < original_size:
        return "CLOSED"
    return "ROUNDTRIP_ONLY"


def build_report(input_path, output_path, original_data, bacr_data, decoded_info):
    decoded = decoded_info["data"]
    original_sha = sha256_hex(original_data)
    decoded_sha = sha256_hex(decoded)
    length_equal = len(original_data) == len(decoded)
    sha_equal = original_sha == decoded_sha
    exact_match = original_data == decoded
    original_size = len(original_data)
    bacr_size = len(bacr_data)
    ratio = None
    if original_size != 0:
        ratio = bacr_size / original_size
    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "original_size": original_size,
        "bacr_size": bacr_size,
        "ratio": ratio,
        "original_sha256": original_sha,
        "decoded_sha256": decoded_sha,
        "decoded_size": len(decoded),
        "exact_match": exact_match,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "status": status_for(exact_match, length_equal, sha_equal, bacr_size, original_size),
        "h_value_count": decoded_info["h_value_count"],
        "root_rule_id": decoded_info["root_rule_id"],
        "rule_count": len(decoded_info["rules"]),
        "rule_counts_by_type": rule_counts_by_type(decoded_info["rules"]),
        "relation_packet_size": decoded_info["relation_packet_size"],
    }


def build_unpack_report(input_path, output_path, bacr_data, decoded_info):
    decoded = decoded_info["data"]
    decoded_sha = sha256_hex(decoded)
    header_sha = decoded_info["original_sha256"].hex()
    sha_equal = decoded_sha == header_sha
    length_equal = len(decoded) == decoded_info["original_length"]

    return {
        "input_path": str(input_path),
        "output_path": str(output_path),
        "original_size": decoded_info["original_length"],
        "bacr_size": len(bacr_data),
        "ratio": len(bacr_data) / decoded_info["original_length"]
        if decoded_info["original_length"] != 0
        else None,
        "original_sha256": header_sha,
        "decoded_sha256": decoded_sha,
        "decoded_size": len(decoded),
        "exact_match": sha_equal and length_equal,
        "length_equal": length_equal,
        "sha_equal": sha_equal,
        "status": status_for(
            sha_equal and length_equal,
            length_equal,
            sha_equal,
            len(bacr_data),
            decoded_info["original_length"],
        ),
        "h_value_count": decoded_info["h_value_count"],
        "root_rule_id": decoded_info["root_rule_id"],
        "rule_count": len(decoded_info["rules"]),
        "rule_counts_by_type": rule_counts_by_type(decoded_info["rules"]),
        "relation_packet_size": decoded_info["relation_packet_size"],
    }


def print_report(report):
    print(json.dumps(report, indent=2))


def pack_command(args):
    input_path = Path(args.input_path)
    output_path = Path(args.output_bacr_path)
    data = read_input_bytes(input_path)
    bacr_data, _, _, _, _ = encode_bacr(data)
    write_bytes(output_path, bacr_data)
    decoded_info = decode_bacr(bacr_data)
    report = build_report(args.input_path, args.output_bacr_path, data, bacr_data, decoded_info)
    print_report(report)
    return 0 if report["exact_match"] else 1


def unpack_command(args):
    input_path = Path(args.input_bacr_path)
    output_path = Path(args.output_path)
    bacr_data = read_input_bytes(input_path)
    decoded_info = decode_bacr(bacr_data)
    decoded = decoded_info["data"]
    write_bytes(output_path, decoded)
    report = build_unpack_report(
        args.input_bacr_path,
        args.output_path,
        bacr_data,
        decoded_info,
    )
    print_report(report)
    return 0 if report["exact_match"] else 1


def verify_command(args):
    input_path = Path(args.input_path)
    bacr_path = Path(args.input_bacr_path)
    original_data = read_input_bytes(input_path)
    bacr_data = read_input_bytes(bacr_path)
    decoded_info = decode_bacr(bacr_data)
    report = build_report(args.input_path, args.input_bacr_path, original_data, bacr_data, decoded_info)
    print_report(report)
    return 0 if report["exact_match"] else 1


def build_parser():
    parser = argparse.ArgumentParser(description="Pack, unpack, and verify BACR artifacts.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    pack_parser = subparsers.add_parser("pack")
    pack_parser.add_argument("input_path")
    pack_parser.add_argument("output_bacr_path")
    pack_parser.set_defaults(func=pack_command)

    unpack_parser = subparsers.add_parser("unpack")
    unpack_parser.add_argument("input_bacr_path")
    unpack_parser.add_argument("output_path")
    unpack_parser.set_defaults(func=unpack_command)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("input_path")
    verify_parser.add_argument("input_bacr_path")
    verify_parser.set_defaults(func=verify_command)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except (DecodeError, ValueError, OSError) as error:
        print(json.dumps({"status": "FAILED", "error": str(error)}, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())
