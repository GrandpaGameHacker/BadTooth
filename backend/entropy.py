import math


def entropy(buffer):
    entropy_value = 0.0
    f_length = float(len(buffer))
    log_base = math.log(256)
    occurrences = [0] * 256
    for byte in buffer:
        occurrences[byte] += 1

    for count in occurrences:
        if count == 0:
            continue
        p = float(count / f_length)
        entropy_value += p * math.log(p) / log_base
    return -entropy_value


def entropy_series(buffer, block_size):
    length = len(buffer)
    entropy_values = []
    current_block = 0

    n_blocks = math.trunc(length / block_size)
    if n_blocks < 1:
        return None

    next_block = block_size
    for i in range(n_blocks):
        value = entropy(buffer[current_block:next_block])
        entropy_values.append(value)

        current_block += block_size
        next_block += block_size
    return entropy_values
