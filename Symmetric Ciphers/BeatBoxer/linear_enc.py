from data_structs import _8BitsNumber
from linear_fun import S_Y, gmul2_Y, gmul3_Y, rcon
def transpose(m):
        return [m[4 * j + i] for i in range(4) for j in range(4)]

def expand_key(key):
    round_keys = [key]

    for i in range(10):
        round_key = []
        first = round_keys[i][:4]
        last = round_keys[i][-4:]
        last = last[1:] + [last[0]]
        last = [i.wrap(S_Y) for i in last]

        for j in range(4):
            temp = first[j].xor(last[j])
            if j == 0:
                temp = temp.xor_const(rcon[i+1])
            round_key.append(temp)
        for j in range(0, 12, 4):
            for k in range(4):
                round_key.append(round_key[j:j + 4][k].xor(round_keys[i][j + 4:j + 8][k]))
        round_keys.append(round_key)

    for i in range(len(round_keys)):
        round_keys[i] = transpose(round_keys[i])
    return round_keys

def add_round_key(index, state, round_keys):
    result = []
    round_key = round_keys[index]
    for i in range(16):
        result.append(state[i].xor(round_key[i]))
    return result

def shift_rows(state):
    return [
        state[0], state[1], state[2], state[3],
        state[5], state[6], state[7], state[4],
        state[10], state[11], state[8], state[9],
        state[15], state[12], state[13], state[14]
    ]

def mix_columns(state):
    s = [_8BitsNumber()] * 16
    for i in range(4):
        s[i] = state[i].wrap(gmul2_Y).xor(state[i+4].wrap(gmul3_Y)).xor(state[i + 8]).xor(state[i + 12])
        s[i+4] = state[i].xor(state[i+4].wrap(gmul2_Y)).xor(state[i + 8].wrap(gmul3_Y)).xor(state[i + 12])
        s[i+8] = state[i].xor(state[i+4]).xor(state[i + 8].wrap(gmul2_Y)).xor(state[i + 12].wrap(gmul3_Y))
        s[i+12] = state[i].wrap(gmul3_Y).xor(state[i+4]).xor(state[i + 8]).xor(state[i + 12].wrap(gmul2_Y))
    return s

def sub_bytes(state):
    return [i.wrap(S_Y) for i in state]

def encrypt_block(state, round_keys):
    state = add_round_key(0, state, round_keys)

    for i in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(i, state, round_keys)

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(10, state, round_keys)

    return state

def encrypt(key, plainText):
    state = transpose(plainText)
    state = encrypt_block(state, expand_key(key))
    return (transpose(state))