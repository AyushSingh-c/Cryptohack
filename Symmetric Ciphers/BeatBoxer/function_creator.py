from data_structs import _singleBit, _8BitsNumber, PlainText, Key, CipherText
from linear_enc import encrypt

def transform(left, right):
    siz = len(right)
    def add(r1, r2):
        for i in range(siz):
            left[r1][i] = left[r1][i] ^ left[r2][i]
        right[r1] = right[r1].xor(right[r2])
    def swap(r1, r2):
        if r1 == r2:
            return
        temp = right[r1].copy()
        right[r1] = right[r2].copy()
        right[r2] = temp
        left[r1], left[r2] =  left[r2], left[r1]
    
    for i in range(siz):
        index = -1
        for j in range(i, siz):
            if left[j][i] == 1:
                index = j 
                break
        if index == -1:
            print("wtfffffffffffffff")
            exit(0)
        swap(i,index)

        for j in range(i+1, siz):
            if left[j][i] == 1:
                add(j,i)

    for i in reversed(range(siz)):
        for j in range(0, i):
            if left[j][i] == 1:
                add(j,i)

    return left, right 

def make_fun(e_ak, ch):
    left = []
    right = []
    for i in range(128):
        subleft = [0]*128
        left.append(subleft)
        right.append(_singleBit())

    for i in range(128):
        bits = e_ak[i//8].number[i%8].bit
        for bit in bits:
            if bit[0] == ch:
                index = 127-int(bit[2:])
                left[i][index] = 1
            else:
                temp = _singleBit()
                temp.add(bit)
                right[i] = right[i].xor(temp)
        right[i].add("E_"+str(127-i))
                
    left, right = transform(left, right)

    result = []
    for i in range(16):
        temp = _8BitsNumber()
        for j in range(8):
            temp.number[j] = right[(8*i)+j]
        result.append(temp)

    return result

E_AK = encrypt(Key, PlainText)
K_AE = make_fun(E_AK, "K")
A_EK = make_fun(E_AK, "A")

