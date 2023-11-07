value_Map = {}

def make_dic(sample_plainText, sample_key, sample_cipherText):
    for i in range(128):
        c = 15-(i//8)
        x = i%8
        value_Map["A_"+str(i)] = (sample_plainText[c]>>x)&1
        value_Map["K_"+str(i)] = (sample_key[c]>>x)&1
        value_Map["E_"+str(i)] = (sample_cipherText[c]>>x)&1
    value_Map["C_1"] = 1

class _singleBit:
    def __init__(self):
        self.bit = set()

    def add(self, s):
        self.bit.add(s)

    def remove(self, s):
        self.bit.remove(s)

    def contains(self, s):
        return s in self.bit

    def size(self):
        return len(self.bit)

    def xor(self, anotherBit):
        final = _singleBit()
        for i in self.bit:
            final.add(i)
        for i in anotherBit.bit:
            if final.contains(i):
                final.remove(i)
            else:
                final.add(i)
        return final
    
    def get_value(self):
        result = 0
        for i in self.bit:
            result = result ^ value_Map[i]
        return result

    def __str__(self):
        return "{" + ", ".join(self.bit) + "}"
    
    def copy(self):
        result = _singleBit()
        for i in self.bit:
            result.add(i)
        return result
    
class _8BitsNumber:

    def __init__(self, bits_list=None):
        self.number = []
        if bits_list:
            for bits in bits_list:
                Bit = _singleBit()
                for bit in bits:
                    Bit.add(bit)
                self.number.append(Bit)
        else:
            for _ in range(8):
                Bit = _singleBit()
                self.number.append(Bit)
    
    def wrap(self, Y):
        result = _8BitsNumber()
        for i in range(8):
            final = _singleBit()
            for j in range(8):
                if Y[i][j] == 1:
                    final = final.xor(self.number[j])
            if(Y[i][8] == 1):
                temp = _singleBit()
                temp.add("C_1")
                final = final.xor(temp)
            result.number[i] = (final)
        return result
    
    def xor(self, anotherNumber):
        result = _8BitsNumber()
        for i in range(8):
            result.number[i] = self.number[i].xor(anotherNumber.number[i])
        return result
    
    def xor_const(self, a):
        result = _8BitsNumber()
        for i in range(8):
            Bit = _singleBit()
            Bit.add("C_1")
            if (a>>(7-i))&1 == 1:
                result.number[i] = self.number[i].xor(Bit)
            else:
                result.number[i] = self.number[i]
        return result
    
    def get_value(self):
        result = 0
        for i in range(8):
            result += self.number[i].get_value()<<(7-i)
        return result
    
    def __str__(self):
        temp = []
        for i in self.number:
            temp.append(str(i))
        return "{" + ", ".join(temp) + "}"
    
    def copy(self):
        result = _8BitsNumber()
        for i in self.number:
            result.number = i.copy()
        return result
    

PlainText = []
Key = []
CipherText = []
for i in range(16):
    temp1 = []
    temp2 = []
    temp3 = []
    for j in range(8):
        c = 127-((i*8) + j)
        temp1.append(["A_" + str(c)])
        temp2.append(["K_" + str(c)]) 
        temp3.append(["E_" + str(c)]) 

    PlainText.append(_8BitsNumber(temp1))
    Key.append(_8BitsNumber(temp2))      
    CipherText.append(_8BitsNumber(temp3))   