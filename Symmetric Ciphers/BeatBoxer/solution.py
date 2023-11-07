from function_creator import E_AK, K_AE, A_EK
from data_structs import make_dic
from get_values import get_data

sample_plainText = [61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61, 61]
sample_key = [58, 165, 234, 214, 75, 243, 185, 101, 255, 125, 106, 71, 67, 228, 146, 203]
sample_cipherText = [2, 228, 104, 118, 109, 84, 211, 122, 238, 252, 145, 114, 218, 195, 242, 251]

sample_cipherText, flag= get_data(sample_plainText)
make_dic(sample_plainText, sample_key, sample_cipherText)  
print(flag)
sample_key = [i.get_value() for i in K_AE]

for i in range(0, len(flag), 16):  
    sample_cipherText = flag[i:i + 16]
    make_dic(sample_plainText, sample_key, sample_cipherText) 
    print("".join([chr(i.get_value()^92) for i in A_EK]), end ="")

