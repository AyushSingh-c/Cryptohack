from Crypto.Util.number import long_to_bytes
import json 
import numpy as np
import matplotlib.pyplot as plt

f = open('collected_data.txt', 'r')
readings = np.array(json.loads(f.readline()))

# Means across 50 observations
readings = np.mean(readings, axis=0)
index = list(range(len(readings)))

# Generate the graph
plt.bar(index, readings)
plt.xlabel("Flag bit")
plt.ylabel("Power reading")
plt.savefig('readings.png')

# Retrieve the output from the readings
output = ""
for reading in readings:
    if reading < 120:
        output += "0"
    else:
        output += "1"

# Has to reverse the output string
# 2 ways to implement double-and-add, either LSB to MSB, or MSB to LSB
flag = int(output[::-1], 2)
print(long_to_bytes(flag))