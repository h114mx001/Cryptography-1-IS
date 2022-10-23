from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from Cryptodome.Util import Counter
from Cryptodome.Util.number import bytes_to_long

blocksize = 16

cbcKeys = ["140b41b22a29beb4061bda66b6747e14", "140b41b22a29beb4061bda66b6747e14"]
cbcCiphers = ["4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81", "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"]
cbcKeys = [bytes.fromhex(s) for s in cbcKeys]
cbcCiphers = [bytes.fromhex(s) for s in cbcCiphers]
cbcIVs = [s[0:16] for s in cbcCiphers]

for i in range(0, 2):
    aesMachine = AES.new(key=cbcKeys[i], mode=AES.MODE_CBC, iv=cbcIVs[i])
    message = aesMachine.decrypt(cbcCiphers[i][16:])
    print(unpad(message, 16))

ctrKeys = ["36f18357be4dbd77f050515c73fcf9f2", "36f18357be4dbd77f050515c73fcf9f2"]
ctrCiphers = ["69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329", "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"]
ctrKeys = [bytes.fromhex(s) for s in ctrKeys]
ctrCiphers = [bytes().fromhex(s) for s in ctrCiphers]
ctrIVs = [s[0:blocksize] for s in ctrCiphers]

for i in range(0, 2):
    ctr = Counter.new(blocksize*8, initial_value=bytes_to_long(ctrIVs[i]))
    aesMachine = AES.new(key=ctrKeys[i], mode=AES.MODE_CTR, counter = ctr)
    print(aesMachine.decrypt(ctrCiphers[i][16:]))