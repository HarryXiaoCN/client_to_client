from numba import jit
import random


def ReadTxt(path):
  with open(path, encoding='utf8') as f:
    return f.read()


def SaveTxt(path, content):
  with open(path, 'w', encoding='utf8') as f:
    f.write(content)


@jit(nopython=True)
def GetPrimeNumber(maxNumber=1000):
  primeNumber = [2]
  primeNumberStr = ['2']
  for number in range(3, maxNumber):
    for n in primeNumber:
      if number % n == 0:
        break
    else:
      primeNumber.append(number)
      primeNumberStr.append(str(number))
    if number % 100000 == 0:
      print('GetPrimeNumber.number=', number)
  return primeNumberStr


# 第一步
def GetTwoPrimeNumber(primeNumberList):
  primeNumber1 = random.choice(primeNumberList)
  primeNumber2 = primeNumber1
  while primeNumber1 == primeNumber2:
    primeNumber2 = random.choice(primeNumberList)
  return primeNumber1, primeNumber2


# 第二步
def GetN(primeNumber1, primeNumber2):
  return primeNumber1 * primeNumber2


# 第三步
def GetMutuallyPrimeCount(primeNumber1, primeNumber2):
  return (primeNumber1 - 1) * (primeNumber2 - 1)


# 第四步
def GetE(mutuallyPrimeCount):
  e = mutuallyPrimeCount
  pNList = GetRangePrimeNumber(mutuallyPrimeCount)
  while mutuallyPrimeCount % e == 0:
    e = random.choice(pNList)
  return e


# 第五步
def GetDK(e, mutuallyPrimeCount):
  rndList = []
  for number in range(1, min(e * 100, 1000000)):
    if (number * mutuallyPrimeCount + 1) % e == 0:
      rndList.append(number)
  # print('rndList=', rndList)
  k = random.choice(rndList)
  d = (k * mutuallyPrimeCount + 1) // e
  return d, k


def GetRangePrimeNumber(maxNumber):
  for numberId in range(len(localPrimeNumberList) - 1, -1, -1):
    if localPrimeNumberList[numberId] < maxNumber:
      return localPrimeNumberList[:numberId + 1]


def GetRandomStr(length: int):
  result = []
  for _ in range(length):
    result.append(random.choice(allKeyChar))
  return ''.join(result)


def StrToBytes(string):
  result = []
  for _chr in string:
    result.append(ord(_chr))
  return result


class AsymmetricEncryptor:

  def __init__(self, publicKey: tuple[int, int] = None, privateKey: tuple[int, int] = None):
    self.publicKey = publicKey
    self.privateKey = privateKey

  def New(self, maxNumber=1000):
    # print('step 0')
    primeNumber1, primeNumber2 = GetTwoPrimeNumber(GetRangePrimeNumber(maxNumber))
    # print('step 1', primeNumber1, primeNumber2)
    n = GetN(primeNumber1, primeNumber2)
    # print('step 2 n=', n)
    mutuallyPrimeCount = GetMutuallyPrimeCount(primeNumber1, primeNumber2)
    # print('step 3 mutuallyPrimeCount=', mutuallyPrimeCount)
    e = GetE(mutuallyPrimeCount)
    # print('step 4 e=', e)
    d, k = GetDK(e, mutuallyPrimeCount)
    # print('step 5 d=%s k=%s' % (d, k))
    self.publicKey = (n, e)
    self.privateKey = (n, d)
    return self.publicKey, self.privateKey

  def Encryption(self, plaintext: int):
    n = self.publicKey[0]
    e = self.publicKey[1]
    assert plaintext < n, 'plaintext >= n,plaintext=%s, n=%s' % (plaintext, n)
    return plaintext ** e % n

  def Decrypt(self, ciphertext: int):
    n = self.privateKey[0]
    d = self.privateKey[1]
    return GetAsymmetricEncryptorDecrypt(ciphertext, n, d)


# @jit(nopython=True)
def GetAsymmetricEncryptorDecrypt(ciphertext: int, n: int, d: int):
  return ciphertext ** d % n


class SymmetricEncryption:

  def __init__(self, key=None):
    self.key = key

  def _SetKey(self, key):
    self.key = key
    self.keyBytes = self.key.encode(encoding='utf8')

  def New(self, length: int):
    self._SetKey(GetRandomStr(length))
    return self.key

  def Encryption(self, plaintext: str):
    plaintextBytes = plaintext.encode(encoding='utf8')
    keyBytesCount = len(self.keyBytes)
    result = []
    for byteId in range(len(plaintextBytes)):
      newByte = (plaintextBytes[byteId] + self.keyBytes[byteId % keyBytesCount]) % 256
      result.append(hex(newByte)[2:])
    return ''.join(result)

  def Decrypt(self, ciphertext: str):
    keyBytesCount = len(self.keyBytes)
    plaintextBytes = []
    assert len(ciphertext) % 2 == 0, 'len(ciphertext) %% 2 != 0, len(ciphertext) = %s' % len(ciphertext)
    keyBytesId = 0
    for byteId in range(0, len(ciphertext), 2):
      byteHex = ciphertext[byteId: byteId + 2]
      byte = int(byteHex, 16)
      originalByte = (byte + 256 - self.keyBytes[keyBytesId % keyBytesCount]) % 256
      plaintextBytes.append(originalByte.to_bytes(1, 'big')[0])
      keyBytesId += 1
    return bytes(plaintextBytes).decode(encoding='utf8')


localPrimeNumberStrList = ReadTxt('PrimeNumber.txt').split('\n')
localPrimeNumberList = []
allKeyChar = [chr(_asc) for _asc in range(33, 127)]
for _primeNumber in localPrimeNumberStrList:
  localPrimeNumberList.append(int(_primeNumber))


if __name__ == '__main__':
  # SaveTxt('PrimeNumber.txt', '\n'.join(GetPrimeNumber(9999999)))
  # print('ok!')
  
  se = SymmetricEncryption()
  se.New(10)
  eStr = se.Encryption('hello world!')
  print(eStr)
  deStr = se.Decrypt(eStr)
  print(deStr)

  ae = AsymmetricEncryptor()
  ae.New()
  eStr = ae.Encryption(2222)
  print(eStr)
  deStr = ae.Decrypt(eStr)
  print(deStr)
