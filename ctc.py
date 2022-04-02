import encryption
import socket
import os
import threading
import json
import time
from enum import Enum


class ConnectStateEnum(Enum):
  LISTEN = 1
  CLOSE = 3
  ONLINE = 5
  DESTROY = 7


class Client:
  def __init__(self, getInfoFeedback):
    self.getInfoFeedback = getInfoFeedback
    self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    self.asymmetricEncryptor = None
    self.remote = None
    self.listenThread = None
    self.recvThread = None
    self.recvData = bytes()
    self.LoadLocalAsymmetricEncryptorKey()
    self.connectState = ConnectStateEnum.CLOSE

  def Listen(self, listenHost, listenPort):
    def _Listen():
      self.socket, self.remote = self.socket.accept()
      self.connectState = ConnectStateEnum.ONLINE
      self.StartRecv()
    if self.connectState != ConnectStateEnum.CLOSE:
      self.Reset()
    self.socket.bind((listenHost, listenPort))
    self.socket.listen(1)
    self.connectState = ConnectStateEnum.LISTEN
    self.listenThread = threading.Thread(target=_Listen)
    self.listenThread.start()

  def Reset(self):
    try:
      self.socket.close()
    except Exception as e:
      print('[error]Reset.e=', e)
    self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    self.connectState = ConnectStateEnum.CLOSE

  def Destroy(self):
    try:
      self.socket.close()
    except Exception as e:
      print('[error]Close.e=', e)
    self.connectState = ConnectStateEnum.DESTROY

  def LoadLocalAsymmetricEncryptorKey(self):
    if os.path.exists('publicKey.key') and os.path.exists('privateKey.key'):
      publicKey = encryption.ReadTxt('publicKey.key').split(',')
      publicKey = (int(publicKey[0]), int(publicKey[1]))
      privateKey = encryption.ReadTxt('privateKey.key').split(',')
      privateKey = (int(privateKey[0]), int(privateKey[1]))
      self.asymmetricEncryptor = encryption.AsymmetricEncryptor(publicKey, privateKey)
    else:
      self.asymmetricEncryptor = encryption.AsymmetricEncryptor()
      self.asymmetricEncryptor.New()

  def Connect(self, remoteIp, remotePort):
    if self.connectState != ConnectStateEnum.CLOSE:
      self.Reset()
    self.remote = (remoteIp, remotePort)
    self.socket.connect((remoteIp, remotePort))
    self.connectState = ConnectStateEnum.ONLINE
    self.StartRecv()

  def Send(self, content: str):
    if self.connectState == ConnectStateEnum.ONLINE:
      self.socket.sendall(content.encode(encoding='utf8'))

  def Recv(self):
    try:
      while self.connectState == ConnectStateEnum.ONLINE:
        self.recvData += self.socket.recv(1024)
        content = self.recvData.decode(encoding='utf8')
        try:
          jsonContent = json.loads(content)
        except Exception as e:
          print('[error]Recv.2.e=', e)
        else:
          self.recvData = bytes()
          self.getInfoFeedback(jsonContent)
    except Exception as e:
      print('[error]Recv.1.e=', e)

  def StartRecv(self):
    self.recvThread = threading.Thread(target=self.Recv)
    self.recvThread.start()


if __name__ == '__main__':
  print('test start')
  c1 = Client(print)
  c2 = Client(print)
  c1.Listen('::1', 8111)
  c2.Connect('::1', 8111)
  c1.Send(json.dumps({'msg': 'hello c2, i am c1.'}))
  c2.Send(json.dumps({'msg': 'hello c1, i am c2.'}))
  time.sleep(1)
  c1.Destroy()
  c2.Destroy()
  print('test finished')
