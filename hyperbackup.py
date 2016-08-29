import base64
import configparser
import getpass
import lz4
import os
import sqlite3
import struct
import sys

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# common paths setup
bkpiPath = raw_input("Please enter the full path to a .bkpi file: ")
if not os.path.isfile(bkpiPath) or bkpiPath[-5:] != ".bkpi":
    sys.exit("{0} is not a valid backup file!".format(bkpiPath))
baseDir = os.path.dirname(bkpiPath)
extractDir = os.path.join(baseDir, "extract")
configDir = os.path.join(baseDir, "Config")
virtualFileIndexDir = os.path.join(configDir, "virtual_file.index")
poolDir = os.path.join(baseDir, "Pool")
chunkIndexDir = os.path.join(poolDir, "chunk_index")
shareDir = os.path.join(configDir, "@Share")
rsaPrivateKeyFile = os.path.join(extractDir, "private.pem")
configFile = os.path.join(baseDir, "_Syno_TaskConfig")

fileChunkIndexTemplate = "file_chunk{0}.index"
poolIndexTemplate = "{0}.index"
poolBucketTemplate = "{0}.bucket"

# magic header number setup
magicKeyFileHeader = "ekhtar"
magicPwSection = "shpw"
magicUnknownSection = "shpv"
magicKeySection = "enpv"
magicIndexHeader = struct.pack("i", 0x6ea85370)

# hash salt setup
passwordSalt = "5mNgudh053SUoMrZxoKG8GUWyj6kEtGO"
unikeySalt1 = "CIpfMargmxetgFtkBmG3KqEiQ6qfqZgF"
unikeySalt2 = "kkE7sRZRvnbVlJFofhD7WCXumXBGyzki"
fileKeySalt = "8Llx6OSaDPzbwCkjG8eYc64GZGMIlMXm"

# hashing utility functions
def hashMD5(data):
    md5Hash = MD5.new()
    md5Hash.update(data)
    hash = md5Hash.digest()
    return hash

def hashSHA256(data):
    sha256Hash = SHA256.new()
    sha256Hash.update(data)
    hash = sha256Hash.digest()
    return hash

# AES-CBC decryption and encryption
def decryptAESCBC(cipherText, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    paddedPlainText = cipher.decrypt(cipherText)
    plainText = paddedPlainText[:-ord(paddedPlainText[-1])]
    return plainText

def encryptAESCBC(plainText, key, iv):
    padLength = 16 - (len(plainText) % 16)
    paddedPlainText = plainText + chr(padLength)*padLength
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipherText = cipher.encrypt(paddedPlainText)
    return cipherText

# RSA decryption using private key and PKCS1 v1.5 cipher
def decryptPrivateRSA(cipherText, privateKey):
    key = RSA.importKey(privateKey)
    cipher = PKCS1_v1_5.new(key)
    plainText = cipher.decrypt(cipherText, None)
    return plainText

# lz4 decompression routine
def uncompressLz4(compressedData, size):
    header = struct.pack("<I", size)
    compressedDataWithHeader = header + compressedData
    uncompressedData = lz4.uncompress(compressedDataWithHeader)
    return uncompressedData

# read and write file utility
def readDataFromFile(fileName, offset, size):
    data = None
    with open(fileName, "rb") as file:
        file.seek(offset)
        data = file.read(size)
    return data

def writeDataToFile(fileName, data):
    fileDirectory = os.path.dirname(fileName)
    if not os.path.exists(fileDirectory):
        os.makedirs(fileDirectory)
    with open(fileName, "wb+") as file:
        file.write(data)

# find a file in baseDir having a file name starting with prefix
def findFile(baseDir, prefix):
    for fileName in os.listdir(baseDir):
        if fileName.startswith(prefix):
            return os.path.join(baseDir, fileName)
    sys.exit("File {0}/{1} not found!".format(baseDir, prefix))

# list all folders in path excluding those in excludeDirectoryList
def getDirectoryList(path, excludeDirectoryList):
    directoryList = [file for file in os.listdir(path) if os.path.isdir(os.path.join(path, file))]
    return list(set(directoryList) - set(excludeDirectoryList))

# read the key file containing the encrypted private RSA key
def readKeyFile(fileName):
    passwordHash = None
    encryptedRsaPrivateKey = None
    with open(keyFile, "rb") as keyFileHandle:
        header = keyFileHandle.read(16)
        if (header[0:6] != magicKeyFileHeader.encode()):
            sys.exit("Wrong keyfile format")
        headerUnknownData = header[6:16]
        passwordSection = keyFileHandle.read(40)
        if (passwordSection[0:4] != magicPwSection.encode()):
            sys.exit("Wrong keyfile format")
        passwordHash = passwordSection[8:40]
        unknownSection = keyFileHandle.read(40)
        if (unknownSection[0:4] != magicUnknownSection.encode()):
            sys.exit("Wrong keyfile format")
        keySection = keyFileHandle.read()
        if (keySection[0:4] != magicKeySection.encode()):
            sys.exit("Wrong keyfile format")
        encryptedRsaPrivateKey = keySection[8:]
    return (passwordHash, encryptedRsaPrivateKey)

# verify the password using the hash from the key file
def verifyPassword(password, passwordHash):
    saltedPassword = passwordSalt + password
    firstPasswordHash = hashSHA256(saltedPassword.encode())
    secondPasswordHash = hashSHA256(firstPasswordHash)

    return passwordHash == secondPasswordHash

# read the unikey property from the config file
def readUnikeyFromConfig():
    backupConfig = configparser.ConfigParser()
    backupConfig.read(configFile)
    unikey = backupConfig['task_config']['unikey'][1:-1]
    return unikey

# decrypt the encrypted private RSA key using the password and unikey
def decryptRsaPrivateKey(encryptedRsaPrivateKey, password, unikey):
    saltedUnikey = unikey + unikeySalt1
    saltedPassword = passwordSalt + password
    key = hashSHA256(saltedPassword)
    iv = hashMD5(saltedUnikey)
    plainRsaPrivateKey = decryptAESCBC(encryptedRsaPrivateKey, key, iv)
    return plainRsaPrivateKey

# decryption and encryption routines for the file names in the file database
def decryptFileName(encryptedFileName, key, iv):
    aesEncryptedFileName = base64.b64decode(encryptedFileName.encode(), '+_')
    decryptedFileName = decryptAESCBC(aesEncryptedFileName, key, iv)
    return decryptedFileName.decode('utf-8')

def encryptFileName(fileName, key, iv):
    aesEncryptedFileName = encryptAESCBC(fileName, key, iv)
    encryptedFileName = base64.b64encode(aesEncryptedFileName, '+_')
    return encryptedFileName

# build a list of all files and their offset in the virtual file table
def buildFileOffsetList(rsaPrivateKey, unikey):
    saltedRsaKey = rsaPrivateKey + unikey
    fileNameDecryptionKey = hashSHA256(saltedRsaKey)

    saltedUnikey = unikey + unikeySalt2
    fileNameDecryptionIv = hashMD5(saltedUnikey)

    dotDirHash = hashMD5(".")
    topDirHash = dotDirHash[0:4] + dotDirHash

    #directoryList = getDirectoryList(shareDir, ["@AppConfig"])
    directoryList = getDirectoryList(shareDir, [])
    fileOffsetList = []

    topDirHash = hashMD5(".")
    rootHash = topDirHash[0:4] + topDirHash

    for directory in directoryList:
        directoryFullPath = os.path.join(shareDir, directory)
        dbFile = findFile(directoryFullPath, "1.db")
        conn = sqlite3.connect(dbFile)
        cursor = conn.cursor()
        fileOffsetList.extend(_buildFileOffsetList(directory, "", rootHash, cursor, fileNameDecryptionKey, fileNameDecryptionIv))
    return fileOffsetList

# method internally used in buildFileOffsetList
def _buildFileOffsetList(directory, encryptedParentPath, parentDirectoryHash, cursor, key, iv):
    cursor.execute("SELECT file_name, off_virtual_file, mode, name_id_v2 FROM version_list WHERE pname_id_v2 = ?", [sqlite3.Binary(parentDirectoryHash)])
    encryptedFileNameList = cursor.fetchall()
    decryptedFileNameList = map(lambda t: (decryptFileName(t[0], key, iv), t[0], t[1], (t[2] & 0x4000) > 0, t[3]), encryptedFileNameList)
    fileOffsetList = []
    for (decryptedFileName, encryptedFileName, offset, isDir, id) in decryptedFileNameList:
        decryptedFullFilePath = os.path.join(directory, decryptedFileName)
        encryptedFullFilePath = encryptedParentPath + encryptedFileName
        fileNameHash = parentDirectoryHash[4:8] + hashMD5(encryptedFullFilePath)
        if (fileNameHash != str(id)):
            sys.exit("Hash not equal!")
        if isDir:
            encryptedFullFilePath += "/"
            fileOffsetList.extend(_buildFileOffsetList(decryptedFullFilePath, encryptedFullFilePath, fileNameHash, cursor, key, iv))
        else:
            fileOffsetList.append((decryptedFullFilePath, offset))
    return fileOffsetList

# extract, decrypt and uncompress a chunk from the bucket
def extractChunk(bucketId, indexOffset, key, iv):
    poolIndexDir = os.path.join(poolDir, "0/0")

    poolIndexFileName = findFile(poolIndexDir, poolIndexTemplate.format(bucketId))
    poolIndexEntry = readDataFromFile(poolIndexFileName, indexOffset, 28)
    chunkSize = struct.unpack(">I", poolIndexEntry[0:4])[0]
    chunkOffset = struct.unpack(">I", poolIndexEntry[4:8])[0]
    chunkOriginalSize = struct.unpack(">I", poolIndexEntry[8:12])[0]
    chunkChecksum = poolIndexEntry[12:28]

    bucketFileName = findFile(poolIndexDir, poolBucketTemplate.format(bucketId))
    chunkCipherContent = readDataFromFile(bucketFileName, chunkOffset, chunkSize)
    chunkCompressedContent = decryptAESCBC(chunkCipherContent, key, iv)
    chunkUncompressedContent = uncompressLz4(chunkCompressedContent, chunkOriginalSize)
    if hashMD5(chunkUncompressedContent) != chunkChecksum:
        sys.exit("Chunk checksum not matched!")
    return chunkUncompressedContent

# get a list of bucket ID and offset tuples from the chunk index file
def getChunkIndexLocations(chunkDescriptorOffsets):
    chunkIndexLocations = []
    chunkIndexFile = findFile(chunkIndexDir, "0.idx")
    with open(chunkIndexFile, "rb") as chunkIndex:
        for chunkDescriptorOffset in chunkDescriptorOffsets:
            chunkIndex.seek(chunkDescriptorOffset)
            chunkDescriptorEntry = chunkIndex.read(16)
            bucketId = struct.unpack(">I", chunkDescriptorEntry[0:4])[0]
            bucketIndexOffset = struct.unpack(">I", chunkDescriptorEntry[4:8])[0]
            bucketUnknownData = chunkDescriptorEntry[8:16] #possibly version and/or compression information
            chunkIndexLocations.append((bucketId, bucketIndexOffset))
    return chunkIndexLocations

# extract all chunks of a file and save them to fileName using the file chunks index
def extractChunks(fileName, fileChunksIndexId, fileChunksOffset, key, iv):
    fileChunksIndexPath = os.path.join(configDir, fileChunkIndexTemplate.format(fileChunksIndexId))
    fileChunksIndexFile = findFile(fileChunksIndexPath, "0.idx")

    chunkOffsets = []
    with open(fileChunksIndexFile, "rb") as fileChunksIndex:
        header = fileChunksIndex.read(4)
        if (header != magicIndexHeader):
            sys.exit("Failed to open index file")
        fileChunksIndex.seek(fileChunksOffset)
        fileChunksEntry = fileChunksIndex.read(12)
        fileChunksUnknownData = fileChunksEntry[0:8]
        numberOfChunks = struct.unpack(">I", fileChunksEntry[8:12])[0] >> 3
        for i in range(0, numberOfChunks):
            chunkOffset = struct.unpack(">Q", fileChunksIndex.read(8))[0] #possibly chunkOffset only 4 bytes long
            chunkOffsets.append(chunkOffset)

    chunkLocations = getChunkIndexLocations(chunkOffsets)
    extractFileName = os.path.join(extractDir, fileName)
    extractFileDir = os.path.dirname(extractFileName)

    if not os.path.exists(extractFileDir):
        os.makedirs(extractFileDir)
    with open(extractFileName, "wb+") as outFile:
        for (bucketId, indexOffset) in chunkLocations:
            extractedData = extractChunk(bucketId, indexOffset, key, iv)
            outFile.write(extractedData)

# extract and save a file from the virtual file table with offset fileOffset to fileName
def extractFile(fileName, fileOffset, key, iv):
    if fileOffset < 0: # config.dss file in @AppConfig has file offset -1
        return
    virtualFileIndexFile = findFile(virtualFileIndexDir, "0.idx")
    with open(virtualFileIndexFile, "rb") as virtualFileIndex:
        header = virtualFileIndex.read(4);
        if (header != magicIndexHeader):
            sys.exit("Failed to open index file")
        virtualFileIndex.seek(fileOffset)
        fileEntry = virtualFileIndex.read(56)
        fileUnknownData1 = fileEntry[0:48] #possibly file meta information
        fileChunksIndexId = struct.unpack(">H", fileEntry[48:50])[0]
        fileUnknownData2 = fileEntry[50:52]
        fileChunksOffset = struct.unpack(">I", fileEntry[52:56])[0]
        extractChunks(fileName, fileChunksIndexId, fileChunksOffset, key, iv)

# decrypt the AES decryption parameters (key and iv) for file decryption using the private RSA key
def getFileDecryptionParameter(rsaPrivateKey):
    decryptionParameterDb = findFile(poolDir, "vkey.db")
    conn = sqlite3.connect(decryptionParameterDb)
    cursor = conn.cursor()
    cursor.execute("SELECT rsa_vkey, rsa_vkey_iv, checksum FROM vkey WHERE version_id = (SELECT MAX(version_id) FROM vkey)")
    res = cursor.fetchone()
    encryptedFileKey = str(res[0])
    encryptedFileIv = str(res[1])
    checksum = str(res[2])

    encryptedParameterHash = hashMD5(encryptedFileKey + fileKeySalt + encryptedFileIv)
    if (encryptedParameterHash != checksum):
        sys.exit("Checksum test failed")

    fileKey = decryptPrivateRSA(encryptedFileKey, rsaPrivateKey)
    fileIv = decryptPrivateRSA(encryptedFileIv, rsaPrivateKey)
    return (fileKey, fileIv)

# read the key file
keyFile = findFile(configDir, "encKeys")
(passwordHash, encryptedRsaPrivateKey) = readKeyFile(keyFile)

# verify the password
password = getpass.getpass("Please enter your password: ")
if not verifyPassword(password, passwordHash):
    sys.exit("Wrong password entered")

# extract the RSA private key
unikey = readUnikeyFromConfig()
rsaPrivateKey = decryptRsaPrivateKey(encryptedRsaPrivateKey, password, unikey)
writeDataToFile(rsaPrivateKeyFile, rsaPrivateKey)

# build a list of all available files and their offsets in the virtual file table
fileOffsetList = buildFileOffsetList(rsaPrivateKey, unikey)

# decrypt the AES decryption parameter for file decryption
(fileKey, fileIv) = getFileDecryptionParameter(rsaPrivateKey)

# extract and decrypt all files
for (file, offset) in fileOffsetList:
    extractFile(file, offset, fileKey, fileIv)
