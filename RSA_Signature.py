# This program uses the pycrypt library version 2.6.1 (http://www.pycrypto.org/)
# available by running the installation command: "pip install pycrypt".  You may
# have to install "python-pip" prior to running this command.

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from random import *


# The "transaction_data" class holds the transaction data and calculates the signatures for
# each transaction.
class transaction_data:
    # the constructor sets up the transaction data and signs the transaction
    def __init__(self, patient_key, medical_key, date, amount):
        self.err = ""  # explanatory variable in case an error is generated

        patient_priv_key = patient_key
        patient_pub_key = patient_key.publickey()
        medical_priv_key = medical_key
        medical_pub_key = medical_key.publickey()

        self.ppubkey = patient_pub_key.exportKey("PEM")  # FIELD #1
        self.mpubkey = medical_pub_key.exportKey("PEM")  # FIELD #2
        self.date = date  # FIELD #3
        self.amount = amount  # FIELD #4

        # concatenating the data fields
        data = self.ppubkey + self.mpubkey + date + "{:.2f}".format(amount)
        # hashing the concatenated data
        data_hash = SHA256.new(data)
        # encrypting the hash with the patient's private key to sign the transaction
        self.psign = PKCS1_v1_5.new(patient_priv_key).sign(data_hash)  # FIELD #5
        # concatenating the data and the customer signature field
        d_plus_psign = data + self.psign
        # hashing the concatenated data
        dppsign_hash = SHA256.new(d_plus_psign)
        # encrypting the hash with the medical authority's private key to sign the transaction
        self.msign = PKCS1_v1_5.new(medical_priv_key).sign(dppsign_hash)  # FIELD #6

    # the verify function simply checks the data integrity of a single transaction
    def verify_transaction(self):
        self.err = ""
        patient_pub_key = RSA.importKey(self.ppubkey)
        medical_pub_key = RSA.importKey(self.mpubkey)

        # concatenating the data fields
        data = self.ppubkey + self.mpubkey + self.date + "{:.2f}".format(self.amount)
        # hashing the concatenated data
        data_hash = SHA256.new(data)
        # encrypting the hash with the patient's private key to sign the transaction
        if PKCS1_v1_5.new(patient_pub_key).verify(data_hash, self.psign):
            d_plus_psign = data + self.psign
            dppsign_hash = SHA256.new(d_plus_psign)
            if PKCS1_v1_5.new(medical_pub_key).verify(dppsign_hash, self.msign):
                return True
            else:
                self.err = "Signature verification against medical authority's data has failed for the transaction"
                return False
        else:
            self.err = "Signature Verification against patient's data has failed for the transaction"
            return False

    def show_transaction(self):
        if self.verify():
            validity = "valid"
        else:
            validity = "invalid"
        print(self.date + "  $" + "{:.2f}".format(self.amount) + "(" + validity + ")")


# The Block_medical class contains all of the data used to describe each block.  It
# automatically calculates the required hashes and signatures, and has the
# capability to verify internal consistency.
class Block_medical:
    # the constructor sets all fields according to arguments provided
    # num       = the index of the block
    # miner_key = the private key of the miner creating the block
    # trans     = the transaction fields for the block
    # prev_hash = the "bhash" of the preceding block
    def __init__(self, num, miner_key, trans, prev_hash):
        self.err = ""  # explanatory variable in case an error is generated
        self.errnum = 0  # additional data to be passed with error
        self.seq = num  # assign a sequence number (FIELD #7)

        # if num is zero, this is the genesis block
        if (num == 0):
            self.bhash = SHA256.new(0).hexdigest()
            prev_hash = self.bhash
            # creating a hash of fields 6-8, for genesis block 6 & 7 are zeroes
            block_hash = SHA256.new(prev_hash)
        else:
            self.btrans = trans  # transfer the data from the transaction to this block
            # concatenate all block data into a single string
            bdata = trans.ppubkey + trans.mpubkey + trans.date + "{:.2f}".format(trans.amount) \
                    + trans.psign + trans.msign + str(num)
            # the hash created from these concatenated fields will be used to link the
            # blocks together
            self.bhash = SHA256.new(bdata).hexdigest()
            # creating a hash of fields 6-8
            block_hash = SHA256.new(trans.msign + str(num) + prev_hash)

        # for every block except the genesis block, this is the previous block's bhash
        self.phash = prev_hash  # FIELD #8
        # creating a signed copy to be stored in the chain
        self.msig = PKCS1_v1_5.new(miner_key).sign(block_hash)  # FIELD #9
        self.minerpubkey = miner_key.publickey().exportKey("PEM")

    # verifies all block signatures
    def verify(self):
        self.err = ""
        mpub = RSA.importKey(self.minerpubkey)
        if (self.seq == 0):
            # verifying the genesis block via a PKCS1 protocol verification procedure since there is no transaction data
            zerohash = SHA256.new(0).hexdigest()
            block_hash = SHA256.new(zerohash)
            if (not PKCS1_v1_5.new(mpub).verify(block_hash, self.msig)):
                self.err = "Signature verification against miner failed for genesis block"
                self.errnum = 0
                return False
        else:
            # verifying that the customer and merchant signatures check out
            if (not self.btrans.verify()):
                self.err = "Transaction Verification failure against patient and medical authority's public keys"
                self.errnum = self.seq
                return False
            # concatenate all block data into a single string
            bdata = self.btrans.ppubkey + self.btrans.mpubkey + self.btrans.date \
                    + "{:.2f}".format(self.btrans.amount) + self.btrans.csign \
                    + self.btrans.msign + str(self.seq)
            # calculate the hash to compare against the recorded hash
            test_hash = SHA256.new(bdata).hexdigest()
            if (test_hash != self.bhash):
                self.err = "Inconsistent hash for block and data"
                self.errnum = self.seq
                return False
            # creating a hash of fields to test against the signature
            block_hash = SHA256.new(self.btrans.msign + str(self.seq) + self.phash)
            # test the signature to ensure the integrity of the recorded hash
            if (not PKCS1_v1_5.new(mpub).verify(block_hash, self.msig)):
                self.err = "Signature verification failed for block #" + str(self.seq)
                self.errnum = self.seq
                return False

        return True


class Blockchain:
    # the constructor creates the genesis block and signs it with a miner's private key
    def __init__(self, miner_key):
        self.err = ""  # explanatory variable in case an error is generated
        self.errnum = 0  # additional data to be passed with error
        self.seq = 0  # the constantly incrementing sequence number
        self.blocks = []  # the list of blocks in the chain
        # appending the genesis block
        self.blocks.append(Block_medical(0, miner_key, 0, 0))

    # adds a transaction block to the chain and includes the hash of the previous block's
    # data to ensure that the data is truly linked like a chain
    def add(self, trans, miner_key):
        self.err = ""
        self.seq += 1
        self.blocks.append(Block_medical(self.seq, miner_key, trans, self.blocks[self.seq - 1].bhash))

    # verifies the integrity of the chain and triggers verification checks at every
    # subordinate level (block and then transaction levels) by cascading verification checks
    def verify(self):
        self.err = ""
        for i in range(self.seq + 1):
            if (i == 0):
                if (not self.blocks[0].verify()):
                    self.err = "Genesis block verification failure"
                    self.errnum = 0
                    return False
            else:
                if (self.blocks[i].phash != self.blocks[i - 1].bhash):
                    self.err = "Inconsistent hash between blocks (" + str(i) + "/" + str(i - 1) + ")"
                    self.errnum = i
                    return False
                if (not self.blocks[i].verify()):
                    self.err = "RSA signature verification failure at (block #" + str(i) + ")"
                    self.errnum = i
                    return False
        return True
