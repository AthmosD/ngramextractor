import sys
import os
import string
import struct
import re
import collections
import random
from itertools import product
from collections import Counter
from nltk.util import ngrams
import numpy as np

from elftools.elf.elffile import ELFFile

def readfile(fname):
    with open(fname, "rb") as file:
        content = file.read()
    return content

def extract_ngrams(directory = "sample/", n_size = 1):
    filecount = 0
    #Read every filename in directory:
    samplefiles = []
    for root, directories, files in os.walk(directory, topdown=False):
        for name in files:
            if os.path.isfile(os.path.join(root, name)):
                samplefiles.append(os.path.join(root, name))
        for name in directories:
            if os.path.isfile(os.path.join(root, name)):
                samplefiles.append(os.path.join(root, name))


    keyslist = set([])
    ngramdictlist = []
    isMalware = []

    for filename in samplefiles:
        #Read a file:
        target = str(filename)
        if target.find("malware") > 0:
            isMalware.append(True)
        else:
            isMalware.append(False)
        samplebinary = readfile(target)

        #Split into n byte sections:
        ngramslist = list(ngrams(samplebinary, n_size, pad_right = True, right_pad_symbol = -1))

        #Count occurences of unique ngrams:
        vector_ngram = dict(Counter(ngramslist))
        ngramdictlist.append(vector_ngram)
        #print(vector_ngram)

        #Add new keys to a list:
        for val in vector_ngram.keys():
            keyslist.add(val)
        filecount += 1
        print(filecount, "files done.")

    print(isMalware)
    #Generate empty dictionary based on every occured ngram:
    keyslist = list(keyslist)
    keyslist.sort()
    ngram_empty = {}
    for val in keyslist:
        ngram_empty[val] = 0

    #Update existing ngrams, put them into a final list
    ngrams_final = []
    for val in ngramdictlist:
        ngram_base = ngram_empty
        ngram_base.update(val)
        #print(list(ngram_base.values()), file = open("ngramoutput.txt", "a"))
        print(len(ngram_base))
        ngrams_final.append(list(ngram_base.values()))


    filem = open("malware_" + str(n_size) + "grams.txt", "w")
    fileb = open("benign_" + str(n_size) +"grams.txt", "w")
    for i in range(len(ngrams_final)):
        if(isMalware[i]):
            filem.write(", ".join(map(str, ngrams_final[i])))
            filem.write(str(int(isMalware[i])))
            filem.write("\n")
        else: 
            fileb.write(", ".join(map(str, ngrams_final[i])))
            fileb.write(str(int(isMalware[i])))
            fileb.write("\n")
    filem.close()
    fileb.close()

    return keyslist

def generate_possible_ngramvalues(n_size = 1):
    #Possible values of a byte:
    byte_possiblevalues = []
    for i in range(0x00, 0x100):
        byte_possiblevalues.append(i)
    byte_possiblevalues.append(None)
    #print(byte_possiblevalues, file=open("byteoutput.txt", "w"))

    #Possible values of an n-gram:
    ngrams_possiblevalues_prod = product(byte_possiblevalues, repeat=n_size)
    ngrams_possiblevalues = list(ngrams_possiblevalues_prod)

    #print(ngrams_possiblevalues, file=open("ngramoutput.txt", "w"))
    print("Possible ngrams:", len(ngrams_possiblevalues), "values generated")

    return ngrams_possiblevalues

def extract_header(filename):
    with open(filename, 'rb') as f:
        elffile = ELFFile(f)
    return elffile.header  
    #return elffile.e_ident_raw

#------------MAIN FUNCTION:------------

#Setting of n_size and target directory:
n_size = 2
target_directory = "sample/"
keylist = 0 

#Extraction of ngrams:
keylist = extract_ngrams(target_directory, n_size)
print(keylist)
