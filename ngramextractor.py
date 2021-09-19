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



def extract_ngrams(directory = "sample/", n_size = 1, ngrams_possiblevalues = 0):
    filecount = 0
    #Read every filename in directory:
    samplefiles = os.listdir(directory)

    for filename in samplefiles:
        #Read a file:
        target = directory + filename
        samplebinary = readfile(target)

        #Split into n byte sections:
        ngramslist = list(ngrams(samplebinary, n_size, pad_right = True))

        #Count occurences of unique ngrams:
        vector_ngram = dict(Counter(ngramslist))

        #Generate empty dictionary with keys as all possible ngrams, values initialized to 0:
        ngram_dict = {}
        for i in range(len(ngrams_possiblevalues)):
            ngram_dict[ngrams_possiblevalues[i]] = 0

        #Merge empty dictionary with counted dictionary
        ngram_dict.update(vector_ngram)
        print(filename, ngram_dict.values(), file = open("ngrams_extracted.txt", "a"))
        filecount += 1
        print(filecount, "files done. Vector lenght:", len(ngram_dict))

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
target_directory = "benign_samples/ubiquiti/"
 
#Extraction of ngrams, give target directory, size of n, generated possible ngram values:
extract_ngrams(target_directory, n_size, generate_possible_ngramvalues(n_size))


