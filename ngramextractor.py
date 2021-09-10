import sys
import os
import string
import struct
import re
import collections
import random
from itertools import product
from collections import Counter

def readfile(fname):
    with open(fname, "rb") as file:
        content = file.read()
    return content

def slidewindow(iterable, size=1):
    i = iter(iterable)
    win = []
    for e in range(0, size):
        win.append(next(i))
    yield win
    for e in i:
        win = win[1:] + [e]
        yield win


def extract_ngrams(directory = "sample/", n_size = 1, ngrams_possiblevalues = 0):
    filecount = 0
    #Read every filename in directory:
    samplefiles = os.listdir(directory)

    for filename in samplefiles:
        #Read a file:
        target = directory + filename
        samplebinary = readfile(target)

        #Split into n byte sections:
        ngramslist = []
        for value in slidewindow(samplebinary,n_size):
            ngramslist.append(tuple(value))
        ngrams = [y for x in ngramslist for y in x]
        #print(ngramslist, file=open("fileoutput.txt", "w"))

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
        print(filecount, "files done.")

def generate_possible_ngramvalues(n_size = 1):
    #Possible values of a byte:
    byte_possiblevalues = []
    for i in range(0x00, 0x100):
        byte_possiblevalues.append(i)
    #print(byte_possiblevalues, file=open("byteoutput.txt", "w"))

    #Possible values of an n-gram:
    ngrams_possiblevalues = list(product(byte_possiblevalues, repeat=n_size))
    #print(ngrams_possiblevalues, file=open("ngramoutput.txt", "w"))
    print("Possible ngrams:", len(ngrams_possiblevalues), "values generated")
    return ngrams_possiblevalues


#------------MAIN FUNCTION:------------

#Setting of n_size and target directory:
n_size = 3
target_directory = "sample/"

#Extraction of ngrams, give target directory, size of n, generated possible ngram values:
extract_ngrams(target_directory, n_size, generate_possible_ngramvalues(n_size))
