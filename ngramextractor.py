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
import pandas as pd

import matplotlib.pyplot as plt
from sklearn import datasets
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings("ignore")
import seaborn as sns
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import KFold
from sklearn.model_selection import cross_val_score
from numpy import mean
from numpy import std
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score
from sklearn.metrics import mean_squared_error
from sklearn.metrics import r2_score

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
            isMalware.append(1)
        else:
            isMalware.append(0)
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
            filem.write(str(isMalware[i]))
            filem.write("\n")
        else: 
            fileb.write(", ".join(map(str, ngrams_final[i])))
            fileb.write(str(isMalware[i]))
            fileb.write("\n")
    filem.close()
    fileb.close()

    #return keyslist
    return ngrams_final, isMalware

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
n_size = 1
target_directory = "sample/"
keylist = 0 

#Extraction of ngrams:
ngrams, isMal = extract_ngrams(target_directory, n_size)

import random
shuffler = list(zip(ngrams, isMal))
random.shuffle(shuffler)
ngrams, isMal = zip(*shuffler)

dataset = pd.DataFrame(ngrams)
print(dataset)

datasetMB = pd.DataFrame(isMal)
print(datasetMB)

X, y = dataset, datasetMB

kf = KFold(n_splits=10)
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
regressor = RandomForestClassifier(max_depth=2, random_state=0)
for train_index, test_index in kf.split(X):

    x_train, x_test = X.iloc[train_index], X.iloc[test_index]
    y_train, y_test = y.iloc[train_index], y.iloc[test_index]

    regressor.fit(x_train,y_train)
    prediction = regressor.predict(x_test)

    print('TN/FP/FN/TP', confusion_matrix(y_test, prediction).ravel())
    print('\n')



