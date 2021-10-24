import sys
import os
import string
import struct
import re
import collections
import random
from itertools import product
from collections import Counter
from collections import OrderedDict
from heapq import nlargest

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
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix
import itertools
from itertools import dropwhile
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

def elffilesorter():
    target = "benign_samples/ubiquiti/"
    filelist = os.listdir(target)
    headerlist = []

    targetlist = []
    for val in filelist:
        targetlist.append(target + val)

    for val in targetlist:
        with open(val, 'rb') as f:
            headerlist.append(dict(ELFFile(f).header))

    for i in range (len(headerlist)):
        if headerlist[i]["e_machine"] == "EM_ARM":
            print(filelist[i], file = open("benign_arm_files.txt", "a"))

def readfile(fname):
    with open(fname, "rb") as file:
        content = file.read()
    return content

def extract_ngrams(directory = "sample/", n_size = 1):
    filecount = 0
    #Read every filename in directory:

    #TODO: BUILD RANDOMIZED FILESET WHERE M=B:
    benign_directory = directory + "benign/"
    malware_directory = directory + "malware/"

    benign_filelist = os.listdir(benign_directory)
    malware_filelist = os.listdir(malware_directory)

    sample_size = int(min(len(benign_filelist),len(malware_filelist))-1950)
    
    benign_files = random.sample(benign_filelist, sample_size)
    malware_files = random.sample(malware_filelist, sample_size)

    samplefiles = [benign_directory + s for s in benign_files] + [malware_directory + s for s in malware_files]
    
    del(benign_directory, malware_directory, benign_filelist, malware_filelist, sample_size)

    keyslist = set([])
    ngramdictlist = []
    isMalware = []
    #countersum = collections.defaultdict(int)
    countersum = Counter()

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
        countersum += Counter(ngramslist)
        ngramdictlist.append(vector_ngram)
        filecount += 1
        print(filecount, "Files done.")


    print(countersum)
    input("COUNTERSUM")
    print("Amount of keys: ", len(countersum.keys()))
    print("Amount of values: ", len(countersum.values()))

    print(list(countersum.values())[:10])

    #ThreeHighest = nlargest(10, countersum, key = countersum.get)

    #df = pd.DataFrame([countersum.values()], ["Occurences"], countersum.keys())
    #df = pd.DataFrame(dict(countersum), index=[0])
    #df = pd.DataFrame(countersum, columns=countersum.keys(), index=[0])
    #df.plot(kind='barh')

    toplist = countersum.most_common(len(countersum))
    topkeylist = list()
    topvallist = list()
    for i in range(len(toplist)):
        topkeylist.append(toplist[i][0])
        topvallist.append(toplist[i][1])
    for i in range(len(toplist)):
        print(topkeylist[i],":" ,topvallist[i])

    keylist = list()
    for key in topkeylist:
        keylist.append(str(key))

    params = {'figure.figsize'  : (100, 90),
          'axes.labelsize'  : 20,
          'axes.titlesize'  : 20,
          'xtick.labelsize' : 10,
          'ytick.labelsize' : 5} 

    plt.rcParams.update(params)

    plt.barh(keylist[1:100], topvallist[1:100], height = 0.5, align = 'center')
 
    plt.xlabel('Occurence inside the dataset')
    plt.ylabel('N-gram sample')
    plt.show()

    cntcountersumvefore = len(countersum)

    countersum = Counter({k: countersum for k, countersum in countersum.items() if countersum >= 100})


    print(countersum)
    print("COUNTERSUM NO VALS UNDER x, keys:", len(countersum), "<-", cntcountersumvefore)
    input("")
    
    emptyset = []
    for val in list(countersum.keys()):
        emptyset.append(val)
    emptyset.sort()

    print(len(emptyset))
    print(emptyset)

    #Generate empty dictionary based on every occured ngram:
    keyslist = list(keyslist)
    keyslist.sort()
    print(len(keyslist))

    keyslist = emptyset

    ngram_empty = {}
    for val in keyslist:
        ngram_empty[val] = 0
    print("Empty dictionary generated:", len(ngram_empty), "values.")
    input("Press ENTER to continue.")

    #Update existing ngrams, put them into a final list
    ngrams_final = []
    filecount = 0

    for val in ngramdictlist:
        ngram_base = ngram_empty
        #ngram_base.update(val)
        for key in ngram_base:
            if key in val:
                ngram_base[key] = val[key]
        ngrams_final.append(list(ngram_base.values()))
        filecount += 1
        print(filecount, "ngrams updated and appended to final list. Ngram vector lenght:", len(list(ngram_base.values())))
        del(val)

    input("ENTER")

    filem = open("malware_" + str(n_size) + "grams.txt", "w")
    fileb = open("benign_" + str(n_size) + "grams.txt", "w")
    filecount = 0
    for i in range(len(ngramdictlist)):
        if(isMalware[i]):
            filem.write(", ".join(map(str, ngramdictlist[i])))
            filem.write(str(isMalware[i]))
            filem.write("\n")
        else: 
            fileb.write(", ".join(map(str, ngramdictlist[i])))
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
n_size = 2
target_directory = "sample/arm/"
keylist = 0 

#Extraction of ngrams:
ngrams, isMal = extract_ngrams(target_directory, n_size)

isMB=[]
for i in range(len(ngrams)):
    if i < len(ngrams)/2:
        isMB.append(0)
    else:
        isMB.append(1)

import random
shuffler = list(zip(ngrams, isMal))
random.shuffle(shuffler)
ngrams, isMal = zip(*shuffler)

dataset = pd.DataFrame(ngrams)
print(dataset)

datasetMB = pd.DataFrame(isMal)
print(datasetMB)

input("ENTER")

X, y = dataset, datasetMB

kf = KFold(n_splits=10)

regressor = RandomForestClassifier(max_depth=2, random_state=0)

rfc = RandomForestClassifier(max_depth=2, random_state=0)
knc = KNeighborsClassifier(n_neighbors=3)
svc = make_pipeline(StandardScaler(), SVC(gamma='auto'))

mlalgorithms = [rfc, knc, svc]
conf_mtxs = list()

print("Number of folds: ", KFold.n_splits)

for mlalgo in mlalgorithms:
    for train_index, test_index in kf.split(X):

        x_train, x_test = X.iloc[train_index], X.iloc[test_index]
        y_train, y_test = y.iloc[train_index], y.iloc[test_index]

        mlalgo.fit(x_train,y_train)
        prediction = mlalgo.predict(x_test)

        print(type(mlalgo))
        print('TN/FP/FN/TP', confusion_matrix(y_test, prediction).ravel())
        conf_mtxs.append(confusion_matrix(y_test, prediction))
        print('\n')
        


