#!/usr/bin/python

#################################################################################
#                                                                               #
#    Copyright (C) 2011-2012 Cynthia Wagner, Jerome Francois, Samuel Marchal    #
#                            Radu State, Thomas Engel                           #
#    Copyright (C) 2011-2012 SnT University of Luxembourg                       #
#                                                                               #
#    This file is part of SDBF GPL Edition, a Smart DNS Brute-Forcing Tool      #
#                                                                               #
#    SDBF GPL Edition is free software: you can redistribute it and/or modify   #
#    it under the terms of the GNU General Public License as published by       #
#    the Free Software Foundation, either version 3 of the License, or          #
#    (at your option) any later version.                                        #
#                                                                               #
#    SDBF GPL Edition is distributed in the hope that it will be useful,        #
#    but WITHOUT ANY WARRANTY; without even the implied warranty of             #
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the              #
#    GNU General Public License for more details.                               #
#                                                                               #
#    You should have received a copy of the GNU General Public License          #
#    along with SDBF GPL Edition.  If not, see <http://www.gnu.org/licenses/>.  #
#                                                                               #
#################################################################################


import sys,re,glob,commands
import numpy,math
from optparse import OptionParser
import copy
import time,string,unicodedata
import random
import dns.resolver

from ngrams import segment
from pybloom import BloomFilter


#Model variables
domains_d = []
myBloom = BloomFilter(500000, 0.0001)
domain_ok = {}
tot = 0
totGood = 0
totBad = 0
to_write = ""


def cleanString(s):    # clean the domain names obtained from disco to respect the DNS rules

    if isinstance(s,str):
	 s = unicode(s,"utf8","replace")
	 s = unicodedata.normalize('NFD',s)
	 return s.encode('ascii','ignore')


def read_domains(file_domains):        # exctration from file of all the initials domains
    
    f = open(file_domains)

    for line in f:
        dom = line.strip()
        myBloom.add(dom)
        domains_d.append(dom)


if __name__ == "__main__":
      
    lineparser = OptionParser("")

    lineparser.add_option('-d','--disco', action="store_true",dest='disco', default=False , help="use DISCO semantic tool")  
    lineparser.add_option('-s','--splitter', action="store_true",dest='splitter', default=False ,  help="use word splitter tool (combined with DISCO)")  
    lineparser.add_option('-p','--increment', action="store_true",dest='increment', default=False ,  help="use incremental discovery tool") 

    lineparser.add_option('-i','--input', dest='input', default="scan_pt.lu",type='string',help="domains previously discovered", metavar="FILE")    
    lineparser.add_option('-o','--output', dest='output', default="outsemanticexp.txt",type='string',help="output file with accessible names or feature", metavar="FILE")  

    lineparser.add_option('-n','--horizontal', dest='count', default=50,type=int,help="horizontal depth : number of domains tested per domain in the initial dataset",) 
    lineparser.add_option('-v','--vertical', dest='vertical', default=3,type=int,help="vertical depth : number of iteration over the new domain lists (only for -d)",) 

    lineparser.add_option('-e','--english', action="store_true",dest='english', default=False , help="use the english dictionnary (only for -d)")  
    lineparser.add_option('-g','--german', action="store_true",dest='german', default=False ,  help="use the german dictionnary (only for -d)")  
    lineparser.add_option('-f','--french', action="store_true",dest='french', default=False ,help="use the french dictionnary (only for -d)")   
     
    options, args = lineparser.parse_args()

    read_domains(options.input)

    list_size = len(domains_d)
    domaintested = 0
    passe = 1

    fw = open(options.output,'w')
    fw.write("New domain\t\tOriginal domain\t\tDisco rank (if applicable)\n\n")


    for domain in domains_d:


     pre_suf = domain.split('.',1)
     prefixe = pre_suf[0]
     suffixe = pre_suf[1]

     print domain + " !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"

     if options.disco :

	minuscule = prefixe[0]
	pref_maj = string.upper(minuscule) + prefixe[1:]


	to_test = []
	disco = ""

	if options.english :
	
            commande = "java -jar ./Disco/disco-1.2.jar ./Disco/en-wikipedia-20080101 -bn " + prefixe + " " + str(options.count)
            result = commands.getoutput(commande)
            if string.find(result,"The word ") == -1:
                disco = disco + "\nCHANGE DICTIONNARY\n" + result
	
            commande = "java -jar ./Disco/disco-1.2.jar ./Disco/en-wikipedia-20080101 -bn " + pref_maj + " " + str(options.count)
            result = commands.getoutput(commande)
            if string.find(result,"The word ") == -1:
                disco = disco + "\nCHANGE DICTIONNARY\n" + result

	if options.french :

            commande = "java -jar ./Disco/disco-1.2.jar ./Disco/fr-wikipedia-20080713 -bn " + prefixe + " " + str(options.count)
            result = commands.getoutput(commande)
            if string.find(result,"The word ") == -1:
                disco = disco + "\nCHANGE DICTIONNARY\n" + result

            commande = "java -jar ./Disco/disco-1.2.jar ./Disco/fr-wikipedia-20080713 -bn " + pref_maj + " " + str(options.count)
            result = commands.getoutput(commande)
            if string.find(result,"The word ") == -1:
                disco = disco + "\nCHANGE DICTIONNARY\n" + result

	if options.german :

            commande = "java -jar ./Disco/disco-1.2.jar ./Disco/de-general-20080727 -bn " + prefixe + " " + str(options.count)
            result = commands.getoutput(commande)
            if string.find(result,"The word ") == -1:
                disco = disco + "\nCHANGE DICTIONNARY\n" + result

            commande = "java -jar ./Disco/disco-1.2.jar ./Disco/de-general-20080727 -bn " + pref_maj + " " + str(options.count)
            result = commands.getoutput(commande)
            if string.find(result,"The word ") == -1:
			disco = disco + "\nCHANGE DICTIONNARY\n" + result



    	if disco != "":

            to_test = disco.split("\n")

            index = 0 

            for word in to_test:

                if word == "CHANGE DICTIONNARY":

                    index = 0

                else :

                    domain_name = string.lower(cleanString(word.split('\t')[0] + "." + suffixe))

                    index = index + 1 

                    if not domain_name in myBloom:
                        tot +=1
                        myBloom.add(domain_name)

                        try:
                
                            answers = dns.resolver.query(domain_name,'A')
                
                            totGood +=1
                            print str(totGood+totBad), totGood, totBad, domain_name,"\t\t",domain,"\t\t",str(index),
                            for rdata in answers.rrset:
                                print rdata.to_text(),
                            print "\n"

                            domains_d.append(domain_name)

                            domain_ok[domain_name] = []
                            domain_ok[domain_name].append(domain_name)
                            domain_ok[domain_name].append(domain)
                            domain_ok[domain_name].append(index)

                        except:
                            totBad +=1
                            print str(totGood+totBad), totGood, totBad,domain_name


        		else:
                            try:
				current = domain_ok[domain_name][2]	
				domain_ok[domain_name][2] = min(current,index)
                            except:
				pass

        


        if domaintested == list_size:

            list_size = len(domains_d)
            to_write += "iteration " + str(passe) + ", " + str(tot) + " domains tested, " + str(list_size - domaintested) + " domains discovered\n"
            tot = 0
            passe += 1

            if passe > options.vertical:
                del(domains_d[:])

        domaintested += 1


     if options.increment or options.splitter :

        decoupe = segment(prefixe)    #split the prefix in different parts if possible
    

        if len(decoupe) > 1 and len(decoupe) < 4:        #  if we obtain different part in one suffixe

            i = -1
            allwords = {}

            for part in decoupe:    #for each parts we try to find if it's a number or a word

                i = i + 1
                allwords[i] = []
                allwords[i].append(part)

                disco = ""
                to_test = []


                try:                        # the part is a number, regading the length we create new numbers
                    
                    a = int(part)
	    
                    if options.increment :

                        b = pow(10,len(part))
                        c = len(part)
                        loop = 0
                                      
                        while loop < b :

                            number = str(loop)
                            loop += 1

                            if len(number) < c:

                                allwords[i].append(number)

                                while len(number) < c :
                                    number = "0" + number

                            allwords[i].append(number)

		                           



                except:                   # the part is a word, we try to find similar words regarding the meaning through DISCO 
                
                    if options.splitter :
                        minuscule = part[0]
                        part_maj = string.upper(minuscule) + part[1:]
 

                        commande = "java -jar ./Disco/disco-1.2.jar ./Disco/en-wikipedia-20080101 -bn " + part + " " + str(options.count)         
                        result = commands.getoutput(commande)
                        if string.find(result,"The word ") == -1:
                            disco = disco + result
	
                        commande = "java -jar ./Disco/disco-1.2.jar ./Disco/en-wikipedia-20080101 -bn " + part_maj + " " + str(options.count)
                        result = commands.getoutput(commande)
                        if string.find(result,"The word ") == -1:
                            disco = disco + result




                        if disco != "":

                            to_test = disco.split("\n")

                            for word in to_test:

                                prefixe = string.lower(cleanString(word.split('\t')[0]))
                                allwords[i].append(prefixe)


		    
            
	    to_test = []
            length = len(allwords)

            if length == 2 :
                for first in allwords[0]:
                    for second in allwords[1]:
			to_test.append(first + second + "." + suffixe)


            if length == 3 :
                for first in allwords[0]:
                    for second in allwords[1]:
                        for third in allwords[2]:

                            #pass
                            to_test.append(first + second +third + "." + suffixe)




	    for domain_name in to_test:


		    if not domain_name in myBloom:
			    tot +=1
			    myBloom.add(domain_name)

			    try:
                
				    answers = dns.resolver.query(domain_name,'A')
                
				    totGood +=1
				    print str(totGood+totBad), totGood, totBad, domain_name,"\t\t",domain,
				    for rdata in answers.rrset:
					    print rdata.to_text()
				    

				    fw.write(domain_name+ "\t\t" + domain + "\n")

			    except:
				    totBad +=1
				    print str(totGood+totBad), totGood, totBad,domain_name





    for domain in domain_ok : 
        fw.write(domain_ok[domain][0]+ "\t\t" + domain_ok[domain][1] +  "\t\t" + str(domain_ok[domain][2]) + "\n")

    fw.write("\n" + to_write + "\n")



    fw.close()
