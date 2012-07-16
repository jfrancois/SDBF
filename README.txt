SDBF (Smart DNS Brute-Forcer) package propose 3 tools to generate 
and discover domain names or dubdomains of a domain names.


Release: 
         sdbf-1.0
Date   :
         15-07-2012
Authors: 
	 Cynthia Wagner, University of Luxembourg, Luxembourg
         Samuel Marchal, University of Luxembourg, Luxembourg
	 Jérôme François, University of Luxembourg, Luxembourg
         Radu STATE, University of Luxembourg, Luxembourg
	 Thomas Engel, University of Luxembourg, Luxembourg
         

Organism attachement:
	SnT- Interdisciplinary Centre for Security, Reliability and Trust
	Université du Luxembourg
	Campus Kirchberg- Office F210
	6, rue Richard Coudenhove- Kalergi
	L- 1359 Luxembourg

License: 
         GNU General Public License 3.0


**First, use markov.pl script to generate 2 files base on a list
  of domain names contained in a txt file (1 domain per line) :

- a "distribution" file which contains character frequencies,
  length distribution of domains, length distribution of names
  for differents domain levels...

- a "transition" file which contains probability of transition
  from a n-gram to the following character

usage : ./markov.pl REAL_DOMAIN_LIST N-GRAM_SIZE OUTPUT_DISTRIBUTON_FILE OUTPUT_TRANSITION_FILE
ex : ./markov.pl domains.txt 3 distribution.txt transition.txt


Requirements:
	Install pybloom http://pypi.python.org/pypi/pybloom



**Second, use sdbf.py script to generate new domain names based
  on the "distribution" and the "transition" files previously generated
  (sample "distribution" and "transition" files are given in the package)

Options :

  -h, --help            show this help message and exit
  -d FILE, --distribution=FILE
                        general distribution file (with length frequencies)
  -t FILE, --transition=FILE
                        character transition matrix
  -e EPS, --epsilons=EPS
                        epsilon values for empty values in transition matrix
  -b EPS_START, --epsilons-start=EPS_START
                        epsilon values for empty values in starting character
                        distribution
  -l EPS_LENGTH, --epsilons-length=EPS_LENGTH
                        epsilon values for empty values in length distribution
  -n NUMBER_GENERATE, --number-to-generate=NUMBER_GENERATE
                        number of names to generate
  -s SUFFIX, --suffix=SUFFIX
                        suffix value
  -p PREFIX, --prefix=PREFIX
                        prefix value
  -w LEVELS, --word-level=LEVELS
                        word levels to generate
  --cw=CWORDS, --custom-words=CWORDS
                        length (in words) of the custom words (prefix and
                        suffix)
  --mxw=MXW, --max-length-words=MXW
                        maximal word lengths (may be adjusted regarding the
                        training)
  --miw=MIW, --min-length-words=MIW
                        minimal word lengths (may be adjusted regarding the
                        training)
  -f FILE, --features=FILE
                        if specified the program will generate the different
                        feature for the domains contained in the mentionned
                        file
  -o FILE, --output=FILE
                        output file with accessible names or feature

ex : 

./sdbf.py -d distribution.txt -t transition.txt -n 1000 -o results.txt
# probe of 1000 generated domain names and store positive results in results.txt


./sdbf.py -d distribution.txt -t transition.txt -n 1000 -p www. -w "0 1" -o results.txt
# probe of 1000 generated domain names starting with "www." and of size 3 (level 0 and 1 generated)
  (ex : www.amazon.com) and store positive results in results.txt

./sdbf.py -d distribution.txt -t transition.txt -n 5000 -s google.com --cw 2 -w 2 -o results.txt
# probe of 5000 generated domain names ending with "google.com" and of size 3 (level 2 generated)
  (ex : mail.google.com) and store positive results in results.txt





!!!!!!!!!!!!!!! To use the third tool of the package you need to download :

* DISCO at http://www.linguatools.de/disco/disco-1.2.jar
  and the following disctionnaries (follow the instructions given on the website for 
  dictionnary installation)
	- http://www.linguatools.de/disco/disco-languagedatapackets_en.html#enwiki
	- http://www.linguatools.de/disco/disco-languagedatapackets_en.html#frwiki
	- http://www.linguatools.de/disco/disco-languagedatapackets_en.html#degen
  create a new folder called "Disco" at the same level of the scripts and copy
  the jar file and the 3 folder corresponding to each dictionnary



**Third, use semanticexp.py script to discover subdomains of a given domain based on a 
  list of existing subdomains (of a common domain) contained in a txt file (1 domain per line)
  this list can be generated from sdbf.py for instance as with the last example.
  three different tools available :
	- semantic exploration (-d)
	- incremental discovery (-p)
	- splitter (-s)

Options:

  -h, --help            show this help message and exit
  -d, --disco           use DISCO semantic tool
  -s, --splitter        use word splitter tool (combined with DISCO)
  -p, --increment       use incremental discovery tool
  -i FILE, --input=FILE
                        domains previously discovered
  -o FILE, --output=FILE
                        output file with accessible names or feature
  -n COUNT, --horizontal=COUNT
                        horizontal depth : number of domains tested per domain
                        in the initial dataset
  -v VERTICAL, --vertical=VERTICAL
                        vertical depth : number of iteration over the new
                        domain lists (only for -d)
  -e, --english         use the english dictionnary (only for -d)
  -g, --german          use the german dictionnary (only for -d)
  -f, --french          use the french dictionnary (only for -d)

ex :

./semanticexp.py -d -egf -i scan_google.com -o semanticexp_google.com -n 100 -v 3
# use DISCO semantic tool with the 3 dictionnaries to discover new subdomains
  100 domains are tested for each subdomains in the initial dataset
  and a maximum of 3 iterations are made (we apply at most 3 times the technique
  on newly discovered domain) results are stored in semanticexp_google.com

./semanticexp.py -sp -i scan_google.com -o semanticexp_google.com -n 50 
# use splitter and incremental discovery tool to discover new subdomains
  50 domains are tested for each subdomains in the initial dataset








