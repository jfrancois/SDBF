#!/usr/bin/perl

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


print "n-gram analysis and stats \n";

open(FIN,$ARGV[0])|| die "impossible opening file";
open(FOUT,">".$ARGV[2])|| die "impossible opening file";

#print "value for n-gram\n";
$val=$ARGV[1];
open(FOUT2,">".$ARGV[3])|| die "impossible opening file";


#print FOUT "Selected value for n-gram: $val\n";

$valueLengthDomain=0;			#get domain length in chars with all special letters as 0-9,.-/
$counter=0;				# count instances in file
$lengthDom0=0;				#count length of toplevel
$lengthDom1=0;				#count length of domain
$lengthDom2=0;				#count length of 1st sublevel
$lengthDom3=0;				#count length of 2nd sublevel
$domsup3=0;
$domeq2=0;
$domeq1=0;
$domeq0=0;
$all=0;
$wordsfordomain=0;
$wordsfordomain0=0;
$wordsfordomain1=0;
$wordsfordomain2=0;
$wordsfordomain3=0;




while ($l=<FIN>){
 
  chomp($l);
  $l = lc $l;

  @word = split (/\./, $l);
  $wordsfordomain += ($#word+1);
  if (($#word+1)<=4){
  	$numberElements{$#word+1} +=1;	#get number of all subdomain elements host.hercules.uni.lu = 4
  }else{
        $numberElements{4} +=1;
   }
   if ($#word >=3){
	$domsup3++;
        $firstchar0{substr($word[$#word],0,1)} +=1;
        $lengthDom0{length($word[$#word])} +=1;	
	$wordsfordomain0 += 1;				
  	for ($t0=0;$t0<=(length($word[$#word]-$val));$t0++){     	# calculate most common n-grams for all 4 domain parts separately
	  $tedo0= substr($word[$#word],$t0,$val);
	  if (length($tedo0) == $val){			
	    $dom0{$tedo0} +=1;	
	    $firstchar0ngram{substr($tedo0,0,1)} +=1;
	  }
        } 
      $firstchar1{substr($word[$#word-1],0,1)} +=1;
      $lengthDom1{length($word[$#word-1])} +=1;
      $wordsfordomain1 += 1;
      for ($t1=0;$t1<=(length($word[$#word-1]-$val));$t1++){		#uni.lu	--> uni ngram
	   $tedo1= substr($word[$#word-1],$t1,$val);
	   if (length($tedo1) == $val){
	     $dom1{$tedo1} +=1;
	     $firstchar1ngram{substr($tedo1,0,1)} +=1;
	   
	   }
       }
      $firstchar2{substr($word[$#word-2],0,1)} +=1;
      $lengthDom2{length($word[$#word-2])} +=1;
      $wordsfordomain2 += 1;
      for ($t2=0;$t2<=(length($word[$#word-2]-$val));$t2++){		#hercules.uni.lu --> hercules
	    $tedo2= substr($word[$#word-2],$t2,$val);
	    if (length($tedo2) == $val){
	      $dom2{$tedo2} +=1;
	      $firstchar2ngram{substr($tedo2,0,1)} +=1;
	    
   	    }
      }
      $firstchar3{substr($word[$#word-3],0,1)} +=1;
      $lengthDom3{length($word[$#word+3])} +=1;
      $wordsfordomain3 += 1;
       for ($t3=0;$t3<=(length($word[$#word-3]-$val));$t3++){		#host.hercules.uni.lu --> host
	    $tedo3= substr($word[$#word-3],$t3,$val);
	    if (length($tedo3) == $val){
	       $dom3{$tedo3} +=1;
	       $firstchar3ngram{substr($tedo3,0,1)} +=1;
	   
	    }
       }

   }
   if ($#word ==2){
	$domeq2++;
        $firstchar0{substr($word[$#word],0,1)} +=1;
        $lengthDom0{length($word[$#word])} +=1;	
        $wordsfordomain0 += 1;				
  	for ($t0=0;$t0<=(length($word[$#word]-$val));$t0++){     	# calculate most common n-grams for all 4 domain parts separately
	  $tedo0= substr($word[$#word],$t0,$val);
	  if (length($tedo0) == $val){			#.lu --> top-level ngram
	    $dom0{$tedo0} +=1;	
	    $firstchar0ngram{substr($tedo0,0,1)} +=1;
	  }
        } 
      $firstchar1{substr($word[$#word-1],0,1)} +=1;
      $lengthDom1{length($word[$#word-1])} +=1;
      $wordsfordomain1 += 1;
      for ($t1=0;$t1<=(length($word[$#word-1]-$val));$t1++){		#uni.lu	--> uni ngram
	   $tedo1= substr($word[$#word-1],$t1,$val);
	   if (length($tedo1) == $val){
	     $dom1{$tedo1} +=1;
	     $firstchar1ngram{substr($tedo1,0,1)} +=1;
	   
	   }
       }
      $firstchar2{substr($word[$#word-2],0,1)} +=1;
      $lengthDom2{length($word[$#word-2])} +=1;
      $wordsfordomain2 += 1;
      for ($t2=0;$t2<=(length($word[$#word-2]-$val));$t2++){		#hercules.uni.lu --> hercules
	    $tedo2= substr($word[$#word-2],$t2,$val);
	    if (length($tedo2) == $val){
	      $dom2{$tedo2} +=1;
	      $firstchar2ngram{substr($tedo2,0,1)} +=1;
	    
   	    }
      }
  }
   if ($#word ==1){
	$domeq1++;
        $firstchar0{substr($word[$#word],0,1)} +=1;
        $lengthDom0{length($word[$#word])} +=1;	
        $wordsfordomain0 += 1;				
  	for ($t0=0;$t0<=(length($word[$#word]-$val));$t0++){     	# calculate most common n-grams for all 4 domain parts separately
	  $tedo0= substr($word[$#word],$t0,$val);
	  if (length($tedo0) == $val){			
	    $dom0{$tedo0} +=1;	
	    $firstchar0ngram{substr($tedo0,0,1)} +=1;
	  }
        } 
      $firstchar1{substr($word[$#word-1],0,1)} +=1;
      $lengthDom1{length($word[$#word-1])} +=1;
      $wordsfordomain1 += 1;
      for ($t1=0;$t1<=(length($word[$#word-1]-$val));$t1++){		#uni.lu	--> uni ngram
	   $tedo1= substr($word[$#word-1],$t1,$val);
	   if (length($tedo1) == $val){
	     $dom1{$tedo1} +=1;
	     $firstchar1ngram{substr($tedo1,0,1)} +=1;
	   
	   }
       }   
  }
  
  $valueLengthDomain += length($l);		#calculate overall length of domains in letters
  @letters = split(//,$l);    			#calculate generated alphabet, count letters numbers, '.', ','
  for ($i=0;$i<=$#letters;$i++){
	$allchars{$letters[$i]} +=1;
	$all++;
   }  
  print ".";
  $counter +=1;	# count all elements in file

}

print "$domsup3 ; $domeq2 ; $domeq1 ; $domeq0\n";
print "$wordsfordomain0; $wordsfordomain1;$wordsfordomain2;$wordsfordomain3;\n";
#--------

@indexes = keys(%allchars);
@index_domainlengthWords = keys(%numberElements);   	#amount of word in domain name

@index_lengthDom0 = keys(%lengthDom0);
@index_lengthDom1 = keys(%lengthDom1);
@index_lengthDom2 = keys(%lengthDom2);
@index_lengthDom3 = keys(%lengthDom3);

@index_firstchar0 = keys(%firstchar0);
@index_firstchar1 = keys(%firstchar1);
@index_firstchar2 = keys(%firstchar2);
@index_firstchar3 = keys(%firstchar3);
@index_dom0 = keys(%dom0);
@index_dom1 = keys(%dom1);
@index_dom2 = keys(%dom2);
@index_dom3 = keys(%dom3);

@index_firstchar0ngram = keys(%firstchar0ngram);
@index_firstchar1ngram = keys(%firstchar1ngram);
@index_firstchar2ngram = keys(%firstchar2ngram);
@index_firstchar3ngram = keys(%firstchar3ngram);

#------------
print FOUT "# Amount of domain names: $counter\n";

$avgdom= $valueLengthDomain/$counter;
print FOUT "# Average domain length considering all characters: $avgdom\n";
#------------

#-----------
print FOUT "# Character frequences\n";
foreach(sort(@indexes)){   
        print FOUT $_,": ",$allchars{$_}/$all,"\n";
}


#print FOUT "# Generated alphabet:\n";
#foreach $key(sort{$frequency{$b} <=> $frequency{$a}} keys %frequency){
#   print FOUT "$key ";
#}

#----------
print FOUT "# Words of domain names :\n";
foreach(sort(@index_domainlengthWords)){
    if ($_<=4){
    $freq_dom= $numberElements{$_}/$counter;
    #print FOUT $_,": ",$numberElements{$_},"\n";
    print FOUT $_,": ",$freq_dom,"\n";
   }
}
#----------

print FOUT "\n# distribution of word-length per domain word\n";
print FOUT "level 0: ";
foreach(sort(@index_lengthDom0)){
       print FOUT $_,": ",$lengthDom0{$_}/$wordsfordomain0,",";
}
print FOUT "\n";
print FOUT "level 1: ";
foreach(sort(@index_lengthDom1)){
       print FOUT $_,": ",$lengthDom1{$_}/$wordsfordomain1,",";
}
print FOUT "\n";
print FOUT "level 2: ";
foreach(sort(@index_lengthDom2)){
       print FOUT $_,": ",$lengthDom2{$_}/$wordsfordomain2,",";
}
print FOUT "\n";
print FOUT "level 3: ";
foreach(sort(@index_lengthDom3)){
     if ($#index_lengthDom3!=0){  print FOUT $_,": ",$lengthDom3{$_}/$wordsfordomain3,","};
}
print FOUT "\n";
#----------
print FOUT "\n# Most occurring first characters:\n";
print FOUT "level 0: ";
foreach(sort(@index_firstchar0)){
    print FOUT $_,": ",$firstchar0{$_}/$wordsfordomain0,",";
}
print FOUT "\n";

print FOUT "level 1: ";
foreach(sort(@index_firstchar1)){
    print FOUT $_,": ",$firstchar1{$_}/$wordsfordomain1,", ";   
}
print FOUT "\n";

print FOUT "level 2: ";
foreach(sort(@index_firstchar2)){
    if ($#index_firstchar2>0){print FOUT $_,": ",$firstchar2{$_}/$wordsfordomain2,","; }   
}
print FOUT "\n";

print FOUT "level 3: ";
foreach(sort(@index_firstchar3)){
   if($#index_firstchar3 >0){ print FOUT $_,": ",$firstchar3{$_}/$wordsfordomain3,","; } 
}
print FOUT "\n";
#print FOUT "\nGenerated alphabet for 2subdomain:\n";
#foreach $key3(sort{$firstchar3{$b} <=> $firstchar3{$a}} keys %firstchar3){
#   print FOUT "$key3 ";
#}

#---------------

#print FOUT2 "level 0: ";
foreach(sort(@index_dom0)){
	$test=substr($_,0,1);
	$testngram= $_;
	$val= $dom0{$_};
	#print "$test-$val\n";
	foreach(sort(@index_firstchar0ngram)){
		$testchar=$_;
		#print "$testchar";
          	if ($test eq $testchar){
		   #print "$testchar-$firstchar0ngram{$_} = $test/$val";
		   $freq= $val/$firstchar0ngram{$_};
                   print FOUT2 "0 $testngram: $freq\n";	
	       }
	}
}

print FOUT2 "level1:\n";
foreach(sort(@index_dom1)){	 
	   
	$test=substr($_,0,1);
	$testngram= $_;
	$val= $dom1{$_};
	#print "$test-$val\n";
	foreach(sort(@index_firstchar1ngram)){
		$testchar=$_;
		#print "$testchar";
          	if ($test eq $testchar){
		   #print "$testchar-$firstchar1ngram{$_} = $test/$val\n";
		   $freq= $val/$firstchar1ngram{$_};
                   print FOUT2 "1 $testngram: $freq\n";	
	       }
	}
}

print FOUT2 "level2:\n";
foreach(sort(@index_dom2)){	 
	   
	$test=substr($_,0,1);
	$testngram=$_;
	$val= $dom2{$_};
	#print "$test-$val\n";
	foreach(sort(@index_firstchar2ngram)){
		$testchar=$_;
		#print "$testchar";
          	if ($test eq $testchar){
		   #print "$testchar-$firstchar2ngram{$_} = $test/$val\n";
		   $freq= $val/$firstchar2ngram{$_};
                   print FOUT2 "2 $testngram: $freq\n";	
	       }
	}
}
print FOUT2 "level3:\n";
foreach(sort(@index_dom3)){	 
	   
	$test=substr($_,0,1);
	$testngram=$_;
	$val= $dom3{$_};
	#print "$test-$val\n";
	foreach(sort(@index_firstchar3ngram)){
		$testchar=$_;
		#print "$testchar";
          	if ($test eq $testchar){
		   #print "$testchar-$firstchar3ngram{$_} = $test/$val\n";
		   $freq= $val/$firstchar3ngram{$_};
                   print FOUT2 "3 $testngram: $freq\n";	
	       }
	}
}

#---------


#-----------

close FOUT;
close FIN;
close FOUT2;
close FOUT3;
