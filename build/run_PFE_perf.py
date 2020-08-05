#!/bin/bash

# This script can be used to automatically run experiments for
# multiple numbers of gates (10 iterations each)

r=$1

if [ -n "$r" ] && [ "$r" -ge 0 ] && [ "$r" -le 1 ]
then
	echo "r = $r"
else
        echo -e "Error: Missing argument.\n"
        echo "Usage:"
        echo "- Run the server: ./run_PFE_perf.sh 0"
        echo "- Run the client: ./run_PFE_perf.sh 1"
	exit
fi

make
if [ $? -ne 0 ];
then
	echo "make failed"
	exit
fi

cs=(SERVER CLIENT)
clientserver=${cs[$r]}
echo $clientserver

fileprefix="perf_`date +'%Y-%m-%d-%H%M'`_${clientserver}_"
echo $fileprefix

for g in 1000 10000 100000 1000000
do
	echo "Running with g = $g gates"
	for i in {1..10}
	do
                # edit the next line to run on a different servers
                # example: bin/millionaire_prob_test -r $r -g $g -a 10.10.10.10 >> $fileprefix$g
		bin/millionaire_prob_test -r $r -g $g >> $fileprefix$g
		echo -n "[$i] "
	done
	echo ""

	# parsing performance outputs
	time_total=`cat $fileprefix$g | grep Total\ = | awk '{ sum += $3} END { print sum/10}'`
	echo "Runtime (averaged): $time_total"

done


