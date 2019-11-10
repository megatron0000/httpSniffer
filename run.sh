while [ 1 ]
do
  time=`date +"%Y-%m-%d %T"`
  ./nfqueue.out > "data/logs/$time" 2>&1
done