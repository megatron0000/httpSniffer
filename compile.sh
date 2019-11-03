clang++ main.cpp -o main.out -lpcap
clang++ -gdwarf nfqueue.cpp -o nfqueue.out -lnetfilter_queue
cp nfqueue.out nonroot.out
sudo setcap cap_net_admin=eip ./nfqueue.out
