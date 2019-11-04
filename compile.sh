clang++ main.cpp -o main.out -lpcap
clang++ -gdwarf nfqueue.cpp -o nfqueue.out -lnetfilter_queue
sudo cp nfqueue.out nonroot.out # useful for debug only
sudo setcap cap_net_admin=eip ./nfqueue.out
