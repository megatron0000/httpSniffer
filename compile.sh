g++ main.cpp -o main.out -lpcap
g++ nfqueue.cpp -o nfqueue.out -lnetfilter_queue
sudo setcap cap_net_admin=eip ./nfqueue.out
