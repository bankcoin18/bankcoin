apt install aptitude
aptitude install  miniupnpc libminiupnpc-dev

apt-get install qt5-default qt5-qmake qtbase5-dev-tools qttools5-dev-tools build-essential libboost-dev libboost-system-dev libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev libssl-dev libdb++-dev
cd /home/oanhle/eclipse-workspace/bank
cd src
make -f makefile.unix
chmod -R 777 /home/oanhle/eclipse-workspace/bank/src


touch .bank/bank.conf
vim .bank/bank.conf
added rpcuser & rpcpassword
start wallet
 ./bankd --daemon -txindex
// check processing
 pidof bankd
//





