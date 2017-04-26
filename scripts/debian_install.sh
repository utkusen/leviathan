apt-get update
sudo apt-get -y install python python-pip git gcc make libpcap-dev build-essential checkinstall libssl-dev libssh-dev libffi-dev python-dev
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
cp bin/masscan /usr/bin/
cd ..
wget https://nmap.org/ncrack/dist/ncrack-0.5.tar.gz
tar -xzf ncrack-0.5.tar.gz
cd ncrack-0.5
./configure
make
sudo make install
cd ..
rm -r ncrack-0.5
rm -r masscan
rm ncrack-0.5.tar.gz
sudo pip install -r requirements.txt