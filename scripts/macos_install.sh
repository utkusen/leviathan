sudo easy_install pip
brew install git
git clone https://github.com/robertdavidgraham/masscan
cd masscan
make
cp bin/masscan /usr/local/bin/
cd ..
brew install ncrack -y
sudo pip install -r requirements.txt --ignore-installed six

