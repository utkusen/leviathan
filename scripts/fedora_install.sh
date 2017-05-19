sudo dnf clean all && sudo dnf --refresh upgrade
sudo dnf -y install ncrack masscan python python-devel python-pip git gcc gcc-c++ make automake libpcap-devel kernel-devel kernel-headers openssl openssl-devel libssh-devel libffi-devel redhat-rpm-config
pip install --user -r requirements.txt
