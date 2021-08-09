sudo apt-get install -y curl apt-transport-https ssl-cert ca-certificates gnupg lsb-release
Lf 'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.deb.sh' | sudo -E bash
echo "deb https://pkg.caida.org/os/$(lsb_release -si|awk '{print tolower($0)}') $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/caida.list
sudo wget -O /etc/apt/trusted.gpg.d/caida.gpg https://pkg.caida.org/os/ubuntu/keyring.gpg

sudo apt update; sudo apt-get install bgpstream

echo "Setup complete"
echo "Compiling bgpstream-pfx-mon.c"
gcc bgpstream-pfx-mon.c  -lbgpstream -o pfx-monitoring
echo "Scraping BGP data"
./pfx-monitoring > bgp-jul26-1am-5am.txt
echo "Filtering duplicate BGP advertisements"
python3 prefix-filter.py bgp-jul26-1am-5am.txt > bgp-jul26-1am-5am-filtered.txt
echo "Counting prefixes"
python3 prefix_count.py bgp-jul26-1am-5am-filtered.txt > bgp-jul26-1am-5am-pfx-counts.txt


