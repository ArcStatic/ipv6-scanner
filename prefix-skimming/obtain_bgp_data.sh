sudo apt-get install -y curl apt-transport-https ssl-cert ca-certificates gnupg lsb-release
Lf 'https://dl.cloudsmith.io/public/wand/libwandio/cfg/setup/bash.deb.sh' | sudo -E bash
echo "deb https://pkg.caida.org/os/$(lsb_release -si|awk '{print tolower($0)}') $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/caida.list
sudo wget -O /etc/apt/trusted.gpg.d/caida.gpg https://pkg.caida.org/os/ubuntu/keyring.gpg

sudo apt update; sudo apt-get install bgpstream

echo "BGPStream setup complete"

echo "Compiling scrape_bgp_advertisements.c"
gcc scrape_bgp_advertisements.c  -lbgpstream -o scrape_bgp_advertisements

echo "Scraping BGP data"
./scrape_bgp_advertisements > raw_bgp_data_`date +%F`.txt

echo "Filtering BGP advertisements - outputs are unique /48s"
python3 prefix_filter.py raw_bgp_data_`date +%F`.txt --48 > filtered_bgp_data_`date +%F`.txt

echo "Creating .txt files containing 2000 advertisements each"

#echo "Counting prefixes"
#python3 prefix_count.py  filtered_bgp_data_%d_%m_%y.txt > filtered_bgp_data_%d_%m_%y.txt



