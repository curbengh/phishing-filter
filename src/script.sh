#!/bin/sh

set -efux -o pipefail

## Detect Musl C library
LIBC="$(ldd /bin/ls | grep 'musl' || [ $? = 1 ])"
if [ -z "$LIBC" ]; then
  rm -f "/tmp/musl.log"
  # Not Musl
  CSVQUOTE="../utils/csvquote-bin-glibc"
else
  # Musl
  CSVQUOTE="../utils/csvquote-bin-musl"
fi


## Create a temporary working folder
mkdir -p "tmp/"
cd "tmp/"


## Prepare datasets
curl -L "https://data.phishtank.com/data/$PHISHTANK_API/online-valid.csv.bz2" -o "phishtank.bz2"
curl -L "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip" -o "top-1m-umbrella.zip"
curl -L "https://tranco-list.eu/top-1m.csv.zip" -o "top-1m-tranco.zip"

bunzip2 -kc "phishtank.bz2" > "phishtank.csv"


## Parse URLs
cat "phishtank.csv" | \
## Workaround for column with double quotes
"./$CSVQUOTE" | \
cut -f 2 -d "," | \
"./$CSVQUOTE" -u | \
sed 's/"//g' | \
cut -f 3- -d "/" | \
# Domain must have at least a 'dot'
grep -F "." | \
sed "s/^www\.//g" | \
sort -u > "phishtank.txt"

## Parse domain and IP address only
cat "phishtank.txt" | \
cut -f 1 -d "/" | \
cut -f 1 -d ":" | \
sort -u > "phishtank-domains.txt"


cp "../src/exclude.txt" "."

## Parse the Umbrella 1 Million
unzip -p "top-1m-umbrella.zip" | \
dos2unix | \
# Parse domains only
cut -f 2 -d "," | \
grep -F "." | \
# Remove www.
sed "s/^www\.//g" | \
sort -u > "top-1m-umbrella.txt"

## Parse the Tranco 1 Million
unzip -p "top-1m-tranco.zip" | \
dos2unix | \
# Parse domains only
cut -f 2 -d "," | \
grep -F "." | \
# Remove www.
sed "s/^www\.//g" | \
sort -u > "top-1m-tranco.txt"

# Merge Umbrella, Traco and self-maintained top domains
cat "top-1m-umbrella.txt" "top-1m-tranco.txt" "exclude.txt" | \
sort -u > "top-1m-well-known.txt"


## Parse popular domains from PhishTank
cat "phishtank-domains.txt" | \
# grep match whole line
grep -Fx -f "top-1m-well-known.txt" > "phishtank-top-domains.txt"


## Parse domains from PhishTank excluding popular domains
cat "phishtank-domains.txt" | \
grep -F -vf "phishtank-top-domains.txt" > "phishing-domains.txt"

## Parse phishing URLs from popular domains
cat "phishtank.txt" | \
grep -F -f "phishtank-top-domains.txt" | \
sed "s/^/||/g" | \
sed "s/$/\$all/g" > "phishing-url-top-domains.txt"


## Merge malware domains and URLs
CURRENT_TIME="$(date -R -u)"
FIRST_LINE="! Title: Phishing URL Blocklist"
SECOND_LINE="! Updated: $CURRENT_TIME"
THIRD_LINE="! Expires: 1 day (update frequency)"
FOURTH_LINE="! Repo: https://gitlab.com/curben/phishing-filter"
FIFTH_LINE="! License: https://creativecommons.org/publicdomain/zero/1.0/"
SIXTH_LINE="! Source: https://www.phishtank.com/"
COMMENT_UBO="$FIRST_LINE\n$SECOND_LINE\n$THIRD_LINE\n$FOURTH_LINE\n$FIFTH_LINE\n$SIXTH_LINE"

cat "phishing-domains.txt" "phishing-url-top-domains.txt" | \
sort | \
sed '1 i\'"$COMMENT_UBO"'' > "../dist/phishing-filter.txt"


## Domains-only blocklist
# awk + head is a workaround for sed prepend
COMMENT=$(printf "$COMMENT_UBO" | sed "s/^!/#/g" | sed "1s/URL/Domains/" | awk '{printf "%s\\n", $0}' | head -c -2)

cat "phishing-domains.txt" | \
sort | \
sed '1 i\'"$COMMENT"'' > "../dist/phishing-filter-domains.txt"


## Hosts file blocklist
cat "../dist/phishing-filter-domains.txt" | \
# Exclude comment with #
grep -vE "^#" | \
# Remove IPv4 address
grep -vE "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | \
sed "s/^/0.0.0.0 /g" | \
# Re-insert comment
sed '1 i\'"$COMMENT"'' | \
sed "1s/Domains/Hosts/" > "../dist/phishing-filter-hosts.txt"


## Dnsmasq-compatible blocklist
cat "../dist/phishing-filter-hosts.txt" | \
grep -vE "^#" | \
sed "s/^0.0.0.0 /address=\//g" | \
sed "s/$/\/0.0.0.0/g" | \
sed '1 i\'"$COMMENT"'' | \
sed "1s/Blocklist/dnsmasq Blocklist/" > "../dist/phishing-filter-dnsmasq.conf"


## BIND-compatible blocklist
cat "../dist/phishing-filter-hosts.txt" | \
grep -vE "^#" | \
sed 's/^0.0.0.0 /zone "/g' | \
sed 's/$/" { type master; notify no; file "null.zone.file"; };/g' | \
sed '1 i\'"$COMMENT"'' | \
sed "1s/Blocklist/BIND Blocklist/" > "../dist/phishing-filter-bind.conf"


## Unbound-compatible blocklist
cat "../dist/phishing-filter-hosts.txt" | \
grep -vE "^#" | \
sed 's/^0.0.0.0 /local-zone: "/g' | \
sed 's/$/" always_nxdomain/g' | \
sed '1 i\'"$COMMENT"'' | \
sed "1s/Blocklist/Unbound Blocklist/" > "../dist/phishing-filter-unbound.conf"


## Clean up artifacts
rm "phishtank.csv" "top-1m-umbrella.zip" "top-1m-umbrella.txt" "top-1m-tranco.txt"


cd ../
