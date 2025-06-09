#!/bin/sh

if ! (set -o pipefail 2>/dev/null); then
  # dash does not support pipefail
  set -efx
else
  set -efx -o pipefail
fi

# bash does not expand alias by default for non-interactive script
if [ -n "$BASH_VERSION" ]; then
  shopt -s expand_aliases
fi

alias curl="curl -L"
alias rm="rm -rf"

## Use GNU grep, busybox grep is not as performant
DISTRO=""
if [ -f "/etc/os-release" ]; then
  . "/etc/os-release"
  DISTRO="$ID"
fi

check_grep() {
  if [ -z "$(grep --help | grep 'GNU')" ]; then
    if [ -x "/usr/bin/grep" ]; then
      alias grep="/usr/bin/grep"
      check_grep
    else
      if [ "$DISTRO" = "alpine" ]; then
        echo "Please install GNU grep 'apk add grep'"
      else
        echo "GNU grep not found"
      fi
      exit 1
    fi
  fi
}
check_grep


## Detect Musl C library
LIBC="$(ldd /bin/ls | grep 'musl' || [ $? = 1 ])"
if [ -z "$LIBC" ]; then
  rm "/tmp/musl.log"
  # Not Musl
  CSVQUOTE="../utils/csvquote-bin-glibc"
else
  # Musl
  CSVQUOTE="../utils/csvquote-bin-musl"
fi


## Fallback to busybox's dos2unix if installed
if ! command -v dos2unix &> /dev/null
then
  if command -v busybox &> /dev/null
  then
    alias dos2unix="busybox dos2unix"
  else
    echo "dos2unix not found"
    exit 1
  fi
fi

if command -v unzip &> /dev/null
then
  alias unzip="unzip -p"
elif command -v busybox &> /dev/null
then
  alias unzip="busybox unzip -p"
elif command -v bsdunzip &> /dev/null
then
  alias unzip="bsdunzip -p"
else
  echo "unzip not found"
  exit 1
fi

## Create a temporary working folder
rm "tmp/"
mkdir -p "tmp/"
cd "tmp/"

USER_AGENT="phishtank/malware-filter"
if [ -n "$GITLAB_USER_LOGIN" ]; then
  USER_AGENT="phishtank/$GITLAB_USER_LOGIN"
elif [ -n "$GITHUB_REPOSITORY_OWNER" ]; then
  USER_AGENT="phishtank/$GITHUB_REPOSITORY_OWNER"
fi

## Prepare datasets
if [ -n "$PHISHTANK_API" ]; then
  curl --user-agent "$USER_AGENT" \
  "https://data.phishtank.com/data/$PHISHTANK_API/online-valid.csv.bz2" -o "phishtank.bz2"
else
  curl --user-agent "$USER_AGENT" \
  "https://data.phishtank.com/data/online-valid.csv.bz2" -o "phishtank.bz2"
fi

curl "https://openphish.com/feed.txt" -o "openphish-raw.txt"
curl "https://lists.ipthreat.net/file/ipthreat-lists/phishing/phishing-threat-0.txt.gz" -o "ipthreat.gz"
curl "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip" -o "top-1m-umbrella.zip"
curl "https://tranco-list.eu/download/daily/top-1m.csv.zip" -o "top-1m-tranco.zip"


## Cloudflare Radar
if [ -n "$CF_API" ]; then
  mkdir -p "cf/"
  # Get the latest domain ranking buckets
  curl -X GET "https://api.cloudflare.com/client/v4/radar/datasets?limit=5&offset=0&datasetType=RANKING_BUCKET&format=json" \
    -H "Authorization: Bearer $CF_API" -o "cf/datasets.json"
  # Get the top 1m bucket's dataset ID
  DATASET_ID=$(jq ".result.datasets[] | select(.meta.top==1000000) | .id" "cf/datasets.json")
  # Get the dataset download url
  curl --request POST \
    --url "https://api.cloudflare.com/client/v4/radar/datasets/download" \
    --header "Content-Type: application/json" \
    --header "Authorization: Bearer $CF_API" \
    --data "{ \"datasetId\": $DATASET_ID }" \
    -o "cf/dataset-url.json"
  DATASET_URL=$(jq ".result.dataset.url" "cf/dataset-url.json" | sed 's/"//g')
  curl "$DATASET_URL" -o "cf/top-1m-radar.csv"

  ## Parse the Radar 1 Million
  cat "cf/top-1m-radar.csv" | \
  dos2unix | \
  tr "[:upper:]" "[:lower:]" | \
  grep -F "." | \
  sed "s/^www\.//" | \
  sort -u > "top-1m-radar.txt"
fi


## Parse URLs
if [ -n "$(file 'phishtank.bz2' | grep 'bzip2 compressed data')" ]; then
  bunzip2 -kc "phishtank.bz2" | \
  tr "[:upper:]" "[:lower:]" | \
  ## Workaround for column with double quotes
  "./$CSVQUOTE" | \
  cut -f 2 -d "," | \
  "./$CSVQUOTE" -u | \
  sed 's/"//g' | \
  node "../src/clean_url.js" | \
  sort -u > "phishtank.txt"
else
  # cloudflare may impose captcha
  echo "phishtank.bz2 is not a bzip2, skipping it..."
  touch "phishtank.txt"
fi

cat "openphish-raw.txt" | \
dos2unix | \
tr "[:upper:]" "[:lower:]" | \
node "../src/clean_url.js" | \
sort -u > "openphish.txt"

gzip -dc "ipthreat.gz" | \
# remove comment
sed "/^#/d" | \
sed "s/ # .*//" | \
tr "[:upper:]" "[:lower:]" | \
node "../src/clean_url.js" | \
sort -u > "ipthreat.txt"

## Combine all sources
cat "openphish.txt" "ipthreat.txt" "phishtank.txt" | \
# remove blank lines
sed "/^$/d" | \
sort -u > "phishing.txt"


## Parse domain and IP address only
cat "phishing.txt" | \
node "../src/clean_url.js" hostname | \
sort -u > "phishing-domains.txt"


cp "../src/exclude.txt" "."
cp "../src/exclude-url.txt" "."

## Parse the Umbrella 1 Million
unzip "top-1m-umbrella.zip" | \
dos2unix | \
tr "[:upper:]" "[:lower:]" | \
# Parse domains only
cut -f 2 -d "," | \
grep -F "." | \
# Remove www.
sed "s/^www\.//" | \
sort -u > "top-1m-umbrella.txt"

## Parse the Tranco 1 Million
if [ -n "$(file 'top-1m-tranco.zip' | grep 'Zip archive data')" ]; then
  unzip "top-1m-tranco.zip" | \
  dos2unix | \
  tr "[:upper:]" "[:lower:]" | \
  # Parse domains only
  cut -f 2 -d "," | \
  grep -F "." | \
  # Remove www.
  sed "s/^www\.//" | \
  sort -u > "top-1m-tranco.txt"
else
  # cloudflare may impose captcha
  echo "top-1m-tranco.zip is not a zip, skipping it..."
  touch "top-1m-tranco.txt"
fi


# Merge Umbrella, Tranco, Radar and self-maintained top domains
cat "top-1m-umbrella.txt" "top-1m-tranco.txt" "exclude.txt" | \
sort -u > "top-1m-well-known.txt"

if [ -n "$CF_API" ] && [ -f "top-1m-radar.txt" ]; then
  cat "top-1m-radar.txt" >> "top-1m-well-known.txt"
  # sort in-place
  sort "top-1m-well-known.txt" -u -o "top-1m-well-known.txt"
fi


cat "exclude-url.txt" | \
sed "/^#/d" | \
# "example.com/path" -> "^example\.com/path"
# slash doesn't need to be escaped
sed -e "s/^/^/" -e "s/\./\\\./g" > "exclude-url-grep.txt"

## Parse popular domains
cat "phishing-domains.txt" | \
# grep match whole line
grep -Fx -f "top-1m-well-known.txt" > "phishing-top-domains.txt"


## Exclude popular domains
cat "phishing-domains.txt" | \
grep -F -vf "phishing-top-domains.txt" | \
# exclude domains from domains-based filters
grep -vf "exclude-url-grep.txt" | \
sort -u > "phishing-notop-domains.txt"

cat "phishing-top-domains.txt" | \
# "example.com" -> "^example\.com"
sed -e "s/^/^/" -e "s/\./\\\./g" > "phishing-top-domains-grep.txt"

cat "phishing.txt" | \
# exact match hostname
grep -f "phishing-top-domains-grep.txt" | \
# exclude URL of top domains without path #43
grep -Fx -vf "phishing-top-domains.txt" | \
# exclude domains/URLs from URL-based filters
grep -vf "exclude-url-grep.txt" | \
sort -u > "phishing-url-top-domains-raw.txt"


## Merge malware domains and URLs
CURRENT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
FIRST_LINE="! Title: Phishing URL Blocklist"
SECOND_LINE="! Updated: $CURRENT_TIME"
THIRD_LINE="! Expires: 12 hours (update frequency)"
FOURTH_LINE="! Homepage: https://gitlab.com/malware-filter/phishing-filter"
FIFTH_LINE="! License: https://gitlab.com/malware-filter/phishing-filter#license"
SIXTH_LINE="! Sources: openphish.com, ipthreat.net, phishtank.org"
COMMENT_UBO="$FIRST_LINE\n$SECOND_LINE\n$THIRD_LINE\n$FOURTH_LINE\n$FIFTH_LINE\n$SIXTH_LINE"

mkdir -p "../public/"

cat "phishing-url-top-domains-raw.txt" | \
sed "s/^/||/" | \
sed 's/$/^$all/' > "phishing-url-top-domains.txt"

cat "phishing-notop-domains.txt" "phishing-url-top-domains.txt" | \
sed "1i $COMMENT_UBO" > "../public/phishing-filter.txt"


# Adguard Home
cat "phishing-notop-domains.txt" | \
sed "s/^/||/" | \
sed "s/$/^/" > "phishing-domains-adguard-home.txt"

cat "phishing-domains-adguard-home.txt" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (AdGuard Home)/" > "../public/phishing-filter-agh.txt"


# Adguard browser extension
cat "phishing-notop-domains.txt" | \
sed "s/^/||/" | \
sed 's/$/^$all/' > "phishing-domains-adguard.txt"

cat "phishing-domains-adguard.txt" "phishing-url-top-domains.txt" | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (AdGuard)/" > "../public/phishing-filter-ag.txt"


# Vivaldi
cat "phishing-notop-domains.txt" | \
sed "s/^/||/" | \
sed 's/$/^$document/' > "phishing-domains-vivaldi.txt"

cat "phishing-domains-vivaldi.txt" "phishing-url-top-domains.txt" | \
sed 's/\$all$/$document/' | \
sed "1i $COMMENT_UBO" | \
sed "1s/Blocklist/Blocklist (Vivaldi)/" > "../public/phishing-filter-vivaldi.txt"


## Domains-only blocklist
# awk + head is a workaround for sed prepend
COMMENT=$(printf "$COMMENT_UBO" | sed "s/^!/#/" | sed "1s/URL/Domains/" | awk '{printf "%s\\n", $0}' | head -c -2)

cat "phishing-notop-domains.txt" | \
# remove IPv6 bracket
sed -r "s/\[|\]//g" | \
sed "1i $COMMENT" > "../public/phishing-filter-domains.txt"

cat "phishing-notop-domains.txt" | \
# exclude IPv4
grep -vE "^([0-9]{1,3}[\.]){3}[0-9]{1,3}$" | \
# exclude IPv6
grep -vE "^\[" > "phishing-notop-hosts.txt"

## Hosts file blocklist
cat "phishing-notop-hosts.txt" | \
sed "s/^/0.0.0.0 /" | \
# Re-insert comment
sed "1i $COMMENT" | \
sed "1s/Domains/Hosts/" > "../public/phishing-filter-hosts.txt"


## Dnsmasq-compatible blocklist
cat "phishing-notop-hosts.txt" | \
sed "s/^/address=\//" | \
sed "s/$/\/0.0.0.0/" | \
sed "1i $COMMENT" | \
sed "1s/Blocklist/dnsmasq Blocklist/" > "../public/phishing-filter-dnsmasq.conf"


## BIND-compatible blocklist
cat "phishing-notop-hosts.txt" | \
sed 's/^/zone "/' | \
sed 's/$/" { type master; notify no; file "null.zone.file"; };/' | \
sed "1i $COMMENT" | \
sed "1s/Blocklist/BIND Blocklist/" > "../public/phishing-filter-bind.conf"


## DNS Response Policy Zone (RPZ)
CURRENT_UNIX_TIME="$(date +%s)"
RPZ_SYNTAX="\n\$TTL 30\n@ IN SOA localhost. root.localhost. $CURRENT_UNIX_TIME 86400 3600 604800 30\n NS localhost.\n"

cat "phishing-notop-hosts.txt" | \
sed "s/$/ CNAME ./" | \
sed '1 i\'"$RPZ_SYNTAX"'' | \
sed "1i $COMMENT" | \
sed "s/^#/;/" | \
sed "1s/Blocklist/RPZ Blocklist/" > "../public/phishing-filter-rpz.conf"


## Unbound-compatible blocklist
cat "phishing-notop-hosts.txt" | \
sed 's/^/local-zone: "/' | \
sed 's/$/" always_nxdomain/' | \
sed "1i $COMMENT" | \
sed "1s/Blocklist/Unbound Blocklist/" > "../public/phishing-filter-unbound.conf"


## dnscrypt-proxy blocklists
# name-based
cat "phishing-notop-hosts.txt" | \
sed "1i $COMMENT" | \
sed "1s/Domains/Names/" > "../public/phishing-filter-dnscrypt-blocked-names.txt"

# IPv4/6
if grep -Eq "^(([0-9]{1,3}[\.]){3}[0-9]{1,3}$|\[)" "phishing-notop-domains.txt"; then
  cat "phishing-notop-domains.txt" | \
  grep -E "^(([0-9]{1,3}[\.]){3}[0-9]{1,3}$|\[)" | \
  sed -r "s/\[|\]//g" | \
  sed "1i $COMMENT" | \
  sed "1s/Domains/IPs/" > "../public/phishing-filter-dnscrypt-blocked-ips.txt"
else
  echo | \
  sed "1i $COMMENT" | \
  sed "1s/Domains/IPs/" > "../public/phishing-filter-dnscrypt-blocked-ips.txt"
fi


## Wildcard subdomain
cat "phishing-notop-hosts.txt" | \
sed "s/^/*./" | \
sed "1i $COMMENT" | \
sed "1s/Domains/Wildcard Asterisk/" > "../public/phishing-filter-wildcard.txt"


## Snort & Suricata rulesets
rm "../public/phishing-filter-snort2.rules" \
  "../public/phishing-filter-snort3.rules" \
  "../public/phishing-filter-suricata.rules" \
  "../public/phishing-filter-suricata-sni.rules" \
  "../public/phishing-filter-splunk.csv"

export CURRENT_TIME
node "../src/ids.js"

sed -i "1i $COMMENT" "../public/phishing-filter-snort2.rules"
sed -i "1s/Domains Blocklist/URL Snort2 Ruleset/" "../public/phishing-filter-snort2.rules"

sed -i "1i $COMMENT" "../public/phishing-filter-snort3.rules"
sed -i "1s/Domains Blocklist/URL Snort3 Ruleset/" "../public/phishing-filter-snort3.rules"

sed -i "1i $COMMENT" "../public/phishing-filter-suricata.rules"
sed -i "1s/Domains Blocklist/URL Suricata Ruleset/" "../public/phishing-filter-suricata.rules"

sed -i "1i $COMMENT" "../public/phishing-filter-suricata-sni.rules"
sed -i "1s/Domains Blocklist/Domains Suricata Ruleset (SNI)/" "../public/phishing-filter-suricata-sni.rules"

sed -i -e "1i $COMMENT" -e '1i "host","path","message","updated"' "../public/phishing-filter-splunk.csv"
sed -i "1s/Domains Blocklist/URL Splunk Lookup/" "../public/phishing-filter-splunk.csv"


## IE blocklist
COMMENT_IE="msFilterList\n$COMMENT\n: Expires=1\n#"

cat "phishing-notop-domains.txt" | \
sed -r "s/\[|\]//g" | \
sed "s/^/-d /" | \
sed "1i $COMMENT_IE" | \
sed "2s/Domains Blocklist/Hosts Blocklist (IE)/" > "../public/phishing-filter.tpl"


## Clean up artifacts
rm "phishtank.bz2" "top-1m-umbrella.zip" "top-1m-umbrella.txt" "top-1m-tranco.txt" "openphish-raw.txt" "cf/" "top-1m-radar.txt"


cd ../
