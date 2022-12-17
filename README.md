# Phishing URL Blocklist

- Formats
  - [URL-based](#url-based)
  - [Domain-based](#domain-based)
  - [Hosts-based](#hosts-based)
  - [Domain-based (AdGuard Home)](#domain-based-adguard-home)
  - [URL-based (AdGuard)](#url-based-adguard)
  - [URL-based (Vivaldi)](#url-based-vivaldi)
  - [Dnsmasq](#dnsmasq)
  - [BIND zone](#bind)
  - [RPZ](#response-policy-zone)
  - [Unbound](#unbound)
  - [dnscrypt-proxy](#dnscrypt-proxy)
  - [Tracking Protection List (IE)](#tracking-protection-list-ie)
  - [Snort2](#snort2)
  - [Snort3](#snort3)
  - [Suricata](#suricata)
  - [Splunk](#splunk)
- [Compressed version](#compressed-version)
- [Reporting issues](#issues)
- [See also](#see-also)
- [FAQ and Guides](#faq-and-guides)
- [CI Variables](#ci-variables)
- [License](#license)

A blocklist of phishing websites, curated from [PhishTank](https://www.phishtank.com/), [OpenPhish](https://openphish.com/), [phishunt.io](https://phishunt.io/). Blocklist is updated twice a day.

There are multiple formats available, refer to the appropriate section according to the program used:

- uBlock Origin (uBO) -> [URL-based](#url-based) section (recommended)
- Pi-hole -> [Domain-based](#domain-based) or [Hosts-based](#hosts-based) section
- AdGuard Home -> [Domain-based (AdGuard Home)](#domain-based-adguard-home) or [Hosts-based](#hosts-based) section
- AdGuard browser extension -> [URL-based (AdGuard)](#url-based-adguard)
- Vivaldi -> [URL-based (Vivaldi)](#url-based-vivaldi)
- [Hosts](#hosts-based)
- [Dnsmasq](#dnsmasq)
- BIND -> BIND [zone](#bind) or [RPZ](#response-policy-zone)
- [Unbound](#unbound)
- [dnscrypt-proxy](#dnscrypt-proxy)
- Internet Explorer -> [Tracking Protection List (IE)](#tracking-protection-list-ie)
- [Snort2](#snort2)
- [Snort3](#snort3)
- [Suricata](#suricata)
- [Splunk](#splunk)

For other programs, see [Compatibility](https://gitlab.com/malware-filter/malware-filter/wikis/compatibility) page in the wiki.

Check out my other filters:

- [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter)
- [pup-filter](https://gitlab.com/malware-filter/pup-filter)
- [tracking-filter](https://gitlab.com/malware-filter/tracking-filter)
- [vn-badsite-filter](https://gitlab.com/malware-filter/vn-badsite-filter)

## URL-based

Import the following URL into uBO to subscribe:

- https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt

_included by default in uBO >=[1.39.0](https://github.com/gorhill/uBlock/releases/tag/1.39.0); to enable, head to "Filter lists" tab, expand "Malware domains" section and tick "Phishing URL Blocklist"._

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter.txt
- https://curbengh.github.io/phishing-filter/phishing-filter.txt
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter.txt
- https://malware-filter.pages.dev/phishing-filter.txt
- https://phishing-filter.pages.dev/phishing-filter.txt

</details>

**AdGuard Home** users should use [this blocklist](#domain-based-adguard-home).

## URL-based (AdGuard)

Import the following URL into AdGuard browser extension to subscribe:

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-ag.txt
- https://curbengh.github.io/phishing-filter/phishing-filter-ag.txt
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-ag.txt
- https://malware-filter.pages.dev/phishing-filter-ag.txt
- https://phishing-filter.pages.dev/phishing-filter-ag.txt

</details>

## URL-based (Vivaldi)

_Requires Vivaldi Desktop/Android 3.3+, blocking level must be at least "Block Trackers"_

Import the following URL into Vivaldi's **Tracker Blocking Sources** to subscribe:

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-vivaldi.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-vivaldi.txt
- https://curbengh.github.io/phishing-filter/phishing-filter-vivaldi.txt
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-vivaldi.txt
- https://malware-filter.pages.dev/phishing-filter-vivaldi.txt
- https://phishing-filter.pages.dev/phishing-filter-vivaldi.txt

</details>

## Domain-based

This blocklist includes domains and IP addresses.

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-domains.txt
- https://curbengh.github.io/phishing-filter/phishing-filter-domains.txt
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-domains.txt
- https://malware-filter.pages.dev/phishing-filter-domains.txt
- https://phishing-filter.pages.dev/phishing-filter-domains.txt

</details>

## Domain-based (AdGuard Home)

This AdGuard Home-compatible blocklist includes domains and IP addresses.

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-agh.txt
- https://curbengh.github.io/phishing-filter/phishing-filter-agh.txt
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-agh.txt
- https://malware-filter.pages.dev/phishing-filter-agh.txt
- https://phishing-filter.pages.dev/phishing-filter-agh.txt

</details>

## Hosts-based

This blocklist includes domains only.

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-hosts.txt
- https://curbengh.github.io/phishing-filter/phishing-filter-hosts.txt
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-hosts.txt
- https://malware-filter.pages.dev/phishing-filter-hosts.txt
- https://phishing-filter.pages.dev/phishing-filter-hosts.txt

</details>

## Dnsmasq

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/dnsmasq/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-dnsmasq.conf" -o "/usr/local/etc/dnsmasq/phishing-filter-dnsmasq.conf"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure dnsmasq to use the blocklist
printf "\nconf-file=/usr/local/etc/dnsmasq/phishing-filter-dnsmasq.conf\n" >> /etc/dnsmasq.conf
```

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-dnsmasq.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-dnsmasq.conf
- https://curbengh.github.io/phishing-filter/phishing-filter-dnsmasq.conf
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-dnsmasq.conf
- https://malware-filter.pages.dev/phishing-filter-dnsmasq.conf
- https://phishing-filter.pages.dev/phishing-filter-dnsmasq.conf

</details>

## BIND

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/bind/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-bind.conf" -o "/usr/local/etc/bind/phishing-filter-bind.conf"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure BIND to use the blocklist
printf '\ninclude "/usr/local/etc/bind/phishing-filter-bind.conf";\n' >> /etc/bind/named.conf
```

Add this to "/etc/bind/null.zone.file" (skip this step if the file already exists):

```
$TTL    86400   ; one day
@       IN      SOA     ns.nullzone.loc. ns.nullzone.loc. (
               2017102203
                    28800
                     7200
                   864000
                    86400 )
                NS      ns.nullzone.loc.
                A       0.0.0.0
@       IN      A       0.0.0.0
*       IN      A       0.0.0.0
```

Zone file is derived from [here](https://github.com/tomzuu/blacklist-named/blob/master/null.zone.file).

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-bind.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-bind.conf
- https://curbengh.github.io/phishing-filter/phishing-filter-bind.conf
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-bind.conf
- https://malware-filter.pages.dev/phishing-filter-bind.conf
- https://phishing-filter.pages.dev/phishing-filter-bind.conf

</details>

## Response Policy Zone

This blocklist includes domains only.

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-rpz.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-rpz.conf
- https://curbengh.github.io/phishing-filter/phishing-filter-rpz.conf
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-rpz.conf
- https://malware-filter.pages.dev/phishing-filter-rpz.conf
- https://phishing-filter.pages.dev/phishing-filter-rpz.conf

</details>

## Unbound

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/unbound/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-unbound.conf" -o "/usr/local/etc/unbound/phishing-filter-unbound.conf"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure Unbound to use the blocklist
printf '\n  include: "/usr/local/etc/unbound/phishing-filter-unbound.conf"\n' >> /etc/unbound/unbound.conf
```

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-unbound.conf

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-unbound.conf
- https://curbengh.github.io/phishing-filter/phishing-filter-unbound.conf
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-unbound.conf
- https://malware-filter.pages.dev/phishing-filter-unbound.conf
- https://phishing-filter.pages.dev/phishing-filter-unbound.conf

</details>

## dnscrypt-proxy

### Install

```
# Create a new folder to store the blocklist
mkdir -p /etc/dnscrypt-proxy/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-dnscrypt-blocked-names.txt" -o "/etc/dnscrypt-proxy/phishing-filter-dnscrypt-blocked-names.txt"\n' > /etc/cron.daily/phishing-filter
printf '\ncurl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-dnscrypt-blocked-ips.txt" -o "/etc/dnscrypt-proxy/phishing-filter-dnscrypt-blocked-ips.txt"\n' >> /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter
```

Configure dnscrypt-proxy to use the blocklist:

```diff
[blocked_names]
+  blocked_names_file = '/etc/dnscrypt-proxy/phishing-filter-dnscrypt-blocked-names.txt'

[blocked_ips]
+  blocked_ips_file = '/etc/dnscrypt-proxy/phishing-filter-dnscrypt-blocked-ips.txt'
```

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-dnscrypt-blocked-names.txt
- https://malware-filter.gitlab.io/malware-filter/phishing-filter-dnscrypt-blocked-ips.txt

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-dnscrypt-blocked-names.txt
- https://curbengh.github.io/phishing-filter/phishing-filter-dnscrypt-blocked-names.txt
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-dnscrypt-blocked-names.txt
- https://malware-filter.pages.dev/phishing-filter-dnscrypt-blocked-names.txt
- https://phishing-filter.pages.dev/phishing-filter-dnscrypt-blocked-names.txt

- https://curbengh.github.io/malware-filter/phishing-filter-dnscrypt-blocked-ips.txt
- https://curbengh.github.io/phishing-filter/phishing-filter-dnscrypt-blocked-ips.txt
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-dnscrypt-blocked-ips.txt
- https://malware-filter.pages.dev/phishing-filter-dnscrypt-blocked-ips.txt
- https://phishing-filter.pages.dev/phishing-filter-dnscrypt-blocked-ips.txt

</details>

## Tracking Protection List (IE)

This blocklist includes domains only.

- https://malware-filter.gitlab.io/malware-filter/phishing-filter.tpl

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter.tpl
- https://curbengh.github.io/phishing-filter/phishing-filter.tpl
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter.tpl
- https://malware-filter.pages.dev/phishing-filter.tpl
- https://phishing-filter.pages.dev/phishing-filter.tpl

</details>

## Snort2

This ruleset includes online URLs only. Not compatible with [Snort3](#snort3).

### Install

```
# Download ruleset
curl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-snort2.rules" -o "/etc/snort/rules/phishing-filter-snort2.rules"

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-snort2.rules" -o "/etc/snort/rules/phishing-filter-snort2.rules"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure Snort to use the ruleset
printf "\ninclude \$RULE_PATH/phishing-filter-snort2.rules\n" >> /etc/snort/snort.conf
```

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-snort2.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-snort2.rules
- https://curbengh.github.io/phishing-filter/phishing-filter-snort2.rules
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-snort2.rules
- https://malware-filter.pages.dev/phishing-filter-snort2.rules
- https://phishing-filter.pages.dev/phishing-filter-snort2.rules

</details>

## Snort3

This ruleset includes online URLs only. Not compatible with [Snort2](#snort2).

### Install

```
# Download ruleset
curl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-snort3.rules" -o "/etc/snort/rules/phishing-filter-snort3.rules"

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-snort3.rules" -o "/etc/snort/rules/phishing-filter-snort3.rules"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter
```

Configure Snort to use the ruleset:

```diff
# /etc/snort/snort.lua
ips =
{
  variables = default_variables,
+  include = 'rules/phishing-filter-snort3.rules'
}
```

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-snort3.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-snort3.rules
- https://curbengh.github.io/phishing-filter/phishing-filter-snort3.rules
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-snort3.rules
- https://malware-filter.pages.dev/phishing-filter-snort3.rules
- https://phishing-filter.pages.dev/phishing-filter-snort3.rules

</details>

## Suricata

This ruleset includes online URLs only.

### Install

```
# Download ruleset
curl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-suricata.rules" -o "/etc/suricata/rules/phishing-filter-suricata.rules"

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://malware-filter.gitlab.io/malware-filter/phishing-filter-suricata.rules" -o "/etc/suricata/rules/phishing-filter-suricata.rules"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter
```

Configure Suricata to use the ruleset:

```diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - phishing-filter-suricata.rules
```

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-suricata.rules

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-suricata.rules
- https://curbengh.github.io/phishing-filter/phishing-filter-suricata.rules
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-suricata.rules
- https://malware-filter.pages.dev/phishing-filter-suricata.rules
- https://phishing-filter.pages.dev/phishing-filter-suricata.rules

</details>

## Splunk

A CSV file for Splunk [lookup](https://docs.splunk.com/Documentation/Splunk/9.0.2/Knowledge/Aboutlookupsandfieldactions). This ruleset includes online URLs only.

- https://malware-filter.gitlab.io/malware-filter/phishing-filter-splunk.csv

<details>
<summary>Mirrors</summary>

- https://curbengh.github.io/malware-filter/phishing-filter-splunk.csv
- https://curbengh.github.io/phishing-filter/phishing-filter-splunk.csv
- https://malware-filter.gitlab.io/phishing-filter/phishing-filter-splunk.csv
- https://malware-filter.pages.dev/phishing-filter-splunk.csv
- https://phishing-filter.pages.dev/phishing-filter-splunk.csv

</details>

## Compressed version

All filters are also available as gzip- and brotli-compressed.

- Gzip: https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt.gz
- Brotli: https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt.br

_Snort 2 rule is only available in compressed format in pages.dev due to the platform's 25MB file size limit_

## Issues

This blocklist operates by blocking the **whole** website, instead of specific webpages; exceptions are made on popular websites (e.g. `https://docs.google.com/`), in which webpages are specified instead (e.g. `https://docs.google.com/phishing-page`). Phishing webpages are only listed in [URL-based](#url-based) filter, popular websites are excluded from other filters.

_Popular_ websites are as listed in the [Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html) (top 1M domains + subdomains), [Tranco List](https://tranco-list.eu/) (top 1M domains), [Cloudflare Radar](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/) (top 1M domains) and this [custom list](src/exclude.txt).

If you wish to exclude certain website(s) that you believe is sufficiently well-known, please create an [issue](https://gitlab.com/malware-filter/phishing-filter/issues) or [merge request](https://gitlab.com/malware-filter/phishing-filter/merge_requests).

This blocklist **only** accepts new phishing URLs from [PhishTank](https://www.phishtank.com/) and [OpenPhish](https://openphish.com/).

Please report new phishing URL to [PhishTank](https://www.phishtank.com/add_web_phish.php) or [OpenPhish](https://openphish.com/faq.html).

## See also

[Phishing Army](https://phishing.army/) by [Andrea Draghetti](https://www.andreadraghetti.it/) is available in domain-based format and utilises more sources. Its exclusion methods are not up-to-date though: [Anudeep's whitelist](https://github.com/anudeepND/whitelist) was lasted updated in Dec 2021 and [Alexa](https://www.alexa.com/topsites) was deprecated in May 2022.

## FAQ and Guides

See [wiki](https://gitlab.com/malware-filter/malware-filter/-/wikis/home)

## CI Variables

Optional variables:

- `PHISHTANK_API`: Recommended if you intend to run [script.sh](src/script.sh) >5 times daily. Register an account at [phishtank.org](https://phishtank.org/developer_info.php) to generate an application key.
- `CLOUDFLARE_BUILD_HOOK`: Deploy to Cloudflare Pages.
- `NETLIFY_SITE_ID`: Deploy to Netlify.
- `CF_API`: Include Cloudflare Radar [domains ranking](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/). [Guide](https://developers.cloudflare.com/radar/get-started/first-request/) to create an API token.

## License

[src/](src/): [CC0](LICENSE.md)

filters: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)

[PhishTank](https://www.phishtank.com/): Available [free of charge](https://www.phishtank.com/faq.php#isitoktousetheapifor) by Cisco for commercial and non-commercial use.

_PhishTank is either trademark or registered trademark of Cisco Systems, Inc._

[OpenPhish](https://openphish.com/): Available [free of charge](https://openphish.com/terms.html) by OpenPhish

[Tranco List](https://tranco-list.eu/): [MIT License](https://choosealicense.com/licenses/mit/)

[Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html): Available free of charge by Cisco Umbrella

[csvquote](https://github.com/dbro/csvquote): MIT License

[phishunt.io](https://phishunt.io/): All rights reserved by [Daniel López](https://twitter.com/0xDanielLopez)

[Cloudflare Radar](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/): Available to free Cloudflare account

This repository is not endorsed by PhishTank/OpenDNS and OpenPhish.
