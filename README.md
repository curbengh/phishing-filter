# Phishing URL Blocklist

A blocklist of phishing websites, based on the [PhishTank](https://www.phishtank.com/) and [OpenPhish](https://openphish.com/) lists. Blocklist is updated twice a day.

There are multiple formats available, refer to the appropriate section according to the program used:

- uBlock Origin (uBO) -> [URL-based](#url-based) section (recommended)
- Pi-hole -> [Domain-based](#domain-based) or [Hosts-based](#hosts-based) section
- AdGuard Home -> [Domain-based (AdGuard Home)](#domain-based-adguard-home) or [Hosts-based](#hosts-based) section
- AdGuard browser extension -> [URL-based (AdGuard)](#url-based-adguard)
- Vivaldi -> [URL-based (Vivaldi)](#url-based-vivaldi)
- [Hosts](#hosts-based)
- [Dnsmasq](#dnsmasq)
- [BIND](#bind)
- [Unbound](#unbound)
- Internet Explorer -> [Tracking Protection List (IE)](#tracking-protection-list-ie)
- [Snort2](#snort2)
- [Suricata](#suricata)

Not sure which format to choose? See [Compatibility](https://gitlab.com/curben/urlhaus-filter/wikis/compatibility) page.

Use [urlhaus-filter](https://gitlab.com/curben/urlhaus-filter) to block malware websites.

## URL-based

Import the following URL into uBO to subscribe:

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter.txt

</details>

**AdGuard Home** users should use [this blocklist](#domain-based-adguard-home).

## URL-based (AdGuard)

Import the following URL into AdGuard browser extension to subscribe:

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-ag.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-ag.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-ag.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-ag.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-ag.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-ag.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-ag.txt

</details>

## URL-based (Vivaldi)

_Requires Vivaldi Desktop/Android 3.3+, blocking level must be at least "Block Trackers"_

Import the following URL into Vivaldi's **Tracker Blocking Sources** to subscribe:

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-vivaldi.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-vivaldi.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-vivaldi.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-vivaldi.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-vivaldi.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-vivaldi.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-vivaldi.txt

</details>

## Domain-based

This blocklist includes domains and IP addresses.

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-domains.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-domains.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-domains.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-domains.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-domains.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-domains.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-domains.txt

</details>

## Domain-based (AdGuard Home)

This AdGuard Home-compatible blocklist includes domains and IP addresses.

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-agh.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-agh.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-agh.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-agh.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-agh.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-agh.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/phishing-filter-agh.txt

</details>

## Hosts-based

This blocklist includes domains only.

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-hosts.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-hosts.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-hosts.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-hosts.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-hosts.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-hosts.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-hosts.txt

</details>

## Dnsmasq

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/dnsmasq/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-dnsmasq.conf" -o "/usr/local/etc/dnsmasq/phishing-filter-dnsmasq.conf"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure dnsmasq to use the blocklist
printf "\nconf-file=/usr/local/etc/dnsmasq/phishing-filter-dnsmasq.conf\n" >> /etc/dnsmasq.conf
```

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-dnsmasq.conf

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-dnsmasq.conf
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-dnsmasq.conf
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-dnsmasq.conf
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-dnsmasq.conf
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-dnsmasq.conf
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-dnsmasq.conf

</details>

## BIND

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/bind/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-bind.conf" -o "/usr/local/etc/bind/phishing-filter-bind.conf"\n' > /etc/cron.daily/phishing-filter

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

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-bind.conf

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-bind.conf
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-bind.conf
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-bind.conf
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-bind.conf
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-bind.conf
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-bind.conf

</details>

## Unbound

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/unbound/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-unbound.conf" -o "/usr/local/etc/unbound/phishing-filter-unbound.conf"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure Unbound to use the blocklist
printf '\n  include: "/usr/local/etc/unbound/phishing-filter-unbound.conf"\n' >> /etc/unbound/unbound.conf
```

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-unbound.conf

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-unbound.conf
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-unbound.conf
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-unbound.conf
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-unbound.conf
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-unbound.conf
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-unbound.conf

</details>

## Tracking Protection List (IE)

This blocklist includes domains only.

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter.tpl

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter.tpl
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter.tpl
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter.tpl
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter.tpl
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter.tpl
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter.tpl

</details>

## Snort2

This ruleset includes online URLs only. Not compatible with Snort3.

### Install

```
# Download ruleset
curl -L "https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-snort2.rules" -o "/etc/snort/rules/phishing-filter-snort2.rules"

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-snort2.rules" -o "/etc/snort/rules/phishing-filter-snort2.rules"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure Snort to use the ruleset
printf "\ninclude \$RULE_PATH/phishing-filter-snort2.rules\n" >> /etc/snort/snort.conf
```

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-snort2.rules

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-snort2.rules
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-snort2.rules
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-snort2.rules
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-snort2.rules
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-snort2.rules
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-snort2.rules

</details>

## Suricata

This ruleset includes online URLs only.

### Install

```
# Download ruleset
curl -L "https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-suricata.rules" -o "/etc/suricata/rules/phishing-filter-suricata.rules"

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-suricata.rules" -o "/etc/suricata/rules/phishing-filter-suricata.rules"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter
```

Configure Suricata to use the ruleset:

``` diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - phishing-filter-suricata.rules
```

- https://curben.gitlab.io/phishing-filter-mirror/phishing-filter-suricata.rules

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/master/dist/phishing-filter-suricata.rules
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-suricata.rules
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-suricata.rules
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-suricata.rules
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-suricata.rules
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-suricata.rules

</details>

## Issues

This blocklist operates by blocking the **whole** website, instead of specific webpages; exceptions are made on popular websites (e.g. `https://docs.google.com/`), in which webpages are specified instead (e.g. `https://docs.google.com/phishing-page`). Phishing webpages are only listed in [URL-based](#url-based) filter, popular websites are excluded from other filters.

*Popular* websites are as listed in the [Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html) (top 1M domains + subdomains), [Tranco List](https://tranco-list.eu/) (top 1M domains) and this [custom list](src/exclude.txt).

If you wish to exclude certain website(s) that you believe is sufficiently well-known, please create an [issue](https://gitlab.com/curben/phishing-filter/issues) or [merge request](https://gitlab.com/curben/phishing-filter/merge_requests).

This blocklist **only** accepts new phishing URLs from [PhishTank](https://www.phishtank.com/) and [OpenPhish](https://openphish.com/).

Please report new phishing URL to [PhishTank](https://www.phishtank.com/add_web_phish.php) or [OpenPhish](https://openphish.com/faq.html).

## Cloning

Since the filter is updated frequently, cloning the repo would become slower over time as the revision grows.

Use shallow clone to get the recent revisions only. Getting the last five revisions should be sufficient for a valid MR.

`git clone --depth 5 https://gitlab.com/curben/phishing-filter.git`

## License

[src/](src/): [CC0](LICENSE.md)

[dist/](dist/): [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)

[badge.sh](src/badge.sh) & [.gitlab/](.gitlab/) contain badges that are licensed by [Shields.io](https://shields.io) under [CC0 1.0](LICENSE.md)

[PhishTank](https://www.phishtank.com/): [CC BY-SA 2.5](https://creativecommons.org/licenses/by-sa/2.5/)

_PhishTank is either trademark or registered trademark of OpenDNS, LLC._

[OpenPhish](https://openphish.com/): Available free of charge by OpenPhish

[Tranco List](https://tranco-list.eu/): MIT License

[Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html): Available free of charge by Cisco Umbrella

[csvquote](https://github.com/dbro/csvquote): [MIT License](https://choosealicense.com/licenses/mit/)

This repository is not endorsed by PhishTank/OpenDNS and OpenPhish.
