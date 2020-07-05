# Phishing URL Blocklist

A blocklist of phishing websites, based on the [PhishTank](https://www.phishtank.com/) list. Blocklist is updated twice a day.

There are multiple formats available, refer to the appropriate section according to the program used:

- uBlock Origin (uBO) -> [URL-based](#url-based) section (recommended)
- Pi-hole -> [Domain-based](#domain-based) or [Hosts-based](#hosts-based) section
- Hosts file -> [Hosts-based](#hosts-based) section
- Dnsmasq -> [Dnsmasq](#dnsmasq) section
- BIND -> [BIND](#bind) section
- Unbound -> [Unbound](#unbound) section

Not sure which format to choose? See [Compatibility](https://gitlab.com/curben/urlhaus-filter/wikis/compatibility) page.

## URL-based

Import the following URL into uBO to subscribe:

- https://gitlab.com/curben/phishing-filter/raw/master/dist/phishing-filter.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/raw/master/dist/phishing-filter.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter.txt
- https://repo.or.cz/phishing-filter.git/blob_plain/refs/heads/master:/dist/phishing-filter.txt

</details>

## Domain-based

This blocklist includes domains and IP addresses.

- https://gitlab.com/curben/phishing-filter/raw/master/dist/phishing-filter-domains.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/raw/master/dist/phishing-filter-domains.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-domains.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-domains.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-domains.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-domains.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-domains.txt
- https://repo.or.cz/phishing-filter.git/blob_plain/refs/heads/master:/dist/phishing-filter-domains.txt

</details>

## Hosts-based

This blocklist includes domains only.

- https://gitlab.com/curben/phishing-filter/raw/master/dist/phishing-filter-hosts.txt

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/raw/master/dist/phishing-filter-hosts.txt
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-hosts.txt
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-hosts.txt
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-hosts.txt
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-hosts.txt
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-hosts.txt
- https://repo.or.cz/phishing-filter.git/blob_plain/refs/heads/master:/dist/phishing-filter-hosts.txt

</details>

## Dnsmasq

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/dnsmasq/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://gitlab.com/curben/phishing-filter/raw/master/dist/phishing-filter-dnsmasq.conf" -o "/usr/local/etc/dnsmasq/phishing-filter-dnsmasq.conf"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure dnsmasq to use the blocklist
printf "\nconf-file=/usr/local/etc/dnsmasq/dist/phishing-filter-dnsmasq.conf\n" >> /etc/dnsmasq.conf
```

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/raw/master/dist/phishing-filter-dnsmasq.conf
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-dnsmasq.conf
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-dnsmasq.conf
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-dnsmasq.conf
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-dnsmasq.conf
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-dnsmasq.conf
- https://repo.or.cz/phishing-filter.git/blob_plain/refs/heads/master:/dist/phishing-filter-dnsmasq.conf

</details>

## BIND

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/bind/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://gitlab.com/curben/phishing-filter/raw/master/dist/phishing-filter-bind.conf" -o "/usr/local/etc/bind/phishing-filter-bind.conf"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure BIND to use the blocklist
printf '\ninclude "/usr/local/etc/bind/dist/phishing-filter-bind.conf";\n' >> /etc/bind/named.conf
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

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/raw/master/dist/phishing-filter-bind.conf
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-bind.conf
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-bind.conf
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-bind.conf
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-bind.conf
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-bind.conf
- https://repo.or.cz/phishing-filter.git/blob_plain/refs/heads/master:/dist/phishing-filter-bind.conf

</details>

## Unbound

This blocklist includes domains only.

### Install

```
# Create a new folder to store the blocklist
mkdir -p /usr/local/etc/unbound/

# Create a new cron job for daily update
printf '#!/bin/sh\ncurl -L "https://gitlab.com/curben/phishing-filter/raw/master/dist/phishing-filter-unbound.conf" -o "/usr/local/etc/unbound/phishing-filter-unbound.conf"\n' > /etc/cron.daily/phishing-filter

# cron job requires execution permission
chmod 755 /etc/cron.daily/phishing-filter

# Configure Unbound to use the blocklist
printf '\n  include: "/usr/local/etc/unbound/dist/phishing-filter-unbound.conf"\n' >> /etc/unbound/unbound.conf
```

<details>
<summary>Mirrors</summary>

- https://cdn.statically.io/gl/curben/phishing-filter/raw/master/dist/phishing-filter-unbound.conf
- https://glcdn.githack.com/curben/phishing-filter/raw/master/dist/phishing-filter-unbound.conf
- https://raw.githubusercontent.com/curbengh/phishing-filter/master/dist/phishing-filter-unbound.conf
- https://cdn.statically.io/gh/curbengh/phishing-filter/master/dist/phishing-filter-unbound.conf
- https://gitcdn.xyz/repo/curbengh/phishing-filter/master/dist/phishing-filter-unbound.conf
- https://cdn.jsdelivr.net/gh/curbengh/phishing-filter/dist/phishing-filter-unbound.conf
- https://repo.or.cz/phishing-filter.git/blob_plain/refs/heads/master:/dist/phishing-filter-unbound.conf

</details>

## Issues

This blocklist operates by blocking the **whole** website, instead of specific webpages; exceptions are made on popular websites (e.g. `https://docs.google.com/`), in which webpages are specified instead (e.g. `https://docs.google.com/phishing-page`). Phishing webpages are only listed in [URL-based](#url-based) filter, popular websites are excluded from other filters.

*Popular* websites are as listed in the [Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html) (top 1M domains + subdomains), [Tranco List](https://tranco-list.eu/) (top 1M domains) and this [custom list](src/exclude.txt).

If you wish to exclude certain website(s) that you believe is sufficiently well-known, please create an [issue](https://gitlab.com/curben/phishing-filter/issues) or [merge request](https://gitlab.com/curben/phishing-filter/merge_requests).

This blocklist **only** accepts new phishing URLs from [PhishTank](https://www.phishtank.com/).

Please report new phishing URL to the upstream maintainer through https://www.phishtank.com/add_web_phish.php.

## Cloning

Since the filter is updated frequently, cloning the repo would become slower over time as the revision grows.

Use shallow clone to get the recent revisions only. Getting the last five revisions should be sufficient for a valid MR.

`git clone --depth 5 https://gitlab.com/curben/phishing-filter.git`

## License

[Creative Commons Zero v1.0 Universal](LICENSE.md)

[csvquote](https://github.com/dbro/csvquote): [MIT License](https://choosealicense.com/licenses/mit/)

[Tranco List](https://tranco-list.eu/): MIT License

[Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html): Available free of charge by Cisco Umbrella

[PhishTank](https://www.phishtank.com/): [CC BY-SA 2.5](https://creativecommons.org/licenses/by-sa/2.5/)

PhishTank and Cisco are either trademarks or registered trademarks of Cisco Systems, Inc. and/or its affiliates in the United States and certain other countries.
