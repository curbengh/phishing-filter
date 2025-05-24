# Phishing URL Blocklist

- Formats
  - [URL-based](#url-based)
  - [Domain-based](#domain-based)
  - [Wildcard asterisk](#wildcard-asterisk)
  - [Hosts-based](#hosts-based)
  - [Domain-based (AdGuard Home)](#domain-based-adguard-home)
  - [URL-based (AdGuard)](#url-based-adguard)
  - [URL-based (Vivaldi)](#url-based-vivaldi)
  - [Dnsmasq](#dnsmasq)
  - [BIND zone](#bind)
  - [RPZ](#response-policy-zone)
  - [Unbound](#unbound)
  - [dnscrypt-proxy](#dnscrypt-proxy)
  - [Snort2](#snort2)
  - [Snort3](#snort3)
  - [Suricata](#suricata)
    - [Suricata (SNI)](#suricata-sni)
  - [Splunk](#splunk)
  - [Tracking Protection List (IE)](#tracking-protection-list-ie)
- [Compressed version](#compressed-version)
- [Reporting issues](#issues)
- [See also](#see-also)
- [FAQ and Guides](#faq-and-guides)
- [CI Variables](#ci-variables)
- [License](#license)

A blocklist of phishing websites, curated from [OpenPhish](https://openphish.com/), [IPThreat](https://ipthreat.net/) and [PhishTank](https://phishtank.org/). Blocklist is updated twice a day.

| Client | mirror 1 | mirror 2 | mirror 3 | mirror 4 | mirror 5 | mirror 6 |
| --- | --- | --- | --- | --- | --- | --- |
| [uBlock Origin](#url-based) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt) | [link](https://curbengh.github.io/malware-filter/phishing-filter.txt) | [link](https://curbengh.github.io/phishing-filter/phishing-filter.txt) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter.txt) | [link](https://malware-filter.pages.dev/phishing-filter.txt) | [link](https://phishing-filter.pages.dev/phishing-filter.txt) |
| [AdGuard Home/Pi-hole](#domain-based-adguard-home) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt) | [link](https://curbengh.github.io/malware-filter/phishing-filter-agh.txt) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-agh.txt) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-agh.txt) | [link](https://malware-filter.pages.dev/phishing-filter-agh.txt) | [link](https://phishing-filter.pages.dev/phishing-filter-agh.txt) |
| [AdGuard (browser extension)](#url-based-adguard)  | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-ag.txt) | [link](https://curbengh.github.io/malware-filter/phishing-filter-ag.txt) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-ag.txt) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-ag.txt) | [link](https://malware-filter.pages.dev/phishing-filter-ag.txt) | [link](https://phishing-filter.pages.dev/phishing-filter-ag.txt) |
| [Vivaldi/Brave](#url-based-vivaldi) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-vivaldi.txt) | [link](https://curbengh.github.io/malware-filter/phishing-filter-vivaldi.txt) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-vivaldi.txt) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-vivaldi.txt) | [link](https://malware-filter.pages.dev/phishing-filter-vivaldi.txt) | [link](https://phishing-filter.pages.dev/phishing-filter-vivaldi.txt) |
| [Hosts](#hosts-based) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt) | [link](https://curbengh.github.io/malware-filter/phishing-filter-hosts.txt) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-hosts.txt) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-hosts.txt) | [link](https://malware-filter.pages.dev/phishing-filter-hosts.txt) | [link](https://phishing-filter.pages.dev/phishing-filter-hosts.txt) |
| [Dnsmasq](#dnsmasq) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-dnsmasq.conf) | [link](https://curbengh.github.io/malware-filter/phishing-filter-dnsmasq.conf) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-dnsmasq.conf) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-dnsmasq.conf) | [link](https://malware-filter.pages.dev/phishing-filter-dnsmasq.conf) | [link](https://phishing-filter.pages.dev/phishing-filter-dnsmasq.conf) |
| BIND [zone](#bind) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-bind.conf) | [link](https://curbengh.github.io/malware-filter/phishing-filter-bind.conf) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-bind.conf) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-bind.conf) | [link](https://malware-filter.pages.dev/phishing-filter-bind.conf) | [link](https://phishing-filter.pages.dev/phishing-filter-bind.conf) |
| BIND [RPZ](#response-policy-zone) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-rpz.conf) | [link](https://curbengh.github.io/malware-filter/phishing-filter-rpz.conf) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-rpz.conf) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-rpz.conf) | [link](https://malware-filter.pages.dev/phishing-filter-rpz.conf) | [link](https://phishing-filter.pages.dev/phishing-filter-rpz.conf) |
| [dnscrypt-proxy](#dnscrypt-proxy) | [names.txt](https://malware-filter.gitlab.io/malware-filter/phishing-filter-dnscrypt-blocked-names.txt), [ips.txt](https://malware-filter.gitlab.io/malware-filter/phishing-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://curbengh.github.io/malware-filter/phishing-filter-dnscrypt-blocked-names.txt), [ips.txt](https://curbengh.github.io/malware-filter/phishing-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://curbengh.github.io/phishing-filter/phishing-filter-dnscrypt-blocked-names.txt), [ips.txt](https://curbengh.github.io/phishing-filter/phishing-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-dnscrypt-blocked-names.txt), [ips.txt](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://malware-filter.pages.dev/phishing-filter-dnscrypt-blocked-names.txt), [ips.txt](https://malware-filter.pages.dev/phishing-filter-dnscrypt-blocked-ips.txt) | [names.txt](https://phishing-filter.pages.dev/phishing-filter-dnscrypt-blocked-names.txt), [ips.txt](https://phishing-filter.pages.dev/phishing-filter-dnscrypt-blocked-ips.txt) |
| [blocky](#wildcard-asterisk) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-wildcard.txt) | [link](https://curbengh.github.io/malware-filter/phishing-filter-wildcard.txt) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-wildcard.txt) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-wildcard.txt) | [link](https://malware-filter.pages.dev/phishing-filter-wildcard.txt) | [link](https://phishing-filter.pages.dev/phishing-filter-wildcard.txt) |
| [Snort2](#snort2) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-snort2.rules) | [link](https://curbengh.github.io/malware-filter/phishing-filter-snort2.rules) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-snort2.rules) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-snort2.rules) | [br](https://malware-filter.pages.dev/phishing-filter-snort2.rules.br)/[gz](https://malware-filter.pages.dev/phishing-filter-snort2.rules.gz) | [link](https://phishing-filter.pages.dev/phishing-filter-snort2.rules) |
| [Snort3](#snort3) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-snort3.rules) | [link](https://curbengh.github.io/malware-filter/phishing-filter-snort3.rules) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-snort3.rules) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-snort3.rules) | [br](https://malware-filter.pages.dev/phishing-filter-snort3.rules.br)/[gz](https://malware-filter.pages.dev/phishing-filter-snort3.rules.gz) | [link](https://phishing-filter.pages.dev/phishing-filter-snort3.rules) |
| [Suricata](#suricata) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-suricata.rules) | [link](https://curbengh.github.io/malware-filter/phishing-filter-suricata.rules) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-suricata.rules) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-suricata.rules) | [br](https://malware-filter.pages.dev/phishing-filter-suricata.rules.br)/[gz](https://malware-filter.pages.dev/phishing-filter-suricata.rules.gz) | [link](https://phishing-filter.pages.dev/phishing-filter-suricata.rules) |
| [Suricata (SNI)](#suricata-sni)| [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-suricata-sni.rules) | [link](https://curbengh.github.io/malware-filter/phishing-filter-suricata-sni.rules) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-suricata-sni.rules) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-suricata-sni.rules) | [br](https://malware-filter.pages.dev/phishing-filter-suricata-sni.rules.br)/[gz](https://malware-filter.pages.dev/phishing-filter-suricata-sni.rules.gz) | [link](https://phishing-filter.pages.dev/phishing-filter-suricata-sni.rules) |
| [Splunk](#splunk) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter-splunk.csv) | [link](https://curbengh.github.io/malware-filter/phishing-filter-splunk.csv) | [link](https://curbengh.github.io/phishing-filter/phishing-filter-splunk.csv) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter-splunk.csv) | [link](https://malware-filter.pages.dev/phishing-filter-splunk.csv) | [link](https://phishing-filter.pages.dev/phishing-filter-splunk.csv) |
| [Internet Explorer](#tracking-protection-list-ie) | [link](https://malware-filter.gitlab.io/malware-filter/phishing-filter.tpl) | [link](https://curbengh.github.io/malware-filter/phishing-filter.tpl) | [link](https://curbengh.github.io/phishing-filter/phishing-filter.tpl) | [link](https://malware-filter.gitlab.io/phishing-filter/phishing-filter.tpl) | [link](https://malware-filter.pages.dev/phishing-filter.tpl) | [link](https://phishing-filter.pages.dev/phishing-filter.tpl) |

For other programs, see [Compatibility](https://gitlab.com/malware-filter/malware-filter/wikis/compatibility) page in the wiki.

Check out my other filters:

- [urlhaus-filter](https://gitlab.com/malware-filter/urlhaus-filter)
- [pup-filter](https://gitlab.com/malware-filter/pup-filter)
- [tracking-filter](https://gitlab.com/malware-filter/tracking-filter)
- [vn-badsite-filter](https://gitlab.com/malware-filter/vn-badsite-filter)

## URL-based

Import the link into uBO's filter list to subscribe.

_included by default in uBO >=[1.39.0](https://github.com/gorhill/uBlock/releases/tag/1.39.0); to enable, head to "Filter lists" tab, expand "Malware domains" section and tick "Phishing URL Blocklist"._

**AdGuard Home** users should use [this blocklist](#domain-based-adguard-home).

## URL-based (AdGuard)

Import the link into AdGuard browser extension to subscribe

## URL-based (Vivaldi)

For Vivaldi, blocking level must be at least "Block Trackers". Import the URL into Vivaldi's **Tracker Blocking Sources** to subscribe.

For Brave, "Trackers & ads blocking" must be set to Aggressive. Import it under Shields > Content filtering > Add custom filter lists.

## Domain-based

This blocklist includes domains and IP addresses.

## Wildcard asterisk

This blocklist includes domains and IP addresses.

## Domain-based (AdGuard Home)

This AdGuard Home-compatible blocklist includes domains and IP addresses. Also compatible with Pi-hole.

## Hosts-based

This blocklist includes domains only.

## Dnsmasq

This blocklist includes domains only.

Save the ruleset to "/usr/local/etc/dnsmasq/phishing-filter-dnsmasq.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnsmasq to use the blocklist:

`printf "\nconf-file=/usr/local/etc/dnsmasq/phishing-filter-dnsmasq.conf\n" >> /etc/dnsmasq.conf`

## BIND

This blocklist includes domains only.

Save the ruleset to "/usr/local/etc/bind/phishing-filter-bind.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure BIND to use the blocklist:

`printf '\ninclude "/usr/local/etc/bind/phishing-filter-bind.conf";\n' >> /etc/bind/named.conf`

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

## Response Policy Zone

This blocklist includes domains only.

## Unbound

This blocklist includes domains only.

Save the rulesets to "/usr/local/etc/unbound/phishing-filter-unbound.conf". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Unbound to use the blocklist:

`printf '\n  include: "/usr/local/etc/unbound/phishing-filter-unbound.conf"\n' >> /etc/unbound/unbound.conf`

## dnscrypt-proxy

Save the rulesets to "/etc/dnscrypt-proxy/". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure dnscrypt-proxy to use the blocklist:

```diff
[blocked_names]
+  blocked_names_file = '/etc/dnscrypt-proxy/phishing-filter-dnscrypt-blocked-names.txt'

[blocked_ips]
+  blocked_ips_file = '/etc/dnscrypt-proxy/phishing-filter-dnscrypt-blocked-ips.txt'
```

## Snort2

This ruleset includes online URLs only. Not compatible with [Snort3](#snort3).

Save the ruleset to "/etc/snort/rules/phishing-filter-snort2.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

`printf "\ninclude \$RULE_PATH/phishing-filter-snort2.rules\n" >> /etc/snort/snort.conf`

## Snort3

This ruleset includes online URLs only. Not compatible with [Snort2](#snort2).

Save the ruleset to "/etc/snort/rules/phishing-filter-snort3.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Snort to use the ruleset:

```diff
# /etc/snort/snort.lua
ips =
{
  variables = default_variables,
+  include = 'rules/phishing-filter-snort3.rules'
}
```

## Suricata

This ruleset includes online URLs only.

Save the ruleset to "/etc/suricata/rules/phishing-filter-suricata.rules". Refer to this [guide](https://gitlab.com/malware-filter/malware-filter/wikis/update-filter) for auto-update.

Configure Suricata to use the ruleset:

```diff
# /etc/suricata/suricata.yaml
rule-files:
  - local.rules
+  - phishing-filter-suricata.rules
```

### Suricata (SNI)

This ruleset includes online domains only. It enables Suricata to detect malicious HTTPS-enabled domains by inspecting the SNI in the [unencrypted ClientHello](https://en.wikipedia.org/wiki/Server_Name_Indication#Security_implications) message. There is increasing support for encrypted Client Hello which defeats SNI inspection.

## Splunk

A CSV file for Splunk [lookup](https://docs.splunk.com/Documentation/Splunk/latest/Knowledge/Aboutlookupsandfieldactions).

Either upload the file via GUI or save the file in `$SPLUNK_HOME/Splunk/etc/system/lookups` or app-specific `$SPLUNK_HOME/etc/YourApp/apps/search/lookups`.

Or use [malware-filter add-on](https://splunkbase.splunk.com/app/6970) to install this lookup and optionally auto-update it.

Columns:

| host | path | message | updated |
| --- | --- | --- | --- |
| example.com  | | phishing-filter phishing website detected | 2022-12-21T12:34:56Z |
| example2.com | /some-path | phishing-filter phishing website detected | 2022-12-21T12:34:56Z |

## Tracking Protection List (IE)

This blocklist includes domains and IP addresses. Supported in Internet Explorer 9+. [Install guide](https://superuser.com/a/550539)

## Compressed version

All filters are also available as gzip- and brotli-compressed.

- Gzip: https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt.gz
- Brotli: https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt.br

_Snort 2 rule is only available in compressed format in pages.dev due to the platform's 25MB file size limit_

## Issues

This blocklist operates by blocking the **whole** website, instead of specific webpages; exceptions are made on popular websites (e.g. `https://docs.google.com/`), in which webpages are specified instead (e.g. `https://docs.google.com/phishing-page`). Phishing webpages are only listed in [URL-based](#url-based) filter, popular websites are excluded from other filters.

_Popular_ websites are as listed in the [Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html) (top 1M domains + subdomains), [Tranco List](https://tranco-list.eu/) (top 1M domains), [Cloudflare Radar](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/) (top 1M domains) and this [custom list](src/exclude.txt).

If you wish to exclude certain website(s) that you believe is sufficiently well-known, please create an [issue](https://gitlab.com/malware-filter/phishing-filter/issues) or [merge request](https://gitlab.com/malware-filter/phishing-filter/merge_requests).

This blocklist **only** accepts new phishing URLs from [OpenPhish](https://openphish.com/) and [IPThreat](https://ipthreat.net/).

Please report new phishing URL to [OpenPhish](https://openphish.com/faq.html), [IPThreat](https://ipthreat.net/tools/reportphishing) or [PhishTank](https://phishtank.org/add_web_phish.php).

## See also

[Phishing Army](https://phishing.army/) by [Andrea Draghetti](https://www.andreadraghetti.it/) is available in domain-based format and utilises more sources. Its exclusion methods are not up-to-date though: [Anudeep's whitelist](https://github.com/anudeepND/whitelist) was lasted updated in Dec 2021 and [Alexa](https://www.alexa.com/topsites) was deprecated in May 2022.

## FAQ and Guides

See [wiki](https://gitlab.com/malware-filter/malware-filter/-/wikis/home)

## CI Variables

Optional variables:

- `PHISHTANK_API`: Recommended if you intend to run [script.sh](src/script.sh) >5 times daily. Register an account at [phishtank.org](https://phishtank.org/developer_info.php) to generate an application key
- `CLOUDFLARE_BUILD_HOOK`: Deploy to Cloudflare Pages.
- `NETLIFY_SITE_ID`: Deploy to Netlify.
- `CF_API`: Include Cloudflare Radar [domains ranking](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/). [Guide](https://developers.cloudflare.com/radar/get-started/first-request/) to create an API token.

## Repository Mirrors

https://gitlab.com/curben/blog#repository-mirrors

## License

[src/](src/): [Creative Commons Zero v1.0 Universal](LICENSE-CC0.md) and [MIT License](LICENSE)

filters: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)

[OpenPhish](https://openphish.com/): Available [free of charge](https://openphish.com/terms.html) by OpenPhish

[IPThreat](https://ipthreat.net): CC BY-SA 4.0

[PhishTank](https://phishtank.org/): Available [free of charge](https://phishtank.org/faq.php#isitoktousetheapifor) by PhishTank

[Tranco List](https://tranco-list.eu/): [MIT License](https://choosealicense.com/licenses/mit/)

[Umbrella Popularity List](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html): Available free of charge by Cisco Umbrella

[csvquote](https://github.com/dbro/csvquote): MIT License

[Cloudflare Radar](https://developers.cloudflare.com/radar/investigate/domain-ranking-datasets/): Available to free Cloudflare account

This repository is not endorsed by any of the upstream sources.
