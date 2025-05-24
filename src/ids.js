'use strict'

import { createWriteStream } from 'node:fs'
import { open } from 'node:fs/promises'

const domains = await open('phishing-notop-domains.txt')
const urls = await open('phishing-url-top-domains-raw.txt')

const snort2 = createWriteStream('../public/phishing-filter-snort2.rules', {
  encoding: 'utf8',
  flags: 'a'
})
const snort3 = createWriteStream('../public/phishing-filter-snort3.rules', {
  encoding: 'utf8',
  flags: 'a'
})
const suricata = createWriteStream('../public/phishing-filter-suricata.rules', {
  encoding: 'utf8',
  flags: 'a'
})
const suricataSni = createWriteStream('../public/phishing-filter-suricata-sni.rules', {
  encoding: 'utf8',
  flags: 'a'
})
const splunk = createWriteStream('../public/phishing-filter-splunk.csv', {
  encoding: 'utf8',
  flags: 'a'
})

let sid = 200000001

for await (const domain of domains.readLines()) {
  snort2.write(`alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443] (msg:"phishing-filter phishing website detected"; flow:established,from_client; content:"GET"; http_method; content:"${domain}"; content:"Host"; http_header; classtype:attempted-recon; sid:${sid}; rev:1;)\n`)
  snort3.write(`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"phishing-filter phishing website detected"; http_header:field host; content:"${domain}",nocase; classtype:attempted-recon; sid:${sid}; rev:1;)\n`)
  suricata.write(`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"phishing-filter phishing website detected"; flow:established,from_client; http.method; content:"GET"; http.host; content:"${domain}"; classtype:attempted-recon; sid:${sid} rev:1;)\n`)
  suricataSni.write(`alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"phishing-filter phishing website detected"; flow:established,from_client; tls.sni; bsize:32; content:"${domain}"; fast_pattern; classtype:attempted-recon; sid:${sid} rev:1;)\n`)
  splunk.write(`"${domain}","","phishing-filter phishing website detected","${process.env.CURRENT_TIME}"\n`)

  sid++
}

suricataSni.close()

for await (const line of urls.readLines()) {
  if (!URL.canParse(`http://${line}`)) {
    console.error(`Invalid URL: ${line}`)
    continue
  }

  const url = new URL(`http://${line}`)
  const { hostname, pathname, search } = url
  const pathEscape = `${pathname}${search}`.replaceAll(';', '\\;')
  const path = pathname + search

  snort2.write(`alert tcp $HOME_NET any -> $EXTERNAL_NET [80,443] (msg:"phishing-filter phishing website detected"; flow:established,from_client; content:"GET"; http_method; content:"${pathEscape.substring(0, 2048)}"; http_uri; nocase; content:"${hostname}"; content:"Host"; http_header; classtype:attempted-recon; sid:${sid}; rev:1;)\n`)
  snort3.write(`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"phishing-filter phishing website detected"; http_header:field host; content:"${hostname}",nocase; http_uri; content:"${pathEscape}",nocase; classtype:attempted-recon; sid:${sid}; rev:1;)\n`)
  suricata.write(`alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"phishing-filter phishing website detected"; flow:established,from_client; http.method; content:"GET"; http.uri; content:"${pathEscape}"; endswith; nocase; http.host; content:"${hostname}"; classtype:attempted-recon; sid:${sid}; rev:1;)\n`)
  splunk.write(`"${hostname}","${path}","phishing-filter phishing website detected","${process.env.CURRENT_TIME}"\n`)

  sid++
}

snort2.close()
snort3.close()
suricata.close()
splunk.close()
