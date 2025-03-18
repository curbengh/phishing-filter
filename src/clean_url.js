import { createInterface } from "node:readline"

for await (const line of createInterface({ input: process.stdin })) {
  // parse hostname from url
  if (process.argv[2] === 'hostname') {
    if (URL.canParse(`http://${line}`)) {
      const { hostname } = new URL(`http://${line}`)

      console.log(hostname)
    }
    else {
      const hostname = line
      // host
      .split('/')[0]
      // exclude credential
      .replace(/.*@(.+)/, '$1')
      // exclude port
      .replace(/:\d+$/, '')
      // #2
      .split('?')[0]

      console.log(hostname)
    }
  } else {
    if (URL.canParse(line)) {
      let url = new URL(line)

      // Decode O365 Safelinks
      // https://support.microsoft.com/en-us/office/advanced-outlook-com-security-for-microsoft-365-subscribers-882d2243-eab9-4545-a58a-b36fee4a46e2
      if (url.hostname.endsWith('safelinks.protection.outlook.com')) {
        url = new URL(url.searchParams.get('url'))
      }

      const outUrl = `${url.host.replace(/^www\./, '')}${url.pathname}${url.search}`
      // remove trailing slash from domain except path #43
      .replace(/(^[^\/]*)\/+$/, '$1')

      console.log(outUrl)
    }
    else {
      const outUrl = line
      // remove protocol
      .split('/').slice(2).join('/')
      // remove www
      .replace(/^www\./, '')
      // url encode space #11
      .replace(' ', '%20')
      .replace(/(^[^\/]*)\/+$/, '$1')

      console.log(outUrl)
    }
  }
}
