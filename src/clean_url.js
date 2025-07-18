'use strict'

import { createInterface } from 'node:readline'

// nodejs does not percent-encode ^ yet
// https://github.com/nodejs/node/issues/57313
// Applies to path, exclude query string
const caretPath = (pathname) => {
  if (!pathname.includes('?')) return pathname.replaceAll('^', '%5E')

  const pathArray = pathname.split('?')
  const path = pathArray[0].replaceAll('^', '%5E')
  const search = pathArray.slice(1).join('?')

  return `${path}?${search}`
}

const safeLinks = [
  'safelinks\\.protection\\.outlook\\.com',
  '\\.protection\\.sophos\\.com',
  'linkprotect\\.cudasvc\\.com'
]

const deSafelink = (urlStr) => {
  let url = new URL(urlStr)

  // O365 Safelinks
  if (url.hostname.endsWith('safelinks.protection.outlook.com')) {
    url = new URL(url.searchParams.get('url'))
  }

  // #92
  if (url.hostname.endsWith('.protection.sophos.com')) {
    url = new URL(`http://${url.searchParams.get('d')}`)
  }

  // Barracuda
  if (url.hostname.endsWith('linkprotect.cudasvc.com')) {
    url = new URL(url.searchParams.get('a'))
  }

  // ShopMy & Disqus
  if ((url.hostname === 'api.shopmy.us' && url.pathname === '/api/redirect_click') || url.hostname === 'disq.us') {
    url = new URL(url.searchParams.get('url'))
  }

  // VKontakte
  if ((url.hostname === 'vk.com' || url.hostname === 'vkontakte.ru') && url.pathname === '/away.php') {
    url = new URL(url.searchParams.get('to'))
  }

  // WhatsApp
  if (url.hostname === 'l.wl.co' && url.pathname === '/l') {
    url = new URL(decodeURIComponent(url.href.replaceAll('&amp;', '&')))
    url = new URL(url.searchParams.get('u'))
  }

  // Google Ads
  if (url.hostname.endsWith('doubleclick.net') || url.hostname.endsWith('googleadservices.com')) {
    url = new URL(url.href.replaceAll('&amp;', '&'))
    const paramUrl = url.searchParams.getAll('adurl').at(-1) || url.searchParams.getAll('url').at(-1) || url.searchParams.getAll('ds_dest_url').at(-1)
    if (paramUrl) url = new URL(paramUrl)
  }

  // Google Search
  // Google AMP does not redirect (e.g. google.com/amp/example.com)
  if (url.hostname.endsWith('google.com') && (url.pathname.startsWith('/url') || url.pathname.startsWith('/travel/clk'))) {
    url = new URL(url.href.replaceAll('&amp;', '&'))
    const paramUrl = url.searchParams.get('q') || url.searchParams.get('url') || url.searchParams.get('pcurl')
    if (paramUrl) url = new URL(paramUrl)
  }

  // SES
  // https://github.com/uBlockOrigin/uAssets/blob/42e518277ab0c36d4b131aa01b4a8828af4e18b6/filters/privacy.txt#L866
  if (url.hostname.endsWith('awstrack.me' && url.pathname.startsWith('/L0'))) {
    url = new URL(decodeURIComponent(url.pathname.match(/\/L0\/(http[^\/?#]+)/)[1]))
  }

  // DuckDuckGo
  if (url.hostname === 'duckduckgo.com' && url.pathname === '/l/') {
    url = new URL(url.searchParams.get('uddg'))
  }

  // "Just have to go deep enough."
  if (url.hostname.match(new RegExp(safeLinks.join('|')))) {
    return deSafelink(url.href)
  }

  return url.href
}

for await (const line of createInterface({ input: process.stdin, terminal: false })) {
  // parse hostname from url
  if (process.argv[2] === 'hostname') {
    if (URL.canParse(`http://${line}`)) {
      const { hostname } = new URL(`http://${line}`)

      console.log(hostname)
    } else {
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
      const url = new URL(deSafelink(line))

      url.host = url.host.replace(/^www\./, '')

      url.pathname = caretPath(url.pathname)
      const outUrl = `${url.host}${url.pathname}${url.search}`
        // remove trailing slash from domain except path #43
        .replace(/(^[^/]*)\/+$/, '$1')

      console.log(outUrl)
    } else {
      const outUrl = caretPath(line)
        // remove protocol
        .split('/').slice(2).join('/')
        // remove www
        .replace(/^www\./, '')
        // url encode space #11
        .replaceAll(' ', '%20')
        .replace(/(^[^/]*)\/+$/, '$1')

      console.log(outUrl)
    }
  }
}
