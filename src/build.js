'use strict'

// for deployment outside of GitLab CI, e.g. Cloudflare Pages and Netlify

import { Extract } from 'unzipper'
import { dirname, join } from 'node:path'
import { mkdir, readdir, rm, stat } from 'node:fs/promises'
import { pipeline } from 'node:stream/promises'
import { fileURLToPath } from 'node:url'
import { Readable } from 'node:stream'

const __dirname = dirname(fileURLToPath(import.meta.url))
const rootPath = join(__dirname, '..')
const publicPath = join(rootPath, 'public')
const artifactsUrl = 'https://gitlab.com/malware-filter/phishing-filter/-/jobs/artifacts/main/download?job=pages'
const pipelineUrl = 'https://gitlab.com/malware-filter/phishing-filter/badges/main/pipeline.svg'
const ghMirror = 'https://nightly.link/curbengh/phishing-filter/workflows/pages/main/public.zip'

const pipelineStatus = async (url) => {
  console.log(`Checking pipeline from "${url}"`)
  try {
    const svg = await (await fetch(url)).text()
    if (!svg.includes('passed')) throw new Error('last gitlab pipeline failed')
  } catch ({ message }) {
    throw new Error(message)
  }
}

const f = async () => {
  console.log(`Downloading artifacts.zip from "${artifactsUrl}"`)
  try {
    await pipeline(
      Readable.fromWeb((await fetch(artifactsUrl)).body),
      Extract({ path: rootPath })
    )
    await pipelineStatus(pipelineUrl)
  } catch ({ message }) {
    console.error(JSON.stringify({
      error: message,
      link: artifactsUrl
    }))

    console.log(`Downloading artifacts.zip from "${ghMirror}"`)

    await mkdir(publicPath, { recursive: true })

    try {
      await pipeline(
        Readable.fromWeb((await fetch(ghMirror)).body),
        Extract({ path: publicPath })
      )
    } catch ({ message }) {
      throw new Error(JSON.stringify({
        error: message,
        link: ghMirror
      }))
    }
  }

  // Cloudflare Pages has maximum file size of 25MiB
  if (process.env.CF_PAGES) {
    const files = await readdir(publicPath)
    for (const filename of files) {
      const { size } = await stat(join(publicPath, filename))
      if (size >= (25 * 1024 * 1024)) {
        await rm(join(publicPath, filename), { force: true })
      }
    }
  }
}

f()
