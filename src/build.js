'use strict'

// for deployment outside of GitLab CI, e.g. Cloudflare Pages and Netlify

const { stream: gotStream } = require('got')
const got = require('got')
const unzip = require('extract-zip')
const { join } = require('path')
const { mkdir, rm } = require('fs/promises')
const { createWriteStream } = require('fs')
const { pipeline } = require('stream/promises')

const rootPath = join(__dirname, '..')
const tmpPath = join(rootPath, 'tmp')
const publicPath = join(rootPath, 'public')
const zipPath = join(tmpPath, 'artifacts.zip')
const artifactsUrl = 'https://gitlab.com/malware-filter/phishing-filter/-/jobs/artifacts/main/download?job=pages'
const pipelineUrl = 'https://gitlab.com/malware-filter/phishing-filter/badges/main/pipeline.svg'
const ghMirror = 'https://nightly.link/curbengh/phishing-filter/workflows/pages/main/public.zip'

const pipelineStatus = async (url) => {
  try {
    const svg = await got(url).text()
    if (!svg.includes('passed')) throw new Error('last gitlab pipeline failed')
  } catch ({ message }) {
    throw new Error(message)
  }
}

const f = async () => {
  let isMirror = false

  await mkdir(tmpPath, { recursive: true })

  console.log(`Downloading artifacts.zip from "${artifactsUrl}"`)
  try {
    await pipeline(
      gotStream(artifactsUrl),
      createWriteStream(zipPath)
    )
    await pipelineStatus(pipelineUrl)
  } catch ({ message }) {
    console.error(JSON.stringify({
      error: message,
      link: artifactsUrl
    }))

    console.log(`Downloading artifacts.zip from "${ghMirror}"`)
    isMirror = true

    try {
      await pipeline(
        gotStream(ghMirror),
        createWriteStream(zipPath)
      )
    } catch ({ message }) {
      throw new Error(JSON.stringify({
        error: message,
        link: ghMirror
      }))
    }
  }

  console.log('Extracting artifacts.zip...')
  if (isMirror === false) {
    await unzip(zipPath, { dir: rootPath })
    // snort2.rules is over 25MB limit of CF Pages
    await rm(join(publicPath, 'phishing-filter-snort2.rules'), { force: true })
  } else {
    await mkdir(publicPath, { recursive: true })
    await unzip(zipPath, { dir: publicPath })
    await rm(join(publicPath, 'phishing-filter-snort2.rules'), { force: true })
  }
}

f()