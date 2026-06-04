let URL_RE = /https?:\/\/[^\s<>"')]+/g

self.addEventListener('message', (event) => {
  runPatch(event.data).catch((error) => {
    self.postMessage({ type: 'error', error: error.message || String(error) })
  })
})

async function runPatch(message) {
  if (!message || message.type !== 'patch-recording') return

  URL_RE = new RegExp(message.urlPattern || URL_RE.source, 'g')
  const values = message.values || []
  const bucketMap = new Map(message.bucketMap || [])
  const serviceAccount = message.serviceAccount || null
  const expiresSeconds = Number(message.expiresSeconds || 604800)
  const signer = serviceAccount ? await GcsV4Signer.create(serviceAccount, expiresSeconds) : null
  const patcher = new GcsUrlPatcher(signer, bucketMap)
  const stats = { urlsSeen: 0, urlsReplaced: 0, bucketRewrites: 0 }
  const progress = { done: 0, total: values.length, scanned: 0, lastReported: 0 }
  const patchedValues = []

  for (let index = 0; index < values.length; index += 1) {
    patchedValues.push(await patchGcsUrls(values[index], patcher, stats, progress))
    progress.done = index + 1
    self.postMessage({ type: 'progress', done: progress.done, total: progress.total, scanned: progress.scanned })
  }

  self.postMessage({ type: 'done', values: patchedValues, stats })
}

class GcsV4Signer {
  constructor(serviceAccount, privateKey, expiresSeconds) {
    this.clientEmail = serviceAccount.client_email
    this.privateKey = privateKey
    this.expiresSeconds = expiresSeconds
    this.cache = new Map()
  }

  static async create(serviceAccount, expiresSeconds) {
    if (!serviceAccount.client_email || !serviceAccount.private_key) {
      throw new Error('Service account JSON must contain client_email and private_key.')
    }

    if (!Number.isFinite(expiresSeconds) || expiresSeconds < 1 || expiresSeconds > 604800) {
      throw new Error('Signed URL lifetime must be between 1 and 604800 seconds.')
    }

    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      pemToArrayBuffer(serviceAccount.private_key),
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    )
    return new GcsV4Signer(serviceAccount, privateKey, Math.floor(expiresSeconds))
  }

  async signUrl(bucket, objectName) {
    const cacheKey = `${bucket}\n${objectName}`
    if (this.cache.has(cacheKey)) return this.cache.get(cacheKey)

    const now = new Date()
    const datestamp = utcDateStamp(now)
    const timestamp = utcTimestamp(now)
    const credentialScope = `${datestamp}/auto/storage/goog4_request`
    const credential = `${this.clientEmail}/${credentialScope}`
    const canonicalUri = `/${gcsEscape(bucket)}/${gcsEscape(objectName, '/~')}`
    const queryParams = {
      'X-Goog-Algorithm': 'GOOG4-RSA-SHA256',
      'X-Goog-Credential': credential,
      'X-Goog-Date': timestamp,
      'X-Goog-Expires': String(this.expiresSeconds),
      'X-Goog-SignedHeaders': 'host',
    }
    const canonicalQuery = Object.entries(queryParams)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${gcsEscape(key)}=${gcsEscape(value)}`)
      .join('&')
    const canonicalRequest = [
      'GET',
      canonicalUri,
      canonicalQuery,
      'host:storage.googleapis.com\n',
      'host',
      'UNSIGNED-PAYLOAD',
    ].join('\n')
    const stringToSign = [
      'GOOG4-RSA-SHA256',
      timestamp,
      credentialScope,
      await sha256Hex(canonicalRequest),
    ].join('\n')
    const signature = await signHex(this.privateKey, stringToSign)
    const signedUrl = `https://storage.googleapis.com${canonicalUri}?${canonicalQuery}&X-Goog-Signature=${signature}`
    this.cache.set(cacheKey, signedUrl)
    return signedUrl
  }
}

class GcsUrlPatcher {
  constructor(signer, bucketMap) {
    this.signer = signer
    this.bucketMap = bucketMap
  }

  async patchUrl(url, stats) {
    const gcsObject = parseGcsUrl(url)
    if (!gcsObject) return url

    stats.urlsSeen += 1
    const targetBucket = this.bucketMap.get(gcsObject.bucket) || gcsObject.bucket
    if (targetBucket !== gcsObject.bucket) {
      stats.bucketRewrites += 1
    }

    const patchedUrl = this.signer
      ? await this.signer.signUrl(targetBucket, gcsObject.objectName)
      : buildUnsignedGcsUrl(targetBucket, gcsObject.objectName)

    if (patchedUrl !== url) {
      stats.urlsReplaced += 1
    }
    return patchedUrl
  }
}

async function patchGcsUrls(value, patcher, stats, progress) {
  noteProgress(progress)

  if (typeof value === 'string') {
    return patchGcsUrlsInString(value, patcher, stats)
  }

  if (Array.isArray(value)) {
    const output = new Array(value.length)
    for (let index = 0; index < value.length; index += 1) {
      output[index] = await patchGcsUrls(value[index], patcher, stats, progress)
    }
    return output
  }

  if (value && typeof value === 'object') {
    const output = {}
    for (const [key, item] of Object.entries(value)) {
      output[key] = await patchGcsUrls(item, patcher, stats, progress)
    }
    return output
  }

  return value
}

function noteProgress(progress) {
  progress.scanned += 1
  if (progress.scanned - progress.lastReported < 5000) return
  progress.lastReported = progress.scanned
  self.postMessage({
    type: 'progress',
    done: progress.done,
    total: progress.total,
    scanned: progress.scanned,
  })
}

async function patchGcsUrlsInString(value, patcher, stats) {
  let output = ''
  let lastIndex = 0

  for (const match of value.matchAll(URL_RE)) {
    output += value.slice(lastIndex, match.index)
    output += await patcher.patchUrl(match[0], stats)
    lastIndex = match.index + match[0].length
  }

  return output + value.slice(lastIndex)
}

function parseGcsUrl(url) {
  let parsed
  try {
    parsed = new URL(url)
  } catch (_) {
    return null
  }

  const host = parsed.hostname.toLowerCase()
  const path = parsed.pathname.replace(/^\/+/, '')

  if (host === 'storage.googleapis.com' || host === 'storage.cloud.google.com') {
    const slash = path.indexOf('/')
    if (slash <= 0) return null
    return {
      bucket: decodeURIComponent(path.slice(0, slash)),
      objectName: decodeURIComponent(path.slice(slash + 1)),
    }
  }

  if (host.endsWith('.storage.googleapis.com')) {
    const bucket = host.slice(0, -'.storage.googleapis.com'.length)
    if (!bucket || !path) return null
    return { bucket, objectName: decodeURIComponent(path) }
  }

  if (host === 'www.googleapis.com' && path.startsWith('download/storage/v1/b/')) {
    const parts = path.split('/')
    if (parts.length >= 7 && parts[5] === 'o') {
      return {
        bucket: decodeURIComponent(parts[4]),
        objectName: decodeURIComponent(parts.slice(6).join('/')),
      }
    }
  }

  return null
}

function buildUnsignedGcsUrl(bucket, objectName) {
  return `https://storage.googleapis.com/${gcsEscape(bucket)}/${gcsEscape(objectName, '/~')}`
}

function gcsEscape(value, safe = '') {
  return encodeURIComponent(value)
    .replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/%2F/g, safe.includes('/') ? '/' : '%2F')
    .replace(/%7E/g, safe.includes('~') ? '~' : '%7E')
}

function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, '')
    .replace(/-----END PRIVATE KEY-----/g, '')
    .replace(/\s+/g, '')
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes.buffer
}

async function sha256Hex(value) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
  return bytesToHex(new Uint8Array(digest))
}

async function signHex(privateKey, value) {
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    privateKey,
    new TextEncoder().encode(value)
  )
  return bytesToHex(new Uint8Array(signature))
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('')
}

function utcDateStamp(date) {
  return [
    date.getUTCFullYear(),
    String(date.getUTCMonth() + 1).padStart(2, '0'),
    String(date.getUTCDate()).padStart(2, '0'),
  ].join('')
}

function utcTimestamp(date) {
  return `${utcDateStamp(date)}T${String(date.getUTCHours()).padStart(2, '0')}${String(date.getUTCMinutes()).padStart(2, '0')}${String(date.getUTCSeconds()).padStart(2, '0')}Z`
}
