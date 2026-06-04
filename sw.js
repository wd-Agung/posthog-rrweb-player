let gcsSigner = null
let gcsBucketMap = new Map()
let gcsEnabled = false

self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting())
})

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim())
})

self.addEventListener('message', (event) => {
  const port = event.ports && event.ports[0]
  configure(event.data)
    .then(() => port && port.postMessage({ ok: true }))
    .catch((error) => port && port.postMessage({ ok: false, error: error.message || String(error) }))
})

self.addEventListener('fetch', (event) => {
  if (!gcsEnabled || event.request.method !== 'GET') return

  const gcsObject = parseGcsUrl(event.request.url)
  if (!gcsObject) return

  event.respondWith(fetchPatchedGcsObject(event.request, gcsObject))
})

async function configure(message) {
  if (!message || message.type !== 'configure-gcs-patcher') return

  gcsBucketMap = new Map(message.bucketMap || [])
  gcsSigner = message.serviceAccount
    ? await GcsV4Signer.create(message.serviceAccount, Number(message.expiresSeconds || 604800))
    : null
  gcsEnabled = Boolean(gcsSigner || gcsBucketMap.size)
}

async function fetchPatchedGcsObject(request, gcsObject) {
  const targetBucket = gcsBucketMap.get(gcsObject.bucket) || gcsObject.bucket
  const patchedUrl = gcsSigner
    ? await gcsSigner.signUrl(targetBucket, gcsObject.objectName)
    : buildUnsignedGcsUrl(targetBucket, gcsObject.objectName)

  if (patchedUrl === request.url) {
    return fetch(request)
  }

  return fetch(patchedUrl, {
    mode: request.mode === 'navigate' ? 'cors' : 'no-cors',
    credentials: 'omit',
    cache: 'default',
    redirect: 'follow',
  })
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
