# Posthog rrweb player

Standalone browser player for PostHog rrweb session replay files.

Open the GitHub Pages site, choose a local recording JSON/JSONL file, optionally paste a GCP service account JSON to regenerate GCS signed image URLs, then either:

- patch and download/play a modified JSON file, or
- enable the service worker live patcher to rewrite GCS image requests during playback.

For large recordings, `Patch & play` uses the service worker live patcher automatically so the browser does not need to rewrite the whole recording before playback. Smaller recordings still use a Web Worker to generate a patched JSON download without blocking the UI thread.

The service account JSON is processed in the browser with WebCrypto and is not uploaded by this page.
