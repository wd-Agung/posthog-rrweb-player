# Posthog rrweb player

Standalone browser player for PostHog rrweb session replay files.

Open the GitHub Pages site, choose a local recording JSON/JSONL file, optionally paste a GCP service account JSON to regenerate GCS signed image URLs, then patch and play the replay locally in the browser.

The service account JSON is processed in the browser with WebCrypto and is not uploaded by this page.
