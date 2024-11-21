# appsec-stats-feed

Application that listens to incoming github webhooks with dependabot & code scanning alerts and sends them to metabase.
Setup webhook with secret saved in `GITHUB_HMAC_SECRET_KEY` env variable under prod-gcp>appsec-stats-feed in nais console.

