# DCK Google IP Ranges Relay

A small, fail-closed relay for DigiCompKala security tooling.

GitHub Actions fetches and validates Google's official crawler/fetcher IP range feeds every 6 hours, then publishes one aggregate file at:

`dist/google-ipranges.json`

Included official sources:

- `common-crawlers.json`
- `special-crawlers.json`
- `user-triggered-fetchers-google.json`
- `user-triggered-agents.json`

Intentionally excluded:

- `user-triggered-fetchers.json`

The broader excluded feed may include user-controlled Google Cloud/App Engine fetchers and is not treated as a blanket security whitelist.

## Safety properties

- HTTPS-only official Google sources.
- JSON and CIDR validation before publish.
- Empty or malformed feeds fail the workflow.
- Source SHA-256 hashes are recorded in the relay output.
- Existing published output is not overwritten when a refresh fails.
- The relay file is committed only when the semantic Google range data changes.
- DigiCompKala's server-side FCrDNS verification remains the fallback when the relay is unavailable.

## Schedule

The workflow runs every 6 hours and can also be started manually from GitHub Actions.
