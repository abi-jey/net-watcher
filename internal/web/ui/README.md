The web UI build output (`dist/`) is embedded into the binary from here.
It is generated from `web/` and not committed:

    make ui        # or: cd web && npm ci && npm run build

Without it the server still runs and serves the API; `/` explains how to build the UI.
