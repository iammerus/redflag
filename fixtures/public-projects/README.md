# Frozen public-project inputs

`manifest.json` records complete Vite React, Next.js static-export and Astro blog
example subtrees at exact upstream commits, including their upstream license
notices. Each file has a Git blob identity, byte count and SHA-256 digest.

Fetch them into a new directory with `scripts/project_fixtures.py fetch`; verify
existing snapshots with its `verify` operation. The downloader neither installs
packages nor executes source code. Upstream source/assets and compiled output are
not vendored into Redflag or included in its release bundles.

`build-locks` contains the npm package declarations and complete lockfiles used by
`scripts/build_project_fixtures.py`. Next's moving `latest` dependency is fixed to
16.3.5 and its TypeScript range is fixed to 5.9.3. Other upstream dependency
ranges remain unchanged; exact installed versions and integrity hashes come from
the committed locks. Builds use copies, leaving the frozen snapshots unchanged.

To build and benchmark the examples without publishing them:

```sh
project_work="$(mktemp -d)"
python3 scripts/project_fixtures.py fetch --directory "$project_work/snapshots"
python3 scripts/build_project_fixtures.py --snapshots "$project_work/snapshots" --directory "$project_work/builds"
python3 scripts/benchmark_projects.py --binary target/release/redflag \
  --betterleaks-path target/release/engines/betterleaks \
  --snapshots "$project_work/snapshots" --builds "$project_work/builds" \
  --output "$project_work/results.json"
```

These public examples test compatibility and local timing. Repeated scans of the
same build do not establish production accuracy.
