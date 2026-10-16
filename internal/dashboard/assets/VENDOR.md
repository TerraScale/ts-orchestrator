# Vendored dashboard assets

Third-party JavaScript and JSON assets are pinned, unmodified upstream files, embedded into the binary with `go:embed` and served
under a content-hash URL with `Cache-Control: immutable`. Nothing is loaded
from a CDN and there is no node/npm build step. To update a file, download the
new release from the URL below, verify the registry integrity, replace the
file and update this table.

| File | Library | Version | License | Source | sha256 |
|------|---------|---------|---------|--------|--------|
| `echarts.min.js` | Apache ECharts | 5.6.0 | Apache-2.0 | `package/dist/echarts.min.js` of https://registry.npmjs.org/echarts/-/echarts-5.6.0.tgz (npm integrity `sha512-oTbVTsXfKuEhxftHqL5xprgLoc0k7uScAwtryCgWF6hPYFLRwOUHiFmHGCBKP5NPFNkDVopOieyUqYGH8Fa3kA==`, verified) | `bf4a223524e40b77c304bec67e1222cf551f14880cf42c69dc046558e11c07b1` |
| `world.json` | Apache ECharts world map GeoJSON | 4.9.0 | Apache-2.0 (geometry derived from Natural Earth, public domain) | `package/map/json/world.json` of https://registry.npmjs.org/echarts/-/echarts-4.9.0.tgz (npm integrity `sha512-+ugizgtJ+KmsJyyDPxaw2Br5FqzuBnyOWwcxPKO6y0gc5caYcfnEUIlNStx02necw8jmKmTafmpHhGo4XDtEIA==`, verified). ECharts 5 no longer ships map data; this is the last official release that does. | `049b334579e5a42d5d16c72d014d380e048e39fc1504049f212acb589484d2fa` |
| Pico base prefix in `dashboard.css` | Pico CSS | 2.1.1 | MIT | `css/pico.min.css` of the v2.1.1 release | `fbc9a63fc9fc9f72d12fd7fc9806e11fa9f77ae4f9cad146b27003a1119ba3db` |
| `datastar.js` | Datastar | 1.0.4 | MIT | `bundles/datastar.js` of the v1.0.4 release | `727844adfc825ee651fb93c544a2a739986f9a21820a94524b35f0cac470cf91` |

uPlot is not vendored: ECharts with downsampled history tiers (raw, 1m, 5m)
keeps every panel well under a few thousand points.

First-party files (not vendored): `app.js` (the `<ts-*>` custom elements,
command palette, toasts and notifications) and the suffix of `dashboard.css` (layout and the
status color system). The stylesheet starts with the byte-for-byte Pico 2.1.1
base listed above, followed by a separator comment and the first-party rules;
the original MIT notice is retained. There is no separate Pico stylesheet.

Verify the vendored files with:

```sh
sha256sum internal/dashboard/assets/{echarts.min.js,world.json,datastar.js}
```
