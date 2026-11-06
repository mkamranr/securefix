# Bundled front-end libraries

Served by the app itself, because the server has no internet access and the proxy's CSP only allows the app's own
files. Copied from the npm packages below (source map comments removed); update them by downloading a newer
package with `npm pack <name>@<version>` and copying the same files.

| Files | Package | License |
| --- | --- | --- |
| `tabler/tabler.min.css`, `tabler/tabler.min.js` | `@tabler/core` 1.6.1 (includes Bootstrap 5) | MIT (header of each file) |
| `inter/inter-latin-wght-normal.woff2` | `@fontsource-variable/inter` 5.3.0 | SIL OFL 1.1 (`inter/LICENSE.txt`) |
| `../icons.svg` (only the icons the app uses, as a sprite) | `@tabler/icons` 3.49.0 | MIT (`tabler/LICENSE-icons.txt`) |
