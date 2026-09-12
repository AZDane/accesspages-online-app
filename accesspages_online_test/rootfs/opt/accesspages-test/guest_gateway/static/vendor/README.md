# Vendored browser libraries

## qrcodegen.js

- Project: [QR Code generator library](https://github.com/nayuki/QR-Code-generator)
- Upstream commit: `2c9044de6b049ca25cb3cd1649ed7e27aa055138`
- Source: `typescript-javascript/qrcodegen.ts`
- License: MIT; the complete notice is retained at the top of `qrcodegen.js`.
- Compiler: TypeScript 5.9.2 with `--strict --lib DOM,DOM.Iterable,ES6 --target ES6`.

The Gateway serves this file locally. It does not load a QR library, font, image,
or other asset from a CDN, and QR payloads are never sent to a QR-generation
service.
