# wwwroot/lib/

Drop `egov-helper.min.js` here.

Quickest path:

```bash
# from your real project root (not this example dir)
npm install @smoker_winston/egov-helper
cp node_modules/@smoker_winston/egov-helper/dist/egov-helper.min.js wwwroot/lib/
```

The Razor view uses:

```html
<script src="~/lib/egov-helper.min.js" asp-append-version="true"></script>
```

`asp-append-version` adds a fingerprint query param so browsers re-fetch when you update the bundle.

Alternative: pull from a CDN to skip the copy step entirely:

```html
<script src="https://unpkg.com/@smoker_winston/egov-helper@0.3.0/dist/egov-helper.min.js"
        crossorigin="anonymous"></script>
```

Bundle size: ~298 KB minified, ~115 KB gzipped. CDN-fine for one-off contract pages.
