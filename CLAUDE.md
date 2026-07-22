# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Static website for **Inter Club Norvegia** — official Norwegian supporters' club for F.C. Internazionale Milano. Site language is Norwegian (Bokmål, `lang="nb-NO"`). Deployed at fcinter.no. No build step, no framework, no package manager — plain HTML/CSS/JS served as-is.

## Deploy

Hosted on **Cloudflare Pages**, connected to this GitHub repo. Pushing to `main` triggers automatic deploy — no manual build/publish. There is no local dev environment; edit, commit, push.

## Structure

- Each page is a folder with `index.html` (clean URLs): root `/`, `/billetter/`, `/bli-medlem/`, `/om-inter-club-norvegia/`.
- Root `index.html` is the "Bli medlem" (join) page — embeds a Google Form iframe for signups.
- `/bli-medlem/index.html` is a meta-refresh redirect to `/` (join content lives at root).
- Assets use absolute paths (`/css/...`, `/bilder/...`, `/fonts/...`) — must be served from domain root, not opened via `file://`.
- `test/innmelding.html` = work-in-progress scratch page, not linked from nav.

## Conventions

- **Header, nav, and footer are duplicated verbatim in every page** — no templating/includes. When changing nav links, branding, or footer, apply the SAME edit to every `index.html`.
- Mark the current page in nav with `aria-current="page"` on its `<li><a>`; remove it from the others.
- The mobile menu toggle `<script>` is also copied into each page's `<body>` bottom — identical inline JS, keep in sync.
- Styling is a single stylesheet: `css/styles.css` (fonts + layout). It is the only CSS actually linked.
  - `css/style.min.css` and `css/style.min-social.css` are leftover WordPress artifacts — not referenced anywhere. Leave unless asked to clean up.
- Fonts (Inter, Cardo) are self-hosted `.woff2` in `/fonts`, declared via `@font-face` at the top of `styles.css`.

## Note on paths

Assets use absolute paths, so pages resolve correctly only when served from the domain root (as Cloudflare does) — not when opened via `file://`.
