<!-- SPDX-FileCopyrightText: 2023 Sayantan Santra <sayantan.santra689@gmail.com> -->
<!-- SPDX-License-Identifier: MIT -->

[![github-tests-badge](https://github.com/vmlrodrigues/curta-url/actions/workflows/rust-tests.yml/badge.svg)](https://github.com/vmlrodrigues/curta-url/actions/workflows/rust-tests.yml)
[![maintainer-badge](https://img.shields.io/badge/maintainer-vmlrodrigues-blue)](https://github.com/vmlrodrigues)
[![latest-release-badge](https://img.shields.io/github/v/release/vmlrodrigues/curta-url?label=latest%20release)](https://github.com/vmlrodrigues/curta-url/releases/latest)
[![license-badge](https://img.shields.io/github/license/vmlrodrigues/curta-url)](https://spdx.org/licenses/MIT.html)

# ![Logo](resources/assets/favicon-curta-32.png) <span style="font-size:42px">CurtaURL</span>

# What is it?

A simple self-hosted URL shortener with no unnecessary features. Simplicity
and speed are the main focuses of this project. The scratch Docker image is under 6 MB (compressed),
the Alpine image is under 10 MB (compressed), and typical RAM usage stays under 15 MB.

This fork exists to support a slightly different default behaviour: when the same
long URL is submitted again, CurtaURL returns the existing short link. This keeps
links stable for repeat submissions while still allowing explicit custom slugs
for context-specific links.

I actively use CurtaURL in production at [https://shrtn.fyi](https://shrtn.fyi),
so expect ongoing changes and improvements as real-world needs evolve.
Thanks to [Sayantan Santra](https://github.com/SinTan1729) for the original Chhoto URL and the inspiration for this fork.

## But why another URL shortener?

The original author of Chhoto URL wrote that many shorteners are either bloated or painful to set up,
and that very few are built with simplicity and lightness in mind. After looking at `simply-shorten`
(linked below), they liked the idea but found it missing a few essentials and disliked the large image
size caused by the Java runtime. They rewrote it in Rust and added features they considered essential,
such as hit counting. CurtaURL inherits that same design intent.

## What does the name mean?

Curta is Portuguese for short. URL means, well... URL. So the name simply means short URL.

# Demo

Link: [https://shrtn.fyi](https://shrtn.fyi)

#### Note:

- This is a live instance. Please avoid sensitive data, and expect occasional changes.
- If you host a public instance of CurtaURL, please let me know, and I'll add it to the README.

# Features

- Shortens URLs of any length to a randomly generated link.
- Automatic expiry of links after a chosen time.
- (Optional) Allows you to specify the shortened URL instead of the generated
  one. (It's missing in a surprising number of alternatives.)
- Opening the shortened URL in your browser will instantly redirect you
  to the correct long URL. (So no stupid redirection pages.)
- Super lightweight and snappy. (The Docker image is only ~6MB and RAM usage
  stays under 5MB under normal use.)
- Counts number of hits for each short link in a privacy-respecting way,
  i.e. only the hit is recorded, and nothing else.
- Short links can be edited after creation.
- QR codes can be generated for easy sharing.
- Reuses an existing short link when the same long URL is submitted again.
- Supports operation using API keys, including managed keys you can create, list, and revoke.
- Has a mobile-friendly UI, and automatic dark mode.
- Can serve a custom landing page, if needed.
- Has a public mode, where anyone can add links without authentication. Deleting
  or listing available links will need admin access using the password. It's also
  possible to completely disable the front end. It's also possible to force an expiry
  time for public instances, which might be useful.
- Allows setting the URL of your website, in case you want to conveniently
  generate short links locally.
- Links are stored in an SQLite database, which is configured to be ACID by default.
  Options are available for tuning the database to the user's liking.
- Available as a Docker container with a provided compose file.
- Backend written in Rust using [Actix Web](https://actix.rs/), and front end
  written in plain HTML and vanilla JS, using [Pure CSS](https://purecss.io/)
  for styling.
- Uses very basic authentication using a provided password. It's not encrypted in transport.
  A reverse proxy such as [caddy](https://caddyserver.com/) is recommended to
  encrypt the connection with SSL.

# Bloat that will not be implemented

- **Tracking or spying of any kind.** The only logs that still exist are
  errors printed to stderr and some basic logging of configuration.
- **User management.** If you need a shortener for your whole organization, either
  run separate containers for everyone or use something else.
- **Cookies, newsletters**, "we value your privacy" popups or any of the multiple
  other ways the modern web shows how anti-user it is. We all hate those, and they're
  not needed here.
- **Paywalls** or messages begging for donations.

# Screenshots

<p align="middle">
  <img src="screenshot-desktop.webp" height="250" alt="desktop screenshot" />
</p>

# Installation and configuration

[See here.](./INSTALLATION.md)

# Local test run

Quick way to validate changes locally using the dev image:

```bash
docker pull ghcr.io/vmlrodrigues/curta-url:dev
docker run -p 4567:4567 -e password=TestPass ghcr.io/vmlrodrigues/curta-url:dev
```

Open `http://localhost:4567`, create a short link, and verify features such as QR code generation.

# Instructions for CLI usage

[See here.](./CLI.md) (includes the in-repo `curtaurl-admin` helper for managed API keys).

# Related software

[See here.](./TOOLS.md)

# Notes

- CurtaURL is a fork of [Chhoto URL](https://github.com/SinTan1729/chhoto-url).
- It started as a fork of [`simply-shorten`](https://gitlab.com/draganczukp/simply-shorten).
- The list of adjectives and names used for random short URL generation is a modified
  version of [this list used by Docker](https://github.com/moby/moby/blob/master/pkg/namesgenerator/names-generator.go).
- It is highly recommended that you [enable WAL mode](./INSTALLATION.md/#use_wal_mode-).
- Although it's unlikely, it's possible that your database is mangled after some update. For mission critical use cases,
  it's recommended to keep regular versioned backups of the database, and sticking to a minor release tag e.g. 5.8.
- If you intend to have more than a few thousand short links, it's strongly recommended that you use the UID `slug_style`
  with a `slug_length` of 16 or more. Otherwise, generating new links will start to fail after a while.
