# homebrew-notafish

🐟 Official [Homebrew](https://brew.sh) tap for [**NotAFish**](https://github.com/realnishil/notafish) — a heuristic phishing URL checker that lives in your terminal.

## Installation

```bash
brew tap realnishil/notafish
brew install notafish
```

Or in one line:

```bash
brew install realnishil/notafish/notafish
```

## Usage

```bash
notafish https://paypa1-secure-login.tk/account/verify
```

See the [NotAFish README](https://github.com/realnishil/notafish) for full usage, scoring details, and CLI options.

## Updating

```bash
brew update
brew upgrade notafish
```

## Uninstalling

```bash
brew uninstall notafish
brew untap realnishil/notafish
```

## Formula

The formula lives in [`Formula/notafish.rb`](Formula/notafish.rb) in this repo. It tracks the latest tagged release of [realnishil/notafish](https://github.com/realnishil/notafish).

## Issues

Problems with the **formula/tap** (install failures, version bumps, etc.) → open an issue here.
Problems with **NotAFish itself** (false positives, missing heuristics, bugs) → open an issue on the [main repo](https://github.com/realnishil/notafish/issues).

## License

MIT — same as NotAFish.
