# NotAFish 🐟🚫

Heuristic phishing URL checker. CLI tool, zero dependencies, MIT licensed.

by [realnishil](https://github.com/realnishil)

## checks
- HTTP vs HTTPS
- raw IP host
- punycode / homograph
- known shorteners
- suspicious TLDs
- subdomain count
- `@` in URL
- brand typosquat (levenshtein)
- suspicious keywords
- URL length
- non-standard ports
- DNS resolution

## usage
```bash
python3 notafish.py "http://paypa1-secure-login.tk/verify@account"
python3 notafish.py -f urls.txt
python3 notafish.py <url> --no-resolve --no-color
```

## install
no deps. python3 stdlib only.
```bash
git clone https://github.com/realnishil/notafish.git
cd notafish
chmod 755 notafish.py
./notafish.py <url>
```

## license
MIT
