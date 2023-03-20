# `koreader-syncd` - KOReader progress sync server

`koreader-syncd` is a [KOReader][koreader] progress sync server. The API is
compatible with upstream's [koreader-sync-server][koreader-sync-server], but
instead of Redis, `koreader-syncd` uses SQLite for persistence.
  
## Example

```bash
$ koreader-syncd -a 0.0.0.0:3000 -d /var/lib/koreader-syncd/state.db
```

## License

Licensed under [MIT license](LICENSE)

[koreader]: http://koreader.rocks/
[koreader-sync-server]: https://github.com/koreader/koreader-sync-server
