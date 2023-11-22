# plug2proxy

Just another awesome magic.

```js
export default {
  mode: 'in',
  tunnel: {
    authority: 'https://example.com',
    password: '',
  },
  proxy: {
    host: 'any',
    port: 8000,
  },
};
```

```js
export default {
  mode: 'out',
  match: {
    include: [
      {
        type: 'domain',
        match: ['*.twitter.com'],
      },
    ],
    exclude: [
      {
        type: 'geoip',
        match: 'CN',
      },
    ],
  },
  tunnel: {
    host: 'any',
    port: 8443,
    password: '',
  },
};
```

```js
export default 'https://gist.github.com/vilicvane/xxx';
```

## HTTP2

```mermaid
sequenceDiagram
  browser ->> in: CONNECT example.com:443 (proxy)
  in ->> +out: detect ALPN protocols (h2, http/1.1)
  out ->> -in: ALPN protocols: h2
  browser ->> in: TLS ALPN (proxy)

```

## License

MIT License.
