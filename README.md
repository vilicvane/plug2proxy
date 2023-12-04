# plug2proxy

Just another awesome magic.

```js
export default {
  mode: 'in',
  tunnel: {
    host: 'any',
    port: 8443,
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
    authority: 'https://example.com',
    password: '',
  },
};
```

```js
export default 'https://gist.github.com/vilicvane/xxx';
```

## Connections

- request/connect socket - proxy socket
- request/connect socket - tunnel stream (IN-OUT/OUT-IN stream) - proxy socket

## License

MIT License.
