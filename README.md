# 插入代理 Plug2Proxy

> 注意！这玩意儿不适合普通科学上网场景。

由出口服务器主动连接入口服务器实现流量代理的小工具，需要出口服务器能直连入口服务器。

## 特性

- 出口服务器无需暴露端口。
- 出口服务器挂了不需要修改入口服务器配置。

我主要是打算用于零散的服务器下载加速，因为长时间不上，很可能上面的科学上网配置已经失效了。

## 用例

> 需安装 Node.js 较新版本，我用的 16。可使用 pm2 启动。

```sh
npm install --global plug2proxy
```

### 入口

```sh
plug2proxy out.p2p.js
```

配置文件 `in.p2p.js`，详见 [in/server.ts](./packages/plug2proxy/src/library/in/server.ts)、[in/proxy.ts](./packages/plug2proxy/src/library/in/proxy.ts)。

```js
const FS = require('fs');

module.exports = {
  mode: 'in',
  server: {
    password: '12345678',
    listen: {
      // 这是给代理出口连的端口。
      port: 8001,
    },
    http2: {
      // 可使用 acme.sh 等工具生成。
      cert: FS.readFileSync('server.crt'),
      key: FS.readFileSync('server.key'),
    },
  },
  proxy: {
    listen: {
      // 这是给终端连的。
      host: '127.0.0.1',
      port: 8000,
    },
  },
};
```

### 出口

```sh
plug2proxy out.p2p.js
```

配置文件 `out.p2p.js`，详见 [router.ts](./packages/plug2proxy/src/library/router/router.ts)、[out/client.ts](./packages/plug2proxy/src/library/out/client.ts)。

```js
module.exports = {
  mode: 'out',
  router: {
    rules: [
      {
        type: 'geoip',
        match: 'CN',
        route: 'direct',
      },
      {
        type: 'ip',
        match: 'private',
        route: 'direct',
      },
    ],
    fallback: 'proxy',
    // MaxMind 数据库。
    geoIPDatabase: 'geoip.mmdb',
  },
  clients: [
    {
      password: '12345678',
      connect: {
        // 入口服务器连接参数。
        authority: 'https://localhost:8001',
      },
    },
  ],
};
```

## 路线图

- P2P 连接。

## 授权协议

MIT 协议
