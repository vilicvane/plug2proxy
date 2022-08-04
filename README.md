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
plug2proxy in.p2p.js
```

配置文件 `in.p2p.js`，详见 [in/server.ts](./src/library/in/server.ts)、[in/proxy.ts](./src/library/in/proxy.ts)。

```js
module.exports = {
  mode: 'in',
  server: {
    password: '12345678',
  },
};
```

> 入口服务器（在入口等待出口客户端连接的服务器）默认监听 0.0.0.0:8443，本地代理服务器默认监听 127.0.0.1:8000。

更多选项：

```js
const FS = require('fs');

module.exports = {
  mode: 'in',
  // 参考 src/library/ddns/ddns.ts 中的 DDNSOptions
  ddns: {
    provider: 'alicloud',
    accessKeyId: '',
    accessKeySecret: '',
    domain: 'example.com',
    record: 'p2p',
  },
  // 参考 src/library/in/server.ts 中的 ServerOptions
  server: {
    host: '0.0.0.0',
    port: 8443,
    cert: FS.readFileSync('example.crt'),
    key: FS.readFileSync('example.key'),
    password: '12345678',
    session: {
      // 当会话最近满足激活条件的比例低于此值时，将被避免使用。
      qualityActivationOverride: 0.95,
      // 统计多长时间内的会话状态（毫秒）。
      qualityMeasurementDuration: 300_000,
    },
  },
  // 参考 src/library/in/proxy.ts 中的 ProxyOptions
  proxy: {
    host: '127.0.0.1',
    port: 8000,
    routing: {
      ipProbe: true,
    },
  },
};
```

### 出口

```sh
plug2proxy out.p2p.js
```

配置文件 `out.p2p.js`，详见 [router.ts](./src/library/router/router.ts)、[out/client.ts](./src/library/out/client.ts)。

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
    // MaxMind GeoLite2（Country）配置，用于 geoip 规则。
    geolite2: {
      // https://support.maxmind.com/hc/en-us/articles/4407111582235-Generate-a-License-Key
      licenseKey: '...',
    },
  },
  clients: [
    {
      // 入口服务器连接参数。
      authority: 'https://in-server:8443',
      password: '12345678',
      // 不检查连接安全性，搭配自签名证书使用。
      rejectUnauthorized: false,
    },
  ],
};
```

更多选项：

```js
module.exports = {
  mode: 'out',
  // 参考 src/library/router/router.ts 中的 RouterOptions
  router: {},
  clients: [
    // 参考 src/library/out/client.ts 中的 ClientOptions
    {
      label: '🌏',
      authority: 'https://in-server:8443',
      rejectUnauthorized: false,
      password: '12345678',
      candidates: 1,
      priority: 0,
      activationLatency: 200,
      deactivationLatency: 300,
    },
  ],
};
```
