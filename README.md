# Plug2Proxy - 插入代理

由流量出口服务器主动连接入口服务器实现代理的小工具。

## 特性

- 流量出口服务器无需暴露端口。
- 由流量出口服务器配置希望代理的请求，支持优先级。
- 支持浏览器请求 referer 嗅探匹配规则（需要信任本地生成的 Plug2Proxy CA）。

## 使用

```bash
p2p [config file]
```

> Plug2Proxy 使用 [cosmiconfig](https://github.com/cosmiconfig/cosmiconfig) 读取配置文件。

## 典型配置

### 流量入口

**p2p.config.js**

```js
export default {
  mode: 'in',
  alias: '🖥️',
  tunnel: {
    password: 'abc123',
  },
  proxy: {
    refererSniffing: {
      include: {
        browsers: ['Edge', 'Chrome', 'Safari'],
      },
      exclude: {
        hosts: ['*.reddit.com'],
      },
    },
  },
  ddns: {
    provider: 'alicloud',
    accessKeyId: '[access key id]',
    accessKeySecret: '[access key secret]',
    domain: 'example.com',
    // 使用泛域名解析避免缓存。
    record: '*.p2p',
  },
};
```

更多配置请参考 [src/library/in/config.ts](./src/library/in/config.ts)。

### 流量出口

**p2p.config.js**

```js
export default {
  mode: 'out',
  alias: '🌎',
  tunnels: [
    {
      // 字符 # 会在连接时被替换成随机字符串，配合泛域名使用。
      host: '#.p2p.example.com',
      password: 'abc123',
      rejectUnauthorized: false,
      match: {
        include: [
          {
            type: 'geoip',
            match: 'CN',
            negate: true,
          },
        ],
      },
      replicas: 3,
    },
  ],
};
```

更多配置请参考 [src/library/out/config.ts](./src/library/out/config.ts)。

## License

MIT License.
