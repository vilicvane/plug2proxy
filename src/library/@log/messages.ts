/* eslint-disable @typescript-eslint/explicit-function-return-type */

import bytes from 'bytes';
import ms from 'ms';

import {getErrorCode} from '../@utils/index.js';

// IN

// http proxy

export const IN_HTTP_PROXY_LISTENING_ON = (host: string, port: number) =>
  `listening on ${host}:${port}...`;

export const IN_CONNECT_NET = (host: string, port: number) =>
  `connect ${host}:${port} (net)`;

export const IN_CONNECT_TLS = (host: string, port: number) =>
  `connect ${host}:${port} (tls)`;

export const IN_OPTIMISTIC_CONNECT = 'optimistic connect...';

export const IN_CONNECT_SOCKET_CLOSED = 'connect socket closed.';

export const IN_ALPN_PROTOCOL_CANDIDATES = (protocols: string[]) =>
  `alpn protocol candidates: ${protocols.join(', ')}`;

export const IN_ALPN_KNOWN_PROTOCOL_SELECTION = (protocol: string | false) =>
  `alpn known protocol selection: ${protocol || 'none'}`;

export const IN_SWITCHING_RIGHT_SECURE_PROXY_SOCKET =
  'referer route is different from host route, switching right (to server) secure proxy socket...';

export const IN_CERTIFICATE_TRUSTED_STATUS_CHANGED =
  'certificate trusted status changed, reset connection.';

export const ALPN_PROTOCOL_CHANGED = 'alpn protocol changed, reset connection.';

export const IN_ERROR_CONNECT_SOCKET_ERROR = (error: unknown) =>
  `connect socket error: ${getErrorCode(error)}`;

export const IN_ERROR_LEFT_SECURE_PROXY_SOCKET_ERROR = (error: unknown) =>
  `left (from client) secure proxy socket error: ${getErrorCode(error)}`;

export const IN_ERROR_RIGHT_SECURE_PROXY_SOCKET_ERROR = (error: unknown) =>
  `right (to server) secure proxy socket error: ${getErrorCode(error)}`;

export const IN_ERROR_PIPING_CONNECT_SOCKET_FROM_TO_TUNNEL = (error: unknown) =>
  `error piping connect socket from/to tunnel: ${getErrorCode(error)}`;

export const IN_ERROR_SETTING_UP_LEFT_SECURE_PROXY_SOCKET =
  'error setting up left (from client) secure proxy socket.';

export const IN_ERROR_SETTING_UP_RIGHT_SECURE_PROXY_SOCKET =
  'error setting up right (to server) secure proxy socket.';

export const IN_ERROR_READING_REQUEST_HEADERS =
  'error reading request headers.';

export const IN_REQUEST_NET = (url: string) => `request ${url}`;

export const IN_ERROR_REQUEST_SOCKET_ERROR = (error: unknown) =>
  `request socket error: ${getErrorCode(error)}`;

export const IN_REQUEST_SOCKET_CLOSED = 'request socket closed.';

export const IN_ERROR_PIPING_REQUEST_SOCKET_FROM_TO_TUNNEL = (error: unknown) =>
  `error piping connect socket from/to tunnel: ${getErrorCode(error)}`;

export const IN_ERROR_TUNNEL_CONNECTING = (error: unknown) =>
  `error tunnel connecting: ${getErrorCode(error)}`;

export const IN_ERROR_ROUTING_CONNECTION = 'error routing connection.';

// tunnel server

export const IN_TUNNEL_SERVER_LISTENING_ON = (host: string, port: number) =>
  `listening on ${host}:${port}...`;

export const IN_TUNNEL_SERVER_TUNNELING = (
  host: string,
  port: number,
  remoteAddress: string,
) => `tunneling ${host}:${port} (via ${remoteAddress})...`;

export const IN_TUNNEL_CLOSED = 'tunnel closed.';

export const IN_TUNNEL_IN_OUT_STREAM_ESTABLISHED =
  'tunnel IN-OUT stream established.';

export const IN_TUNNEL_OUT_IN_STREAM_ESTABLISHED =
  'tunnel OUT-IN stream established.';

export const IN_TUNNEL_IN_OUT_STREAM_CLOSED = 'tunnel IN-OUT stream closed.';

export const IN_TUNNEL_OUT_IN_STREAM_CLOSED = 'tunnel OUT-IN stream closed.';

export const IN_TUNNEL_IN_OUT_STREAM_ERROR = (error: unknown) =>
  `tunnel IN-OUT stream error: ${getErrorCode(error)}`;

export const IN_TUNNEL_OUT_IN_STREAM_ERROR = (error: unknown) =>
  `tunnel OUT-IN stream error: ${getErrorCode(error)}`;

export const IN_TUNNEL_CONFIGURE_STREAM_ERROR = (error: unknown) =>
  `tunnel configure stream error: ${getErrorCode(error)}`;

export const IN_TUNNEL_CONFIGURE_UPDATE_STREAM_ERROR = (error: unknown) =>
  `tunnel configure (update) stream error: ${getErrorCode(error)}`;

export const IN_TUNNEL_ESTABLISHED = 'tunnel established.';

export const IN_TUNNEL_UPDATED = 'tunnel updated.';

export const IN_ROUTE_MATCH_OPTIONS = 'route match options:';

export const IN_TUNNEL_PASSWORD_MISMATCH = (remoteAddress: string) =>
  `tunnel password mismatch (from ${remoteAddress}).`;

export const IN_TUNNEL_WINDOW_SIZE_UPDATED = (windowSize: number) =>
  `tunnel window size updated: ${bytes(windowSize)}`;

// router

export const IN_ROUTER_FAILED_TO_RESOLVE_DOMAIN = (domain: string) =>
  `failed to resolve domain "${domain}".`;

// geolite2

export const IN_GEOLITE2_FAILED_TO_READ_DATABASE =
  'failed to read previously saved database.';

export const IN_GEOLITE2_DATABASE_UPDATED = 'database updated.';

export const IN_GEOLITE2_DATABASE_UPDATE_FAILED = 'database update failed.';

// ddns

export const IN_DDNS_PUBLIC_IP = (ip: string, provider: string) =>
  `public ip ${ip} (${provider}).`;

export const IN_DDNS_ERROR_CHECKING_AND_UPDATING = (error: unknown) =>
  `error checking and updating: ${getErrorCode(error)}`;

// OUT

// tunnel

export const OUT_CONNECTING = (authority: string) =>
  `connecting ${authority}...`;

export const OUT_TUNNEL_ESTABLISHED = 'tunnel established.';

export const OUT_TUNNEL_CLOSED = 'tunnel closed.';

export const OUT_TUNNEL_ERROR = (error: unknown) =>
  `tunnel error: ${getErrorCode(error)}`;

export const OUT_RECONNECT_IN = (delay: number) =>
  `reconnect in ${ms(delay)}...`;

export const OUT_ERROR_CONFIGURING_TUNNEL = (
  status: number | undefined,
  message: string | undefined,
) => `error configuring tunnel (status ${status}): ${message}`;

export const OUT_RECEIVED_IN_OUT_STREAM = (host: string, port: number) =>
  `received tunnel IN-OUT stream to ${host}:${port}.`;

export const OUT_TUNNEL_OUT_IN_STREAM_ESTABLISHED =
  'tunnel OUT-IN stream established.';

export const OUT_TUNNEL_STREAM_CLOSED = 'tunnel stream closed.';

export const OUT_ERROR_PIPING_TUNNEL_STREAM_FROM_TO_PROXY_STREAM = (
  error: unknown,
) => `error piping tunnel stream from/to proxy stream: ${getErrorCode(error)}`;

export const OUT_TUNNEL_WINDOW_SIZE_UPDATED = (windowSize: number) =>
  `tunnel window size updated: ${bytes(windowSize)}`;
