import type {RouteMatchOptions} from './router.js';

export type TunnelInOutHeaderData = {
  type: 'in-out-stream';
};

export type TunnelOutInHeaderData =
  | {
      type: 'tunnel';
      routeMatchOptions: RouteMatchOptions;
    }
  | {
      type: 'out-in-stream';
      id: string;
    };
