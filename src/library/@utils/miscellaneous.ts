export function getErrorCode(error: unknown): string {
  return error instanceof Error
    ? 'code' in error
      ? String(error.code)
      : error.name
    : String(error);
}

export function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export function disposable(dispose: () => void): Disposable {
  return {
    [Symbol.dispose]: dispose,
  };
}

export type Destroyable = {
  destroy(): void;
};

export function destroyable(object: Destroyable): Disposable {
  return {
    [Symbol.dispose]() {
      object.destroy();
    },
  };
}
