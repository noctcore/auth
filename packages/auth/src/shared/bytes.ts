/**
 * Whether a value is a byte array (a `Uint8Array` or a `Buffer`), including one
 * made in another realm (a `vm` context, some test environments), where
 * `instanceof Uint8Array` is false. `ArrayBuffer.isView` and the built-in tag
 * both work across realms; the tag tells a `Uint8Array` from a `DataView`, a
 * `Uint16Array` or a `Uint8ClampedArray`, and `isView` keeps a plain object
 * with a faked `Symbol.toStringTag` out.
 */
export function isBytes(value: unknown): value is Uint8Array {
  return (
    ArrayBuffer.isView(value) && Object.prototype.toString.call(value) === '[object Uint8Array]'
  );
}
