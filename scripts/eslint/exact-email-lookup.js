// The `no-restricted-syntax` selectors that keep every lookup by address on
// `core.findCredentialByEmail`.
//
// That method treats a row whose stored address is not exactly the one asked
// for as not found: a store behind a case- or accent-insensitive collation
// would otherwise reach one account under several spellings. Calling the
// store's own method skips that check, so outside the core any reach for
// `findCredentialByEmail` on another receiver is refused, however it is
// spelled: a member (`users.findCredentialByEmail`), a computed member with a
// string or template key (`users['findCredentialByEmail']`), or a destructured
// key (`const { findCredentialByEmail } = users`), on `core` too, since a
// detached method loses its receiver. A name built at runtime is not caught:
// the rule narrows the ways to slip, it does not prove there are none.

const NAME = 'findCredentialByEmail';
const NOT_CORE = ":not([object.name='core']):not([object.property.name='core'])";

const MESSAGE = 'Look users up by address with core.findCredentialByEmail (exact match only).';

const SELECTORS = [
  `MemberExpression[property.name='${NAME}']${NOT_CORE}`,
  `MemberExpression[computed=true][property.value='${NAME}']${NOT_CORE}`,
  `MemberExpression[computed=true][property.quasis.0.value.cooked='${NAME}']${NOT_CORE}`,
  `ObjectPattern > Property[key.name='${NAME}']`,
  `ObjectPattern > Property[key.value='${NAME}']`,
  `ObjectPattern > Property[key.quasis.0.value.cooked='${NAME}']`,
];

/** The options for `no-restricted-syntax`, one entry per spelling. */
export const exactEmailLookup = SELECTORS.map((selector) => ({ selector, message: MESSAGE }));
