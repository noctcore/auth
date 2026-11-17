// Refuses comparing secrets with anything but the constant-time helpers.
//
// `===`, `Buffer#equals`, `Object.is` and `localeCompare` stop at the first
// character that differs, so the time a comparison takes leaks how much of a
// guess was right. Library code compares hashes, tokens, codes, digests, MACs,
// signatures and secrets only through hexDigestsEqual or secretsEqual in
// crypto/hash.ts.
//
// The check goes by name: a value whose name ends in one of the secret words,
// as a variable, a property (`row.tokenHash`, `row?.tokenHash`,
// `rec['passwordHash']`) or the same wrapped in `as`, `satisfies` or `!`. A
// comparison with a literal, `undefined` or a `typeof` is a shape or presence
// check, not a comparison of two secrets, and is allowed. A secret held under
// an unrelated name is not caught: the rule narrows the ways to slip, it does
// not prove there are none.

const SECRET_NAME = /(?:hash|token|secret|digest|mac|code|sig|signature)$/iu;
const EQUALITY = new Set(['==', '===', '!=', '!==']);

const MESSAGE =
  'Do not compare a secret with ===, !==, equals, Object.is, localeCompare or Buffer.compare: use hexDigestsEqual or secretsEqual from crypto/hash.ts.';

/** Strips `?.` chains and TypeScript-only wrappers that do not change the value. */
function unwrap(node) {
  let current = node;

  while (
    current &&
    (current.type === 'ChainExpression' ||
      current.type === 'TSAsExpression' ||
      current.type === 'TSSatisfiesExpression' ||
      current.type === 'TSNonNullExpression' ||
      current.type === 'TSTypeAssertion')
  )
    current = current.expression;

  return current;
}

/** The name a value is read under: a variable, or the last property of a member access. */
function nameOf(node) {
  const value = unwrap(node);

  if (!value) return null;
  if (value.type === 'Identifier') return value.name;
  if (value.type !== 'MemberExpression') return null;
  if (!value.computed && value.property.type === 'Identifier') return value.property.name;
  if (
    value.computed &&
    value.property.type === 'Literal' &&
    typeof value.property.value === 'string'
  )
    return value.property.value;

  return null;
}

const isSecret = (node) => {
  const name = nameOf(node);

  return name !== null && SECRET_NAME.test(name);
};

/** A literal, `undefined` or a `typeof`/`!` expression: a shape or presence check. */
function isConstantSide(node) {
  const value = unwrap(node);

  return (
    value.type === 'Literal' ||
    (value.type === 'Identifier' && value.name === 'undefined') ||
    value.type === 'UnaryExpression' ||
    (value.type === 'TemplateLiteral' && value.expressions.length === 0)
  );
}

/** @type {import('eslint').Rule.RuleModule} */
const rule = {
  meta: {
    type: 'problem',
    docs: { description: 'Compare secrets only through the constant-time helpers.' },
    schema: [],
    messages: { secret: MESSAGE },
  },
  create(context) {
    const report = (node) => context.report({ node, messageId: 'secret' });

    return {
      BinaryExpression(node) {
        if (!EQUALITY.has(node.operator)) return;

        const left = isSecret(node.left) && !isConstantSide(node.right);
        const right = isSecret(node.right) && !isConstantSide(node.left);

        if (left || right) report(node);
      },
      CallExpression(node) {
        const callee = unwrap(node.callee);
        const args = node.arguments;

        if (callee.type === 'Identifier') {
          if (callee.name === 'timingSafeEqual') report(node);

          return;
        }

        if (callee.type !== 'MemberExpression' || callee.computed) return;

        const method = callee.property.type === 'Identifier' ? callee.property.name : '';
        const object = unwrap(callee.object);
        const objectName = object.type === 'Identifier' ? object.name : '';

        if (method === 'timingSafeEqual') return report(node);
        if (objectName === 'Buffer' && method === 'compare') return report(node);

        if (objectName === 'Object' && method === 'is') {
          if (args.some((arg) => isSecret(arg))) report(node);

          return;
        }

        if (method === 'equals' || method === 'localeCompare') {
          if (isSecret(callee.object) || args.some((arg) => isSecret(arg))) report(node);
        }
      },
    };
  },
};

export default rule;
