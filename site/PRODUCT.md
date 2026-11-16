# Product: the @noctcore/auth docs site

register: brand

## What it is

The public docs for `@noctcore/auth`, an authentication library for TypeScript servers: sessions,
Argon2id passwords, hashed single-use tokens, throttling without permanent lockout, CSRF helpers and
the register, login, verification, reset and session flows, with Redis and Prisma stores. Every
module is tied to the attack it stops, and the docs exist to show that link.

The site has two jobs. The landing page presents the library and its one idea. Learn, Build and
Reference are long reading: they must be calm and readable before anything else.

## Users

- **Backend developers choosing an auth library.** They arrive from a search, a README or a
  recommendation, skeptical, with ten minutes. They want to know what the library does, what it
  refuses to do, and whether the claims are backed by code. They read the code sample before the
  copy.
- **Developers wiring it in.** They come back many times, in a hurry, for one config key, one guide
  step or one type. They need the sidebar, search and Reference to be fast and boring.
- **Reviewers and the curious.** People auditing a login flow, or learning why a rule exists. They
  read the Learn pages end to end, often at night, and follow links into the source.

## Brand

- **Voice words:** calm, exact, accountable.
- **Tone:** plain sentences, no hype, no fear. A rule is stated, then the attack that makes it
  necessary, then where it lives. The library is described by what it does and what it refuses,
  never by adjectives about itself.
- **Name:** noctcore is a night word. The brand may lean on night, ink and lamplight, quietly.
- **Copy rules:** first person singular where the author speaks (a solo project); no em or en
  dashes; no "blazing", "seamless", "enterprise-grade", "military-grade".

## Anti-references

- Generic SaaS landing pages: purple or blue gradients, gradient text, glass cards, three identical
  feature cards with rounded icons, a hero metric strip.
- Neon hacker aesthetics: green on black, glitch type, matrix rain, padlock and shield clip art,
  terminal costume.
- Fear marketing: red alert banners, breach counters, "your users are at risk".

## Strategic principles

1. **Readable first.** Learn pages are 500 to 1000 words of dense reasoning. Body type, line length
   and contrast serve that before any brand move.
2. **Show the link.** The landing page makes "every module is tied to the attack it stops" visible
   in one glance, with each pair linking to the page that argues it.
3. **Code is evidence.** Real, typechecked snippets, never pseudo code.
4. **Both themes are first class.** Light for daytime evaluation, dark for night reading; neither is
   a palette swap of the other.
5. **Quiet structure.** Hierarchy from type scale and spacing, not from boxes. Cards only where a
   card is the real affordance.
