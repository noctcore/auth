# Learn page template

How a Learn page is built, and how its diagram is drawn. The pilot pages are `learn/csrf.mdx`,
`learn/brute-force-and-lockout.mdx` and `learn/sessions-and-expiry.mdx`; copy from them.

## Page order

1. **In short** (`InShort.astro`), right under the frontmatter. Three slots, one sentence each:
   `threat` (what goes wrong), `rule` (what the package does about it), `where` (the module and its
   config key). No numbers that are not also in the body. `where` names at most two
   identifiers: the module, not every function in it.
2. **What goes wrong.** The attack, in prose. A page with no attack to show (a design choice, a
   concept) calls this section **The problem** and passes `first="The problem"` to `InShort`.
3. **The diagram**, directly after it. One per page; another only when a separate mechanism needs
   its own picture, placed under the `###` it explains (the brute force page has three: the budgets,
   the locks, the owner's device). A page whose point is a single value or a list (a table of
   defaults says it better) gets no diagram: a drawing must show something moving or being decided.
4. **The rule.** One lead sentence under the `##`, then one `###` per rule, so the right rail lists
   them. Inside: short paragraphs, a list where the text was a list in disguise, a Markdown table for defaults (budget, default, what it
   stops), an `<Aside type="caution">` for a trade-off the reader must not miss. Keep every fact,
   number, config key, link and attack id of the old page; change the wording only.
5. **In code.** A typechecked sample from `site/snippets/learn/`, imported with `?raw` and shown with
   `<Code>`. Two samples go in `<Tabs>` (the defaults written out, then the API in use).
6. **Where the package and the guide differ.**
7. **Attack tests.** A Markdown table inside `<div class="nc-attacks">` (blank lines around it):
   `| Test | Attack | Stopped by |`, one row per attack in `packages/auth/tests/attacks/ATTACKS.md`
   that names the page, the link text being the bare id. "Stopped by" is one code chip per file,
   `http/csrf.ts` in the core and `auth-trpc/middlewares.ts` in an adapter. On a phone the rows
   stack.
8. **Further reading**, then **Related** if the page had it.

### The body

- A table of 4 or more columns does not fit a phone. Split it into two tables by topic (the design
  choices page does), or wrap it in `<div class="nc-stack">` (blank lines around the table) so the
  rows stack under 40rem: the first cell names the row and every other cell has to read on its
  own, because the column names are hidden. Prefer the split when the columns need their headers.
- An `<Aside type="caution">` tints its inline code amber on its own; no class is needed.
- A paragraph or bullet runs at most about three lines at the content width. Longer, it becomes
  several short paragraphs, each led by a **bold phrase** that says the point.
- Cases with an outcome ("the test suite runs ...") are a two-column table, not prose.
- An attack id in prose links to its test, like the table does.

A page becomes `.mdx` when it uses a component. The file name is the only thing that changes: the
URL stays the same.

## Numbers are checked

Add the page to `PAGES` in `site/scripts/learn-numbers.test.ts` (or to the `PAGES` of the sibling
test for its topic: `learn-credentials`, `learn-requests` or `learn-accounts`) when you convert it.
Every digit on the page must then come from a fact phrase built from the package source, and the
page must link every attack test `ATTACKS.md` files under it, under the page's exact title. The
shared readers and checks are in `site/scripts/learn-checks.ts`. Diagram numbers are not typed into the diagram: the
diagram imports the code sample (`snippets/learn/*.ts`) and the test checks the sample against the
source. A constant the sample cannot hold (like the lock factor) is a named `const` in the diagram
that the test reads.

## Drawing a diagram

A diagram is an Astro component in `diagrams/` that renders a `DiagramFrame` with two `<svg>`
drawings: `nc-d nc-d--wide` (viewBox 680 wide, for the content column) and `nc-d nc-d--narrow`
(viewBox 360 wide, for phones). The frame shows the one that fits its own width. Both get
`aria-hidden="true"`; the frame carries `role="img"`, the `title` and a full `description` in
sentences, so a screen reader hears one account. The same description sits under the caption behind
**Text version**: SVG text does not grow with a text-only zoom, so the words must be on the page too.
Draw both at roughly 1:1 scale: the narrow drawing takes over below a 39rem plate and is capped
near its own size, so its text never renders far below its CSS size.

Put positions in a layout object per drawing and map over the data; do not copy the drawing twice by
hand. Lay out text with mono widths in mind (12px DM Mono is about 7.2px a character) and check the
result in headless screenshots at 1440 and 390, in both themes.

### The vocabulary

Use the classes in `src/styles/docs.css`, never a color value:

| Class                         | Use                                                                                                                                                                                                                                                                                                                                                                                                              |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `nc-d-tick`                   | A request along a route. Say so on the drawing ("each tick: a request").                                                                                                                                                                                                                                                                                                                                         |
| `nc-d-route`                  | The legitimate path: pale blue at night, brand blue by day.                                                                                                                                                                                                                                                                                                                                                      |
| `nc-d-node`, `nc-d-node-open` | Where a path starts (filled) and where it arrives (open ring).                                                                                                                                                                                                                                                                                                                                                   |
| `nc-d-attack-node`            | Where the attack starts (filled salmon dot).                                                                                                                                                                                                                                                                                                                                                                     |
| `nc-d-attack`                 | The attack: salmon, dashed `5 7`. Add `nc-d-attack--past` (fine, dotted, faint) for what happens only if the layer before missed it.                                                                                                                                                                                                                                                                             |
| `Stop.astro`                  | A mark across a path. `kind="refused"` (default): salmon bar and dot, the package turns a request away. `kind="end"`: ink bar, something ends on schedule (an expiry, a sign-out). `kind="stripped"`: ink bar and open ring, the request goes on minus what made it dangerous (the browser drops the cookie). It draws `nc-d-stop`, `nc-d-stop-dot`, `nc-d-end` and `nc-d-strip-ring`: never use those directly. |
| `nc-d-post`                   | A checkpoint line the request crosses. Where full-height posts would cut through text (a wide drawing with several lanes), give each lane its own short tick, as the wide password reset drawing does.                                                                                                                                                                                                           |
| `nc-d-rule`, `nc-d-leader`    | Dashed dividers and caps; dotted leaders from a note to what it names. A dashed `nc-d-rule` is too faint as a checkpoint line in dark mode: use the dotted `nc-d-leader` there.                                                                                                                                                                                                                                  |
| `nc-d-cell`, `nc-d-span`      | A counted attempt; a span of time (a lock), in ink. `nc-d-span--ghost` for an example span.                                                                                                                                                                                                                                                                                                                      |
| `nc-d-label`                  | A name on the drawing (Manrope, strong).                                                                                                                                                                                                                                                                                                                                                                         |
| `nc-d-code`                   | A config key or function name (DM Mono, accent).                                                                                                                                                                                                                                                                                                                                                                 |
| `nc-d-note`, `nc-d-value`     | An annotation (DM Mono, muted); a number that matters (DM Mono, strong).                                                                                                                                                                                                                                                                                                                                         |
| `nc-d-stop-text`              | Text about the stop itself (DM Mono, salmon).                                                                                                                                                                                                                                                                                                                                                                    |
| `nc-d-kicker`                 | One small uppercase header for a panel, like the brand art's "LOGIN / MODULE MAP".                                                                                                                                                                                                                                                                                                                               |

### Checking a drawing

Run the dev server (`bun run dev` in `site/`) and shoot each page headless at 1440 and 390 wide, in
both themes (set `localStorage['starlight-theme']` to `dark` or `light` before load). On each visible
`svg.nc-d`, compare the `getBBox()` of every `<text>`: no two may overlap, none may leave the
viewBox. Read the crops at full size; a label that touches a line counts as a collision. Never look
at the screen itself, only at images the headless browser writes.

### Style rules

- **Show the mechanism.** Every mark is something the code does: a budget, a check, a lock, an
  expiry. No decoration, no icons, no padlocks or shields.
- **Salmon means the package refuses something here**, nothing else: the attack line, its stop bar
  and the text about that refusal. An expiry, a sign-out or a lock's length is ink (`kind="end"`,
  `nc-d-span`), even when it ends a session, and so is a defence that disarms a request without
  refusing it (`kind="stripped"`). Blue is the legitimate path.
- **One mechanism per frame.** A frame shows one mechanism and sits under the `###` that explains
  it. The narrow drawing may run to about 700 units tall if each lane reads on its own within one
  phone screen (about 640 CSS px); past that, or with a second mechanism, split it.
- **Real text, real values.** Labels are `<text>`, never outlined paths; values come from the code
  sample, config keys are spelled as in the package.
- **Say "not to scale"** when a time axis is not.
- **A caption is the takeaway**, one or two sentences with the key phrase in `<strong>`. A reader
  who sees only the In short box, the drawing and the caption should get the page's point.
- **No motion.** The diagrams are static; the landing page is the only place that animates.
- No em or en dashes anywhere, in labels, descriptions or captions.

## Skeleton

```mdx
---
title: Topic
description: One sentence.
---

import { Code } from '@astrojs/starlight/components';
import InShort from '../../../components/docs/InShort.astro';
import TopicDiagram from '../../../components/docs/diagrams/TopicDiagram.astro';
import topicTs from '../../../../snippets/learn/topic.ts?raw';

<InShort>
  <Fragment slot="threat">What goes wrong, in one sentence.</Fragment>
  <Fragment slot="rule">What the package does about it.</Fragment>
  <Fragment slot="where">`module/file.ts`, configured under `key`.</Fragment>
</InShort>

## What goes wrong

<TopicDiagram />

## The rule

One lead sentence.

### First rule

## In code

<Code code={topicTs} lang="ts" title="topic.ts" />

## Where the package and the guide differ

## Attack tests

<div class="nc-attacks">

| Test | Attack | Stopped by |
| ---- | ------ | ---------- |

</div>

## Further reading
```

A new diagram starts from the smallest pilot, `diagrams/LockoutDevice.astro`: one `layouts` array
with a wide and a narrow entry, a `title`, a `description` that says everything the drawing does,
and a caption.

# Build guide template

How a Build guide is built. The pilot guides are `build/node-server.mdx` (short, the base every
other guide builds on) and `build/trpc.mdx` (long, with reference sections after the steps); copy
from them. A Build guide is the same family as a Learn page: an open summary band at the top, one
drawing in the blueprint plate, the same diagram vocabulary and the same body rules (see "The body"
above). It differs in what it answers: not "why does this rule exist" but "what do I wire, in which
order, and how do I know it works".

## Page order

1. **Guide summary** (`GuideSummary.astro`), right under the imports. Three slots, one sentence
   each: `build` (what the reader has at the end), `needs` (the guides it builds on, as links, and
   the services it needs by name: Postgres, Redis), `check` (what to run or observe, taken from
   "Check it works": never a promise the guide does not test).
2. **The intro** the guide already had: one or two short paragraphs, the "builds on" link among
   them.
3. **How the pieces fit**: the wiring diagram, alone under the `##`.
4. **Build it**: one lead sentence at most, then `<Steps>`. One step per file the reader writes,
   in the order they would write them. Each step is a `###` (the right rail lists them and other
   pages link to them), then its `<Code>` sample, then what the reader must know about that file.
   A step that offers an alternative to itself (the fetch adapter beside the Node one) puts it
   under a `####` inside the step and sets `tableOfContents: { maxHeadingLevel: 4 }`.
5. **Reference sections**, each a `##`, for what is not a build step: options and tiers, error
   mapping, schemas, a second framework. Keep the headings' wording when you move them out of a
   step, so their anchors stay the same.
6. **Before going live**, if the guide had it.
7. **Check it works**, last. What to run (the guide's test sample, or a short `sh` session against
   the server the guide builds) and a two-column table `| You observe | It shows |` or
   `| Test | Passes when |`, one row per outcome. Put the table before a long test sample, so the
   outcomes are read before the code; after a short `sh` session, the table follows it. Source it from tests that exist: the snippet's own
   test (`trpc/router.test.ts`) or the example app's (`examples/basic/tests/e2e.int.test.ts`). Name
   the command and the services it needs.

### Steps

- `<Steps>` wraps exactly one ordered list. Write each step as `1. ### Title`, and indent
  everything in the step (paragraphs, `<Code>`, lists, tables, asides) by three spaces, with a
  blank line between blocks.
- Every snippet the old page showed stays, in a step or a reference section. The `?raw` import and
  the `<Code>` line do not change, so `test:snippets` and the snippet typecheck keep covering it.
- On a phone (under 40rem) the rail is hidden and a step's content takes the full column; the
  number stays beside the heading. Nothing to do in the page.
- A first-column config key or call in a table inside a step stays on one line.

### Gotchas, comparisons and checks

- A trade-off the reader must not miss is an `<Aside type="caution">` with a short title that says
  the rule ("Run this Redis with noeviction", "Never verify on page load"). One per trap; the rest
  stays prose.
- A list whose items compare options (values of `TRUST_PROXY`, middlewares and what they refuse
  with, peer dependency floors) becomes a Markdown table. Keep the list beside it when its items
  carry more than the table can: the table is the overview, the list keeps every fact.
- Moving or rewording is fine; dropping is not. Every claim, config key, number, link and snippet
  of the old page survives, and anything you add (a refusal code in a table, a curl session) is
  checked against `packages/*/src` or the snippet code first.

## The wiring diagram

One per guide, `diagrams/<Topic>Wiring.astro` (prefixed by the guide's topic), in a `DiagramFrame`
with a `title`, a full `description` and a caption, a wide (680) and a narrow (360) drawing, like
every Learn diagram. It shows how the guide's pieces connect, read from the snippets, not a
generic architecture picture:

- **A lane for the request**, `nc-d-route`, through the calls the snippet makes in the order it
  makes them, each a `nc-d-post` with a filled node, the call above in `nc-d-code`, what it hands
  on below in `nc-d-note`. Where the package refuses, `nc-d-stop-text` names the refusal: a short
  `nc-d-attack` spur ending in a `Stop` when one step refuses (the node server's CSRF 403), or the
  public code under each post when every post can refuse (the tRPC chains, with a one-line legend
  saying so).
- **Boxes for what the guide wires in**, new in this template: `nc-d-box` for a module, store or
  service, `nc-d-box--key` (outlined in the path color) for the one the others hang from (the auth
  instance, the context). Inside: the name in `nc-d-label`, the call in `nc-d-code`, what it holds
  in `nc-d-note`.
- **Wires**, `nc-d-wire` (thin, solid, muted), for "holds" or "calls": a bus from the key box to
  the others. A dotted `nc-d-leader` joins a lane step to the box it calls.
- Kickers name the panel and the file it comes from (`ONE REQUEST, src/server.ts`).
- Values come from the sample: the tRPC drawing reads `freshAuth('5m')` out of `router.ts?raw`.
  Add the guide to `GUIDES` in `site/scripts/build-guides.test.ts`, with a describe block that
  checks the drawing's steps, order and codes against the sample and the package source, and lists
  the anchors other pages link to.
- Narrow drawings turn the lane vertical (labels to its right) and may run to about 750 units when
  the lanes each read on their own. Check the drawing as in "Checking a drawing" above.

## Skeleton

```mdx
---
title: Guide title
description: One sentence.
---

import { Aside, Code, Steps } from '@astrojs/starlight/components';
import GuideSummary from '../../../components/docs/GuideSummary.astro';
import TopicWiring from '../../../components/docs/diagrams/TopicWiring.astro';
import serverTs from '../../../../snippets/build/topic/server.ts?raw';
import appTestTs from '../../../../snippets/build/topic/app.test.ts?raw';

<GuideSummary>
  <Fragment slot="build">What the reader has at the end, in one sentence.</Fragment>
  <Fragment slot="needs">[A Node server](/auth/build/node-server/), and Redis.</Fragment>
  <Fragment slot="check">`app.test.ts` passes: what it proves, in one clause.</Fragment>
</GuideSummary>

The intro the guide had. This guide builds on [...](/auth/build/...).

## How the pieces fit

<TopicWiring />

## Build it

<Steps>

1. ### The server

   What this file does, in a sentence.

   <Code code={serverTs} lang="ts" title="src/server.ts" />

   - **A bold lead.** What the reader must know about it.

   <Aside type="caution" title="The rule, in a few words">
     The trade-off.
   </Aside>

2. ### The next file

</Steps>

## A reference section

## Check it works

What the test needs (services, a command), in a sentence.

| Test | Passes when |
| ---- | ----------- |

<Code code={appTestTs} lang="ts" title="src/app.test.ts" />
```
