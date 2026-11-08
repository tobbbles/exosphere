// Prepares the reference tree the spaces corpus is generated from.
//
// The corpus follows bluesky-social/atproto `atproto-spaces-cleanup` at
// 4037310 (which carries `atproto-spaces-lexicon-review` at 7089c42). That
// branch forked from `permissioned-data` at 99bf6e2, before STAR moved into
// its own `@atproto/star` package and gained its control byte (13994f1,
// bd58bd8), so its `packages/space` still carries the older in-package STAR
// codec. Neither upstream tip has both sets of changes, and a plain merge
// conflicts (in packages/space, packages/star, packages/repo and the PDS).
//
// This script resolves the one part of that conflict that reaches the corpus
// bytes the same way `permissioned-data` did: given a cleanup-branch tree with
// `packages/star` copied in from `permissioned-data` at 98ef3a6, it makes
// `packages/space` read and write STAR through `@atproto/star`, with the
// per-profile read limits 98ef3a6 introduced, and drops the in-package codec.
// Nothing else is touched.
//
// Usage (see SOURCE.md):
//
//   node graft-star.mjs --atproto /path/to/cleanup-tree-with-packages-star

import { parseArgs } from 'node:util'
import { resolve } from 'node:path'
import { readFile, writeFile, rm } from 'node:fs/promises'

const { values: args } = parseArgs({ options: { atproto: { type: 'string' } } })
if (!args.atproto) throw new Error('--atproto is required')
const space = resolve(args.atproto, 'packages/space')

const edit = async (rel, fn) => {
  const path = resolve(space, rel)
  const before = await readFile(path, 'utf8')
  const after = fn(before)
  if (after === before) throw new Error(`graft made no change to ${rel}`)
  await writeFile(path, after)
}

const replaceOnce = (s, from, to) => {
  if (s.split(from).length !== 2) throw new Error(`expected exactly one ${JSON.stringify(from)}`)
  return s.replace(from, to)
}

await rm(resolve(space, 'src/star.ts'))
await rm(resolve(space, 'src/star.test.ts'), { force: true })

const pkgPath = resolve(space, 'package.json')
const pkg = JSON.parse(await readFile(pkgPath, 'utf8'))
pkg.dependencies['@atproto/star'] = 'workspace:^'
pkg.dependencies = Object.fromEntries(Object.entries(pkg.dependencies).sort(([a], [b]) => a.localeCompare(b)))
await writeFile(pkgPath, JSON.stringify(pkg, null, 2) + '\n')

await edit('tsconfig.build.json', (s) =>
  replaceOnce(s, '"references": [', '"references": [\n    { "path": "../star/tsconfig.build.json" },'),
)

await edit('src/types.ts', (s) => {
  s = replaceOnce(
    s,
    "import { l } from '@atproto/lex-schema'\n",
    "import { l } from '@atproto/lex-schema'\nimport type { ReadStarOptions } from '@atproto/star'\n",
  )
  return (
    s +
    `
export const REPO_STAR_LIMITS: ReadStarOptions = {
  maxMetaLength: 64 * 1024, // 64 KiB
  maxKeyLength: 4 * 1024, // 4 KiB
  maxValueLength: MAX_RECORD_SIZE,
}

export const SPACE_META_STAR_LIMITS: ReadStarOptions = {
  maxMetaLength: 64 * 1024, // 64 KiB
  maxKeyLength: 4 * 1024, // 4 KiB
  maxValueLength: 1024 * 1024, // 1 MiB
}
`
  )
})

await edit('src/space-meta-archive.ts', (s) => {
  s = replaceOnce(s, "import { type StarPair, readStar, writeStar } from './star.js'\n", '')
  s = replaceOnce(
    s,
    'import {\n  type DidString,',
    "import { type StarPair, readStar, writeStar } from '@atproto/star'\nimport {\n  type DidString,",
  )
  s = replaceOnce(s, '  SPACE_META_STAR_TYPE,\n', '  SPACE_META_STAR_LIMITS,\n  SPACE_META_STAR_TYPE,\n')
  return replaceOnce(s, 'await readStar(star)', 'await readStar(star, SPACE_META_STAR_LIMITS)')
})

await edit('src/sync/provider.ts', (s) => replaceOnce(s, "from '../star.js'", "from '@atproto/star'"))

await edit('src/sync/consumer.ts', (s) => {
  s = replaceOnce(s, "from '../star.js'", "from '@atproto/star'")
  s = replaceOnce(s, '  MAX_RECORD_SIZE,\n', '  REPO_STAR_LIMITS,\n')
  return replaceOnce(s, 'readStar(star, { maxValueLength: MAX_RECORD_SIZE })', 'readStar(star, REPO_STAR_LIMITS)')
})

await edit('src/index.ts', (s) => s.replace(/export \{\n {2}STAR_MAGIC,[\s\S]*?\} from '\.\/star\.js'\n/, ''))

console.log('grafted @atproto/star into', space)
