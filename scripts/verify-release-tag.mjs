import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const tag = process.argv[2] ?? process.env.GITHUB_REF_NAME;
if (!tag) throw new Error('Release tag is required as argv[2] or GITHUB_REF_NAME');
const pkg = JSON.parse(fs.readFileSync(path.resolve(import.meta.dirname, '..', 'package.json'), 'utf8'));
const expected = `v${pkg.version}`;
if (tag !== expected) throw new Error(`Release tag ${tag} does not match package version ${expected}`);
process.stdout.write(`${tag} matches package version ${pkg.version}\n`);
