/**
 * Password-lock gate for Vigil CLI.
 * On launch, if ~/.vigil/passwd exists, prompt for the password.
 * Passwords are stored as SHA-256 hex hashes.
 */
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

function vigilHome(): string {
  return process.env['VIGIL_HOME']?.trim() || join(homedir(), '.vigil');
}

function passwdFile(): string {
  return join(vigilHome(), 'passwd');
}

function hashPassword(password: string): string {
  return createHash('sha256').update(password).digest('hex');
}

async function promptPassword(): Promise<string> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  return new Promise<string>((resolve) => {
    // Use stderr so stdout output (piped/redirected) is not polluted
    process.stdout.write('\x1b[2J\x1b[H');
    process.stderr.write('┌──────────────────────────────────────────────────┐\n');
    process.stderr.write('│                                                  │\n');
    process.stderr.write('│   Vigil -- unrestricted security terminal agent   │\n');
    process.stderr.write('│   DeepSeek V4 Pro  |  1M context  |  9 tools     │\n');
    process.stderr.write('│                                                  │\n');
    process.stderr.write('├──────────────────────────────────────────────────┤\n');
    process.stderr.write('│                                                  │\n');
    process.stderr.write('│   Password Required                              │\n');
    process.stderr.write('│   Enter the Vigil unlock password to continue.    │\n');
    process.stderr.write('│                                                  │\n');
    process.stderr.write('├──────────────────────────────────────────────────┤\n');
    process.stderr.write('│                                                  │\n');
    process.stderr.write('│   Password:                                      │\n');
    process.stderr.write('│                                                  │\n');
    process.stderr.write('└──────────────────────────────────────────────────┘\n');
    process.stderr.write('\n> ');
    rl.question('', (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

export async function checkPasswordLock(): Promise<void> {
  const file = passwdFile();
  if (!existsSync(file)) return;

  const storedHash = readFileSync(file, 'utf-8').trim();
  if (!storedHash) return;

  let attempts = 3;
  while (attempts > 0) {
    const input = await promptPassword();
    if (hashPassword(input) === storedHash) {
      process.stdout.write('\x1b[2J\x1b[H');
      process.stderr.write('\n');
      return;
    }
    attempts--;
    if (attempts > 0) {
      process.stderr.write(`\n  Incorrect password -- ${attempts} attempt${attempts === 1 ? '' : 's'} remaining.\n\n`);
    }
  }
  process.stderr.write('\n  Access denied.\n');
  process.exit(1);
}
