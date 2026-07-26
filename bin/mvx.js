#!/usr/bin/env node
import process from 'node:process';
import { runCli } from '../src/cli.js';

process.exitCode = await runCli(process.argv.slice(2));

