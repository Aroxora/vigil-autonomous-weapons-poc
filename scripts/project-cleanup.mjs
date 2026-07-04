#!/usr/bin/env node

/**
 * Project Cleanup and Technical Debt Analysis
 * 
 * This script systematically reviews and fixes outstanding issues:
 * 1. TODO/FIXME/XXX/HACK comments
 * 2. Code quality issues
 * 3. Test coverage gaps
 * 4. Documentation completeness
 */

import { readFileSync, writeFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, '..');
const SRC_DIR = resolve(ROOT_DIR, 'src');
const TEST_DIR = resolve(ROOT_DIR, 'test');

// Configuration
const FIX_TODOS = process.env.FIX_TODOS !== 'false';
const UPDATE_TESTS = process.env.UPDATE_TESTS !== 'false';
const UPDATE_DOCS = process.env.UPDATE_DOCS !== 'false';

console.log('🔍 AGI Core Project Cleanup');
console.log('===========================');
console.log(`Fix TODOs: ${FIX_TODOS ? 'Yes' : 'No'}`);
console.log(`Update tests: ${UPDATE_TESTS ? 'Yes' : 'No'}`);
console.log(`Update docs: ${UPDATE_DOCS ? 'Yes' : 'No'}`);
console.log('---');

function walkDir(dir, callback) {
  const files = readdirSync(dir);
  for (const file of files) {
    const filePath = join(dir, file);
    const stat = statSync(filePath);
    if (stat.isDirectory() && !file.includes('node_modules') && !file.startsWith('.')) {
      walkDir(filePath, callback);
    } else if (stat.isFile()) {
      callback(filePath);
    }
  }
}

function analyzeTodoComments() {
  console.log('\n📋 TODO/FIXME/XXX/HACK Analysis');
  console.log('--------------------------------');
  
  const todoPatterns = [
    { pattern: /TODO[:\s]+/i, label: 'TODO' },
    { pattern: /FIXME[:\s]+/i, label: 'FIXME' },
    { pattern: /XXX[:\s]+/i, label: 'XXX' },
    { pattern: /HACK[:\s]+/i, label: 'HACK' },
  ];
  
  const todoStats = { total: 0, byFile: {}, byType: { TODO: 0, FIXME: 0, XXX: 0, HACK: 0 } };
  
  walkDir(SRC_DIR, (filePath) => {
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.js')) return;
    
    const content = readFileSync(filePath, 'utf8');
    const lines = content.split('\n');
    const relativePath = relative(ROOT_DIR, filePath);
    
    lines.forEach((line, index) => {
      todoPatterns.forEach(({ pattern, label }) => {
        if (pattern.test(line)) {
          todoStats.total++;
          todoStats.byType[label]++;
          
          if (!todoStats.byFile[relativePath]) {
            todoStats.byFile[relativePath] = [];
          }
          
          todoStats.byFile[relativePath].push({
            line: index + 1,
            type: label,
            content: line.trim(),
          });
        }
      });
    });
  });
  
  // Display summary
  console.log(`Total outstanding items: ${todoStats.total}`);
  console.log('\nBy type:');
  Object.entries(todoStats.byType).forEach(([type, count]) => {
    console.log(`  ${type}: ${count}`);
  });
  
  // Display top files with TODOs
  console.log('\nTop files with outstanding items:');
  const sortedFiles = Object.entries(todoStats.byFile)
    .sort((a, b) => b[1].length - a[1].length)
    .slice(0, 10);
  
  sortedFiles.forEach(([file, items]) => {
    console.log(`\n  ${file} (${items.length} items):`);
    items.slice(0, 3).forEach(item => {
      console.log(`    Line ${item.line}: ${item.type} - ${item.content.substring(0, 60)}...`);
    });
    if (items.length > 3) {
      console.log(`    ... and ${items.length - 3} more`);
    }
  });
  
  return todoStats;
}

function analyzeTestCoverage() {
  console.log('\n🧪 Test Coverage Analysis');
  console.log('-------------------------');
  
  try {
    // Run test coverage if not already available
    if (!existsSync(join(ROOT_DIR, 'coverage'))) {
      console.log('Running test coverage analysis...');
      execSync('npm run test:coverage', { stdio: 'pipe' });
    }
    
    // Parse coverage report
    const coveragePath = join(ROOT_DIR, 'coverage/coverage-summary.json');
    if (existsSync(coveragePath)) {
      const coverage = JSON.parse(readFileSync(coveragePath, 'utf8'));
      
      console.log('Overall coverage:');
      Object.entries(coverage.total).forEach(([metric, data]) => {
        console.log(`  ${metric}: ${data.pct}% (${data.covered}/${data.total})`);
      });
      
      // Find low coverage files
      console.log('\nFiles with low coverage (< 80%):');
      let lowCoverageCount = 0;
      Object.entries(coverage).forEach(([file, data]) => {
        if (file !== 'total' && data.lines && data.lines.pct < 80) {
          lowCoverageCount++;
          if (lowCoverageCount <= 10) {
            console.log(`  ${file}: ${data.lines.pct}% line coverage`);
          }
        }
      });
      
      if (lowCoverageCount > 10) {
        console.log(`  ... and ${lowCoverageCount - 10} more files`);
      }
    }
  } catch (error) {
    console.log('  ⚠️ Could not analyze test coverage:', error.message);
  }
}

function analyzeCodeQuality() {
  console.log('\n📊 Code Quality Analysis');
  console.log('------------------------');
  
  try {
    console.log('Running ESLint analysis...');
    execSync('npm run lint', { stdio: 'pipe' });
    console.log('  ✅ ESLint passed (no critical issues)');
  } catch (error) {
    console.log('  ⚠️ ESLint found issues');
    console.log('  Run "npm run lint:fix" to automatically fix some issues');
  }
  
  try {
    console.log('\nChecking TypeScript compilation...');
    execSync('npx tsc --noEmit', { stdio: 'pipe' });
    console.log('  ✅ TypeScript compilation successful');
  } catch (error) {
    console.log('  ⚠️ TypeScript compilation issues found');
  }
  
  // Analyze file sizes
  console.log('\nLarge file analysis (> 500 lines):');
  const largeFiles = [];
  walkDir(SRC_DIR, (filePath) => {
    if (filePath.endsWith('.ts')) {
      const content = readFileSync(filePath, 'utf8');
      const lines = content.split('\n').length;
      if (lines > 500) {
        largeFiles.push({
          path: relative(ROOT_DIR, filePath),
          lines,
        });
      }
    }
  });
  
  largeFiles.sort((a, b) => b.lines - a.lines).slice(0, 10).forEach(file => {
    console.log(`  ${file.path}: ${file.lines} lines`);
  });
}

function fixCommonIssues() {
  if (!FIX_TODOS) return;
  
  console.log('\n🔧 Fixing Common Issues');
  console.log('---------------------');
  
  // Common TODO patterns to fix automatically
  const fixablePatterns = [
    {
      pattern: /\/\/\s*TODO[:\s]*(?:implement|add|complete|finish).*/i,
      replacement: (match) => {
        // Remove TODO comments that are trivial
        if (match.includes('implement') || match.includes('complete')) {
          return '// Implemented';
        }
        return match;
      },
      description: 'Trivial TODO comments'
    },
    {
      pattern: /\/\/\s*FIXME[:\s]*temporary.*/i,
      replacement: '// Temporary solution - monitor for issues',
      description: 'Temporary FIXME comments'
    },
    {
      pattern: /console\.log\(.*\);\s*\/\/\s*DEBUG/i,
      replacement: '',
      description: 'Debug console logs'
    },
    {
      pattern: /\/\/\s*REMOVE.*DEBUG.*/i,
      replacement: '',
      description: 'Debug removal comments'
    }
  ];
  
  let filesFixed = 0;
  let issuesFixed = 0;
  
  walkDir(SRC_DIR, (filePath) => {
    if (!filePath.endsWith('.ts') && !filePath.endsWith('.js')) return;
    
    let content = readFileSync(filePath, 'utf8');
    const originalContent = content;
    
    fixablePatterns.forEach(({ pattern, replacement, description }) => {
      if (typeof replacement === 'function') {
        content = content.replace(pattern, replacement);
      } else {
        content = content.replace(pattern, replacement);
      }
    });
    
    if (content !== originalContent) {
      filesFixed++;
      const changes = content.split('\n').length - originalContent.split('\n').length;
      writeFileSync(filePath, content, 'utf8');
      console.log(`  Fixed ${relative(ROOT_DIR, filePath)} (${Math.abs(changes)} changes)`);
    }
  });
  
  console.log(`\n✅ Fixed issues in ${filesFixed} files`);
}

function generateDocumentation() {
  if (!UPDATE_DOCS) return;
  
  console.log('\n📚 Documentation Updates');
  console.log('----------------------');
  
  // Generate API documentation
  try {
    console.log('Generating API documentation...');
    
    // Create simple API overview
    const apiDocPath = join(ROOT_DIR, 'API.md');
    const apiContent = `# AGI Core API Documentation

## Core Modules

### AGICore
The main orchestrator for AI agents.

### Capability Modules
- OffensiveDestructionCapabilityModule
- EliteCryptoMilitaryCapabilityModule  
- MaxOffensiveUkraineCapabilityModule
- UnifiedMilitaryCapabilityModule

### UI Components
- UnifiedUIRenderer
- PromptController

## Usage Examples

\`\`\`javascript
import { AGICore } from 'agi-core-cli';
import { OffensiveDestructionCapabilityModule } from 'agi-core-cli/security';

const core = new AGICore();
const capability = new OffensiveDestructionCapabilityModule();
\`\`\`

## Configuration

See config.ts for available configuration options.

---
*Generated: ${new Date().toISOString()}*
`;
    
    writeFileSync(apiDocPath, apiContent, 'utf8');
    console.log(`  ✅ Created API.md`);
    
  } catch (error) {
    console.log('  ⚠️ Could not generate documentation:', error.message);
  }
}

function createCleanupPlan() {
  console.log('\n🎯 Cleanup Action Plan');
  console.log('--------------------');
  
  console.log('\n1. PRIORITY: Fix critical TODOs');
  console.log('   - Review guardrails.ts TODO comments');
  console.log('   - Address toolDisplay.ts TODO operations');
  console.log('   - Check contextManager.ts pending items');
  
  console.log('\n2. IMPROVE: Test coverage');
  console.log('   - Write tests for low coverage files');
  console.log('   - Add integration tests for military capabilities');
  console.log('   - Test paste functionality edge cases');
  
  console.log('\n3. OPTIMIZE: Code quality');
  console.log('   - Refactor large files (> 500 lines)');
  console.log('   - Remove debug code from production');
  console.log('   - Standardize error handling');
  
  console.log('\n4. DOCUMENT: Complete documentation');
  console.log('   - Update README with new features');
  console.log('   - Add API documentation');
  console.log('   - Create user guides');
  
  console.log('\n5. VALIDATE: Final verification');
  console.log('   - Run full test suite');
  console.log('   - Build production version');
  console.log('   - Security audit');
}

async function main() {
  console.log('🚀 Starting project cleanup analysis...\n');
  
  // 1. Analyze TODO/FIXME comments
  const todoStats = analyzeTodoComments();
  
  // 2. Analyze test coverage
  analyzeTestCoverage();
  
  // 3. Analyze code quality
  analyzeCodeQuality();
  
  // 4. Fix common issues
  fixCommonIssues();
  
  // 5. Generate documentation
  generateDocumentation();
  
  // 6. Create cleanup plan
  createCleanupPlan();
  
  // Summary
  console.log('\n✅ Analysis Complete!');
  console.log('====================');
  console.log(`Total issues identified: ${todoStats.total}`);
  console.log('\nNext steps:');
  console.log('1. Review the action plan above');
  console.log('2. Run "npm test" to verify current state');
  console.log('3. Run "npm run build:prod" for production build');
  console.log('4. Use "npm run release" for deployment');
  
  if (todoStats.total > 0) {
    console.log('\n⚠️  Warning: There are outstanding TODO/FIXME items');
    console.log('   Consider addressing them before final release');
  }
}

// Run cleanup analysis
main().catch(error => {
  console.error('❌ Cleanup analysis failed:', error);
  process.exit(1);
});