"""
Final Security Verification Script
Checks all security measures are properly implemented
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

print("=" * 70)
print("🔒 PENTEST TOOLKIT - SECURITY VERIFICATION")
print("=" * 70)
print()

issues = []
passed = []

# Check 1: .env exists
print("[1/7] Checking .env file...")
if Path('.env').exists():
    passed.append("✅ .env file exists")
else:
    issues.append("❌ .env file missing - copy from .env.example")
print()

# Check 2: .gitignore exists and contains sensitive files
print("[2/7] Checking .gitignore...")
if Path('.gitignore').exists():
    with open('.gitignore', 'r') as f:
        gitignore = f.read()
        if 'config.yaml' in gitignore and '.env' in gitignore:
            passed.append("✅ .gitignore protects config.yaml and .env")
        else:
            issues.append("❌ .gitignore missing config.yaml or .env")
else:
    issues.append("❌ .gitignore file missing")
print()

# Check 3: Environment variables loaded
print("[3/7] Checking environment variables...")
env_vars = ['SHODAN_API_KEY', 'FOFA_EMAIL', 'FOFA_API_KEY', 'URLSCAN_API_KEY']
loaded_vars = []
for var in env_vars:
    if os.getenv(var):
        loaded_vars.append(var)

if len(loaded_vars) >= 3:
    passed.append(f"✅ Environment variables loaded ({len(loaded_vars)}/{len(env_vars)})")
else:
    issues.append(f"⚠️  Only {len(loaded_vars)}/{len(env_vars)} environment variables loaded")
print()

# Check 4: config.yaml doesn't contain API keys
print("[4/7] Checking config.yaml security...")
if Path('config.yaml').exists():
    with open('config.yaml', 'r') as f:
        content = f.read()
        # Check for actual API keys (not comments)
        exposed_keys = []
        for line in content.split('\n'):
            if 'api_key:' in line and not line.strip().startswith('#'):
                if '"' in line and len(line.split('"')[1]) > 10:
                    exposed_keys.append(line.strip())
        
        if not exposed_keys:
            passed.append("✅ config.yaml contains no exposed API keys")
        else:
            issues.append(f"❌ config.yaml contains {len(exposed_keys)} exposed API keys")
else:
    issues.append("❌ config.yaml missing")
print()

# Check 5: No test files
print("[5/7] Checking for test files...")
test_files = list(Path('.').glob('test_*.py'))
if not test_files:
    passed.append("✅ No test files in root directory")
else:
    issues.append(f"⚠️  Found {len(test_files)} test files: {[f.name for f in test_files]}")
print()

# Check 6: No __pycache__
print("[6/7] Checking for cache directories...")
pycache_dirs = list(Path('.').rglob('__pycache__'))
if not pycache_dirs:
    passed.append("✅ No __pycache__ directories")
else:
    issues.append(f"⚠️  Found {len(pycache_dirs)} __pycache__ directories")
print()

# Check 7: Required modules exist
print("[7/7] Checking core modules...")
required_files = [
    'main.py',
    'api_server.py',
    'src/core/config.py',
    'src/core/utils.py',
    'src/modules/reconnaissance/free_recon.py'
]
missing = []
for file in required_files:
    if not Path(file).exists():
        missing.append(file)

if not missing:
    passed.append("✅ All core modules present")
else:
    issues.append(f"❌ Missing files: {missing}")
print()

# Print results
print("=" * 70)
print("RESULTS")
print("=" * 70)
print()

print("✅ PASSED CHECKS:")
for check in passed:
    print(f"   {check}")
print()

if issues:
    print("❌ ISSUES FOUND:")
    for issue in issues:
        print(f"   {issue}")
    print()

# Final verdict
print("=" * 70)
critical_issues = [i for i in issues if i.startswith("❌")]
warnings = [i for i in issues if i.startswith("⚠️")]

print(f"Critical Issues: {len(critical_issues)}")
print(f"Warnings: {len(warnings)}")
print(f"Passed Checks: {len(passed)}")
print()

if not critical_issues and not warnings:
    print("🎉 ALL SECURITY CHECKS PASSED!")
    print("Your toolkit is secure and ready to use.")
elif not critical_issues:
    print("✅ No critical issues, but review warnings above.")
else:
    print("⚠️  Please fix critical issues before using the toolkit.")

print("=" * 70)
