# Disk Space Management

## Problem: Tests Filling Up Disk Space

This project uses **property-based testing** with Hypothesis, which can generate thousands of test cases. Each test may create:
- Temporary files in `uploads/` and `encrypted_files/`
- Database entries in SQLite
- MongoDB documents
- Cache files (.hypothesis, .pytest_cache, __pycache__)

**With 39 property tests × 100 examples each = 3,900+ test executions!**

This can quickly fill up your disk space, especially drive C: on Windows.

## Solutions

### 1. Use Development Profi