"""
Pytest configuration for test suite
"""
import os
import tempfile
import shutil
import pytest
from hypothesis import settings, Verbosity
from hypothesis.database import DirectoryBasedExampleDatabase

# Use D drive for Hypothesis cache to save C drive space
# Falls back to system temp if D drive is not available
hypothesis_cache_dir = os.getenv('HYPOTHESIS_STORAGE_DIRECTORY', 'D:\\hypothesis_cache')
if not os.path.exists(os.path.dirname(hypothesis_cache_dir)) and hypothesis_cache_dir.startswith('D:'):
    # Fallback to system temp if D drive not available
    hypothesis_cache_dir = os.path.join(tempfile.gettempdir(), 'hypothesis_cache')
os.makedirs(hypothesis_cache_dir, exist_ok=True)
temp_dir = hypothesis_cache_dir

# Configure Hypothesis to use less disk space and temp directory
settings.register_profile(
    "ci", 
    max_examples=50, 
    verbosity=Verbosity.verbose,
    database=DirectoryBasedExampleDatabase(temp_dir)
)
settings.register_profile(
    "dev", 
    max_examples=20, 
    verbosity=Verbosity.normal,
    database=DirectoryBasedExampleDatabase(temp_dir)
)
settings.register_profile(
    "debug", 
    max_examples=10, 
    verbosity=Verbosity.verbose,
    database=DirectoryBasedExampleDatabase(temp_dir)
)

# Use dev profile by default (fewer examples = less disk usage)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))


@pytest.fixture(scope="session", autouse=True)
def cleanup_test_files():
    """Automatically cleanup test files after test session"""
    yield
    
    # Cleanup encrypted files after tests
    encrypted_dir = os.path.join(os.path.dirname(__file__), '..', 'encrypted_files')
    if os.path.exists(encrypted_dir):
        for file in os.listdir(encrypted_dir):
            file_path = os.path.join(encrypted_dir, file)
            if os.path.isfile(file_path):
                try:
                    os.remove(file_path)
                except:
                    pass
    
    # Cleanup hypothesis cache in project directory
    hypothesis_dir = os.path.join(os.path.dirname(__file__), '..', '.hypothesis')
    if os.path.exists(hypothesis_dir):
        try:
            shutil.rmtree(hypothesis_dir)
        except:
            pass
