#!/usr/bin/env python3
"""
Performance Testing Suite
Tests encryption performance, load testing, and system benchmarks
"""

import time
import os
import sys
import statistics
import psutil
import threading
import concurrent.futures
from datetime import datetime
from tests import create_test_app, create_test_users, create_test_files, TestConfig

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class PerformanceTester:
    """Main performance testing class"""
    
    def __init__(self):
        self.results = {}
        
    def generate_test_data(self, size_mb):
        """Generate test data of specified size in MB"""
        return os.urandom(int(size_mb * 1024 * 1024))
    
    def measure_encryption_performance(self):
        """Comprehensive encryption performance testing"""
        print("Testing Encryption Performance...")
        print("-" * 50)
        
        try:
            from app.crypto_utils import CryptoEngine
            engine = CryptoEngine()
        except ImportError as e:
            print(f"❌ Cannot import CryptoEngine: {e}")
            return {}
        
        test_sizes = [0.1, 0.5, 1, 5]  # MB - reduced for faster testing
        algorithms = ['AES-256', 'DES', 'RC4']
        results = {}
        
        for algorithm in algorithms:
            print(f"\nTesting {algorithm}...")
            results[algorithm] = {}
            
            for size in test_sizes:
                print(f"  Testing {size}MB file...", end=" ")
                
                # Generate test data
                test_data = self.generate_test_data(size)
                
                # Run multiple iterations for accuracy
                encryption_times = []
                decryption_times = []
                memory_usage = []
                
                for run in range(3):  # Reduced iterations for speed
                    # Monitor memory before operation
                    process = psutil.Process()
                    initial_memory = process.memory_info().rss / 1024 / 1024  # MB
                    
                    try:
                        # Perform encryption based on algorithm
                        if algorithm == 'AES-256':
                            start_time = time.perf_counter()
                            encrypted_data, key, iv, _ = engine.encrypt_aes(test_data)
                            encryption_time = time.perf_counter() - start_time
                            
                            start_time = time.perf_counter()
                            decrypted_data, _ = engine.decrypt_aes(encrypted_data, key, iv)
                            decryption_time = time.perf_counter() - start_time
                            
                        elif algorithm == 'DES':
                            start_time = time.perf_counter()
                            encrypted_data, key, iv, _ = engine.encrypt_des(test_data)
                            encryption_time = time.perf_counter() - start_time
                            
                            start_time = time.perf_counter()
                            decrypted_data, _ = engine.decrypt_des(encrypted_data, key, iv)
                            decryption_time = time.perf_counter() - start_time
                            
                        elif algorithm == 'RC4':
                            start_time = time.perf_counter()
                            encrypted_data, key, _, _ = engine.encrypt_rc4(test_data)
                            encryption_time = time.perf_counter() - start_time
                            
                            start_time = time.perf_counter()
                            decrypted_data, _ = engine.decrypt_rc4(encrypted_data, key)
                            decryption_time = time.perf_counter() - start_time
                        
                        # Monitor memory after operation
                        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
                        memory_used = peak_memory - initial_memory
                        
                        encryption_times.append(encryption_time)
                        decryption_times.append(decryption_time)
                        memory_usage.append(memory_used)
                        
                        # Verify correctness
                        assert decrypted_data == test_data, f"Data corruption in {algorithm}"
                        
                    except Exception as e:
                        print(f"ERROR: {e}")
                        continue
                
                if encryption_times and decryption_times:
                    # Calculate statistics
                    avg_encryption = statistics.mean(encryption_times)
                    avg_decryption = statistics.mean(decryption_times)
                    avg_memory = statistics.mean(memory_usage)
                    
                    # Calculate throughput (MB/s)
                    throughput_enc = (size / avg_encryption) if avg_encryption > 0 else 0
                    throughput_dec = (size / avg_decryption) if avg_decryption > 0 else 0
                    
                    results[algorithm][f"{size}MB"] = {
                        'encryption_time_ms': avg_encryption * 1000,
                        'decryption_time_ms': avg_decryption * 1000,
                        'encryption_throughput_mbps': throughput_enc,
                        'decryption_throughput_mbps': throughput_dec,
                        'memory_usage_mb': avg_memory,
                        'total_time_ms': (avg_encryption + avg_decryption) * 1000
                    }
                    
                    # Check against performance benchmarks
                    expected_limit = TestConfig.ENCRYPTION_TIME_LIMITS.get(algorithm, {}).get(f"{int(size)}MB", float('inf'))
                    actual_time = avg_encryption * 1000
                    
                    if actual_time <= expected_limit:
                        print("✅ PASS")
                    else:
                        print(f"❌ FAIL ({actual_time:.1f}ms > {expected_limit}ms)")
                else:
                    print("❌ FAILED - No valid measurements")
        
        return results
    
    def test_database_performance(self):
        """Test database query performance"""
        print("\nTesting Database Performance...")
        print("-" * 50)
        
        try:
            app, db = create_test_app()
            
            with app.app_context():
                db.create_all()
                users = create_test_users(app, db)
                
                from app.models import User, EncryptedFile
                
                # Create some test files in database
                for i in range(10):
                    file_record = EncryptedFile(
                        file_id=f"test-file-{i}",
                        filename=f"test_file_{i}.txt",
                        original_filename=f"test_file_{i}.txt",
                        file_type="text/plain",
                        file_size=1024,
                        encrypted_path=f"/encrypted/test_file_{i}.enc",
                        algorithm="AES-256",
                        encryption_key=os.urandom(32),
                        iv=os.urandom(16),
                        user_id=users[0].id
                    )
                    db.session.add(file_record)
                
                db.session.commit()
                
                # Test query performance
                query_results = {}
                
                # Test 1: User lookup by username
                start_time = time.perf_counter()
                for _ in range(100):  # Run 100 times
                    user = User.query.filter_by(username='testuser1').first()
                end_time = time.perf_counter()
                
                avg_lookup_time = (end_time - start_time) / 100 * 1000  # ms
                query_results['user_lookup_ms'] = avg_lookup_time
                
                # Test 2: File listing for user
                start_time = time.perf_counter()
                for _ in range(100):
                    files = EncryptedFile.query.filter_by(user_id=users[0].id).all()
                end_time = time.perf_counter()
                
                avg_files_time = (end_time - start_time) / 100 * 1000  # ms
                query_results['user_files_lookup_ms'] = avg_files_time
                
                print(f"User lookup time: {avg_lookup_time:.2f}ms")
                print(f"User files lookup time: {avg_files_time:.2f}ms")
                
                # Check against benchmarks
                if avg_lookup_time < 10:  # Should be very fast with index
                    print("✅ User lookup performance: EXCELLENT")
                elif avg_lookup_time < 50:
                    print("✅ User lookup performance: GOOD")
                else:
                    print("⚠️  User lookup performance: NEEDS OPTIMIZATION")
                
                if avg_files_time < 50:
                    print("✅ File listing performance: GOOD")
                else:
                    print("⚠️  File listing performance: NEEDS OPTIMIZATION")
                
                return query_results
                
        except Exception as e:
            print(f"❌ Database performance test failed: {e}")
            return {}
    
    def test_concurrent_operations(self):
        """Test system performance under concurrent load"""
        print("\nTesting Concurrent Operations...")
        print("-" * 50)
        
        try:
            from app.crypto_utils import CryptoEngine
            engine = CryptoEngine()
        except ImportError:
            print("❌ Cannot import CryptoEngine")
            return {}
        
        test_data = self.generate_test_data(0.5)  # 0.5MB test file
        num_threads = [1, 2, 4, 8]
        results = {}
        
        for thread_count in num_threads:
            print(f"Testing with {thread_count} concurrent operations...")
            
            def encrypt_operation():
                """Single encryption operation"""
                start_time = time.perf_counter()
                encrypted, key, iv, _ = engine.encrypt_aes(test_data)
                decrypted, _ = engine.decrypt_aes(encrypted, key, iv)
                end_time = time.perf_counter()
                return end_time - start_time
            
            # Run concurrent operations
            start_time = time.perf_counter()
            with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
                futures = [executor.submit(encrypt_operation) for _ in range(thread_count * 2)]
                operation_times = [future.result() for future in concurrent.futures.as_completed(futures)]
            end_time = time.perf_counter()
            
            total_time = end_time - start_time
            avg_operation_time = statistics.mean(operation_times)
            throughput = len(operation_times) / total_time  # operations per second
            
            results[f"{thread_count}_threads"] = {
                'total_time_s': total_time,
                'avg_operation_time_ms': avg_operation_time * 1000,
                'throughput_ops_per_sec': throughput
            }
            
            print(f"  Total time: {total_time:.2f}s")
            print(f"  Avg operation time: {avg_operation_time * 1000:.2f}ms") 
            print(f"  Throughput: {throughput:.2f} ops/sec")
        
        return results
    
    def monitor_system_resources(self, duration_seconds=30):
        """Monitor system resources during operations"""
        print(f"\nMonitoring System Resources for {duration_seconds}s...")
        print("-" * 50)
        
        cpu_usage = []
        memory_usage = []
        
        def monitor():
            start_time = time.time()
            while time.time() - start_time < duration_seconds:
                cpu_usage.append(psutil.cpu_percent(interval=1))
                memory_info = psutil.virtual_memory()
                memory_usage.append(memory_info.percent)
        
        # Start monitoring in background
        monitor_thread = threading.Thread(target=monitor)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Perform intensive operations during monitoring
        try:
            from app.crypto_utils import CryptoEngine
            engine = CryptoEngine()
            test_data = self.generate_test_data(1)  # 1MB
            
            for _ in range(20):  # 20 encryption operations
                encrypted, key, iv, _ = engine.encrypt_aes(test_data)
                decrypted, _ = engine.decrypt_aes(encrypted, key, iv)
                time.sleep(0.5)  # Small delay between operations
                
        except ImportError:
            print("⚠️  Cannot perform operations during monitoring")
            time.sleep(duration_seconds)  # Just wait
        
        monitor_thread.join()
        
        if cpu_usage and memory_usage:
            avg_cpu = statistics.mean(cpu_usage)
            max_cpu = max(cpu_usage)
            avg_memory = statistics.mean(memory_usage)
            max_memory = max(memory_usage)
            
            print(f"CPU Usage - Average: {avg_cpu:.1f}%, Peak: {max_cpu:.1f}%")
            print(f"Memory Usage - Average: {avg_memory:.1f}%, Peak: {max_memory:.1f}%")
            
            # Evaluate performance
            if max_cpu < 80:
                print("✅ CPU usage: GOOD")
            else:
                print("⚠️  CPU usage: HIGH")
            
            if max_memory < 80:
                print("✅ Memory usage: GOOD") 
            else:
                print("⚠️  Memory usage: HIGH")
            
            return {
                'avg_cpu_percent': avg_cpu,
                'max_cpu_percent': max_cpu,
                'avg_memory_percent': avg_memory,
                'max_memory_percent': max_memory
            }
        
        return {}
    
    def generate_performance_report(self):
        """Generate comprehensive performance report"""
        print("\n" + "=" * 70)
        print("PERFORMANCE TEST REPORT")
        print("=" * 70)
        print(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"System: {psutil.cpu_count()} CPU cores, {psutil.virtual_memory().total / (1024**3):.1f}GB RAM")
        
        results = {}
        
        # Run all performance tests
        results['encryption'] = self.measure_encryption_performance()
        results['database'] = self.test_database_performance()
        results['concurrent'] = self.test_concurrent_operations()
        results['system'] = self.monitor_system_resources(duration_seconds=15)  # Shorter for demo
        
        # Generate summary
        print(f"\n📊 PERFORMANCE SUMMARY:")
        
        # Encryption performance summary
        if results['encryption']:
            print(f"\n🔐 Encryption Performance:")
            for algorithm in results['encryption']:
                # Get 1MB performance as baseline
                mb1_data = results['encryption'][algorithm].get('1MB', {})
                if mb1_data:
                    enc_time = mb1_data.get('encryption_time_ms', 0)
                    throughput = mb1_data.get('encryption_throughput_mbps', 0)
                    print(f"  {algorithm}: {enc_time:.1f}ms (1MB), {throughput:.1f} MB/s")
        
        # Database performance summary
        if results['database']:
            print(f"\n🗄️ Database Performance:")
            user_lookup = results['database'].get('user_lookup_ms', 0)
            files_lookup = results['database'].get('user_files_lookup_ms', 0)
            print(f"  User lookup: {user_lookup:.2f}ms")
            print(f"  File listing: {files_lookup:.2f}ms")
        
        # System resources summary
        if results['system']:
            print(f"\n💻 System Resources:")
            max_cpu = results['system'].get('max_cpu_percent', 0)
            max_memory = results['system'].get('max_memory_percent', 0)
            print(f"  Peak CPU usage: {max_cpu:.1f}%")
            print(f"  Peak memory usage: {max_memory:.1f}%")
        
        return results
    
    def print_detailed_results(self, results):
        """Print detailed performance results"""
        print(f"\n📋 DETAILED RESULTS:")
        
        # Encryption details
        if results.get('encryption'):
            print(f"\n🔐 Encryption Algorithm Comparison:")
            print(f"{'Algorithm':<10} {'Size':<6} {'Enc Time':<10} {'Dec Time':<10} {'Throughput':<12} {'Memory':<10}")
            print("-" * 70)
            
            for algorithm in results['encryption']:
                for size in results['encryption'][algorithm]:
                    data = results['encryption'][algorithm][size]
                    print(f"{algorithm:<10} {size:<6} {data['encryption_time_ms']:<10.1f} "
                          f"{data['decryption_time_ms']:<10.1f} {data['encryption_throughput_mbps']:<12.1f} "
                          f"{data['memory_usage_mb']:<10.1f}")
        
        # Concurrent operations details
        if results.get('concurrent'):
            print(f"\n⚡ Concurrency Performance:")
            print(f"{'Threads':<8} {'Total Time':<12} {'Avg Op Time':<12} {'Throughput':<15}")
            print("-" * 50)
            
            for thread_config in results['concurrent']:
                data = results['concurrent'][thread_config]
                threads = thread_config.split('_')[0]
                print(f"{threads:<8} {data['total_time_s']:<12.2f} {data['avg_operation_time_ms']:<12.1f} "
                      f"{data['throughput_ops_per_sec']:<15.1f}")


def run_performance_tests():
    """Run all performance tests"""
    print("Starting Performance Testing Suite...")
    print("This may take several minutes to complete...")
    print("=" * 70)
    
    tester = PerformanceTester()
    results = tester.generate_performance_report()
    tester.print_detailed_results(results)
    
    # Determine overall performance rating
    encryption_ok = bool(results.get('encryption'))
    database_ok = results.get('database', {}).get('user_lookup_ms', 100) < 50
    system_ok = results.get('system', {}).get('max_cpu_percent', 100) < 90
    
    overall_score = sum([encryption_ok, database_ok, system_ok])
    
    print(f"\n🎯 OVERALL PERFORMANCE RATING:")
    if overall_score == 3:
        print("🟢 EXCELLENT - All performance metrics are good")
    elif overall_score == 2:
        print("🟡 GOOD - Most performance metrics are acceptable")
    elif overall_score == 1:
        print("🟠 FAIR - Some performance issues detected")
    else:
        print("🔴 POOR - Significant performance issues found")
    
    return overall_score >= 2  # Return success if at least 2/3 metrics are good


if __name__ == '__main__':
    success = run_performance_tests()
    
    if success:
        print("\n🎉 Performance tests completed successfully!")
        exit(0)
    else:
        print("\n⚠️  Performance issues detected - review the report above")
        exit(1)