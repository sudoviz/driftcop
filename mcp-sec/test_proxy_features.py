#!/usr/bin/env python3
"""
Test script for DriftCop Proxy advanced features: hot reload and process pool
"""

import json
import asyncio
import multiprocessing as mp
from pathlib import Path
import time
import logging
import sys
import os

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_process_pool():
    """Test process pool functionality"""
    print("\n=== Testing Process Pool ===")
    
    from src.driftcop_proxy.security_worker import init_worker, analyze_message, AnalysisRequest
    
    # Initialize a worker process
    init_worker()
    
    # Create a test request
    test_message = {
        'jsonrpc': '2.0',
        'method': 'tools/call',
        'params': {
            'tool': 'dangerous_tool',
            'arguments': {'cmd': 'rm -rf /'}
        },
        'id': 'test-1'
    }
    
    request = AnalysisRequest(
        request_id='test-request-1',
        message_data=test_message,
        analyzers_to_run=['tool_poisoning', 'cross_origin'],
        session_context={'client_name': 'test', 'session_id': 'test-session'}
    )
    
    # Analyze the message
    start = time.time()
    result = analyze_message(request.to_dict())
    elapsed = time.time() - start
    
    print(f"Analysis completed in {elapsed:.3f} seconds")
    print(f"Found {len(result['findings'])} findings")
    print(f"Risk scores: {result['risk_scores']}")
    
    # Test with pool
    print("\nTesting with multiprocessing pool...")
    pool = mp.Pool(processes=2, initializer=init_worker)
    
    # Submit multiple requests
    requests = []
    for i in range(5):
        req = AnalysisRequest(
            request_id=f'test-request-{i}',
            message_data=test_message,
            analyzers_to_run=['tool_poisoning', 'cross_origin'],
            session_context={'client_name': 'test', 'session_id': f'session-{i}'}
        )
        requests.append(req.to_dict())
    
    # Process in parallel
    start = time.time()
    results = pool.map(analyze_message, requests)
    elapsed = time.time() - start
    
    print(f"Analyzed {len(results)} messages in {elapsed:.3f} seconds")
    print(f"Average time per message: {elapsed/len(results):.3f} seconds")
    
    pool.close()
    pool.join()
    
    print("✅ Process pool test passed")
    return True


async def test_hot_reload():
    """Test hot reload functionality"""
    print("\n=== Testing Hot Reload ===")
    
    from src.driftcop_proxy.hot_reload import ConfigWatcher
    
    # Create test config file
    test_config_path = Path('/tmp/test_driftcop_config.json')
    test_config = {
        'mode': 'monitor',
        'interceptors': [
            {'type': 'security', 'config': {'block_threshold': 5.0}}
        ]
    }
    
    with open(test_config_path, 'w') as f:
        json.dump(test_config, f, indent=2)
    
    print(f"Created test config at {test_config_path}")
    
    # Track reload events
    reload_count = 0
    
    async def reload_callback(changed_files):
        nonlocal reload_count
        reload_count += 1
        print(f"Reload triggered! Changed files: {[str(f) for f in changed_files]}")
    
    # Create and start watcher
    watcher = ConfigWatcher(
        config_paths=[test_config_path],
        reload_callback=reload_callback,
        check_interval=0.5  # Fast check for testing
    )
    
    await watcher.start()
    print("Watcher started, waiting for changes...")
    
    # Wait a bit
    await asyncio.sleep(1)
    
    # Modify the config
    test_config['mode'] = 'enforce'
    test_config['interceptors'][0]['config']['block_threshold'] = 3.0
    
    with open(test_config_path, 'w') as f:
        json.dump(test_config, f, indent=2)
    
    print("Modified config file")
    
    # Wait for reload
    await asyncio.sleep(2)
    
    # Check if reload was triggered
    if reload_count > 0:
        print(f"✅ Hot reload test passed - {reload_count} reloads triggered")
        result = True
    else:
        print("❌ Hot reload test failed - no reloads triggered")
        result = False
    
    # Stop watcher
    await watcher.stop()
    
    # Clean up
    test_config_path.unlink(missing_ok=True)
    
    # Get stats
    stats = watcher.get_stats()
    print(f"Watcher stats: {json.dumps(stats, indent=2, default=str)}")
    
    return result


async def test_worker_pool_async():
    """Test async worker pool integration"""
    print("\n=== Testing Async Worker Pool ===")
    
    from src.driftcop_proxy.security_worker import init_worker, SecurityWorkerPool
    
    # Create pool
    pool = mp.Pool(processes=2, initializer=init_worker)
    worker_pool = SecurityWorkerPool(pool)
    
    # Test single analysis
    test_message = {
        'jsonrpc': '2.0',
        'method': 'resources/write',
        'params': {
            'path': '/etc/passwd',
            'content': 'hacked'
        },
        'id': 'async-test-1'
    }
    
    print("Testing single async analysis...")
    start = time.time()
    result = await worker_pool.analyze_async(
        test_message,
        ['tool_poisoning'],
        {'client_name': 'test', 'session_id': 'async-session'}
    )
    elapsed = time.time() - start
    
    print(f"Async analysis completed in {elapsed:.3f} seconds")
    print(f"Found {len(result.findings)} findings")
    
    # Test batch analysis
    print("\nTesting batch async analysis...")
    messages = [
        (test_message, ['tool_poisoning'], {'client_name': 'test', 'session_id': f'batch-{i}'})
        for i in range(5)
    ]
    
    start = time.time()
    results = await worker_pool.batch_analyze_async(messages)
    elapsed = time.time() - start
    
    print(f"Batch analyzed {len(results)} messages in {elapsed:.3f} seconds")
    print(f"Average time per message: {elapsed/len(results):.3f} seconds")
    
    # Clean up
    worker_pool.close()
    pool.join()
    
    print("✅ Async worker pool test passed")
    return True


def main():
    """Run all tests"""
    print("=" * 60)
    print("DriftCop Proxy Advanced Features Test Suite")
    print("=" * 60)
    
    results = {}
    
    try:
        # Test process pool
        results['process_pool'] = test_process_pool()
    except Exception as e:
        print(f"\n❌ Process pool test failed: {e}")
        import traceback
        traceback.print_exc()
        results['process_pool'] = False
    
    try:
        # Test hot reload
        results['hot_reload'] = asyncio.run(test_hot_reload())
    except Exception as e:
        print(f"\n❌ Hot reload test failed: {e}")
        import traceback
        traceback.print_exc()
        results['hot_reload'] = False
    
    try:
        # Test async worker pool
        results['async_worker_pool'] = asyncio.run(test_worker_pool_async())
    except Exception as e:
        print(f"\n❌ Async worker pool test failed: {e}")
        import traceback
        traceback.print_exc()
        results['async_worker_pool'] = False
    
    print("\n" + "=" * 60)
    print("Test Summary:")
    for feature, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {feature}: {status}")
    
    total_passed = sum(1 for v in results.values() if v)
    print(f"\nTotal: {total_passed}/{len(results)} features working")
    print("=" * 60)
    
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())