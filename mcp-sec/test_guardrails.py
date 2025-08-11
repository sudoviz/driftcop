#!/usr/bin/env python3
"""
Test script for DriftCop Guardrails Implementation
Tests profile management, new interceptors, and Python functions
"""

import json
import asyncio
import sys
from pathlib import Path
import tempfile
import logging

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def test_profile_manager():
    """Test the enhanced profile manager with namespaces"""
    print("\n=== Testing Profile Manager ===")
    
    from src.driftcop_proxy.profiles import ProfileManager, GuardProfile
    
    manager = ProfileManager()
    
    # List builtin profiles
    print("\nBuiltin profiles:")
    builtin_profiles = manager.list_profiles('builtin')
    for profile in builtin_profiles:
        print(f"  - {profile['name']}: {profile['description'][:50]}...")
    
    # Load a builtin profile
    print("\nLoading strict-compliance profile:")
    strict_profile = manager.load_profile('strict-compliance', 'builtin')
    if strict_profile:
        print(f"  Name: {strict_profile.name}")
        print(f"  Version: {strict_profile.version}")
        print(f"  Interceptors: {len(strict_profile.interceptors)}")
        
        # Validate profile
        errors = strict_profile.validate()
        if errors:
            print(f"  ❌ Validation errors: {errors}")
        else:
            print(f"  ✅ Profile is valid")
    
    # Create custom profile based on builtin
    print("\nCreating custom profile:")
    custom_profile = manager.create_profile(
        name='test-profile',
        namespace='test',
        base_profile='development',
        description='Test profile for guardrails',
        interceptors=[
            {
                'type': 'logging',
                'config': {
                    'log_level': 'debug',
                    'output': 'console'
                }
            }
        ]
    )
    
    if custom_profile:
        print(f"  ✅ Created: {custom_profile.namespace}/{custom_profile.name}")
    else:
        print("  ❌ Failed to create profile")
    
    # Test profile composition
    print("\nTesting profile composition:")
    dev_profile = manager.load_profile('development', 'builtin')
    log_profile = manager.load_profile('log-only', 'builtin')
    
    if dev_profile and log_profile:
        composed = dev_profile.compose(log_profile)
        print(f"  Composed profile has {len(composed.interceptors)} interceptors")
    
    return True


async def test_logging_interceptor():
    """Test the new logging interceptor"""
    print("\n=== Testing Logging Interceptor ===")
    
    from src.driftcop_interceptors.logging import LoggingInterceptor
    from src.driftcop_proxy.message import MCPMessage, MessageDirection
    from src.driftcop_proxy.session import ProxySession
    
    # Create interceptor
    config = {
        'log_level': 'INFO',
        'include_payload': True,
        'format': 'pretty',
        'colorize': True,
        'output': 'console'
    }
    
    interceptor = LoggingInterceptor(config)
    
    # Create test message
    message = MCPMessage.from_dict({
        'jsonrpc': '2.0',
        'method': 'tools/call',
        'params': {
            'tool': 'test_tool',
            'arguments': {'arg1': 'value1'}
        },
        'id': 'test-1'
    }, MessageDirection.OUTBOUND)
    
    # Create test session
    from src.driftcop_proxy.session import SecurityContext
    security_context = SecurityContext(
        session_id='test-session',
        client_name='test-client',
        server_name='test-server'
    )
    session = ProxySession(
        id='test-session',
        client_name='test-client',
        server_config={},
        security_context=security_context
    )
    
    # Test interception
    action = await interceptor.intercept(message, session)
    
    print(f"  Action: {action.type.value}")
    print(f"  Logged: {action.metadata.get('logged', False)}")
    
    # Get stats
    stats = interceptor.get_stats()
    print(f"  Messages logged: {stats['messages_logged']}")
    
    return True


async def test_audit_interceptor():
    """Test the new audit interceptor"""
    print("\n=== Testing Audit Interceptor ===")
    
    from src.driftcop_interceptors.audit import AuditInterceptor
    from src.driftcop_proxy.message import MCPMessage, MessageDirection
    from src.driftcop_proxy.session import ProxySession
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create interceptor
        config = {
            'enabled': True,
            'compliance_mode': 'SOC2',
            'storage_path': tmpdir,
            'hash_messages': True,
            'sign_logs': True
        }
        
        interceptor = AuditInterceptor(config)
        
        # Create test messages
        messages = []
        for i in range(5):
            msg = MCPMessage.from_dict({
                'jsonrpc': '2.0',
                'method': f'test/method_{i}',
                'params': {'index': i},
                'id': f'test-{i}'
            }, MessageDirection.OUTBOUND)
            messages.append(msg)
        
        # Create test session
        from src.driftcop_proxy.session import SecurityContext
        security_context = SecurityContext(
            session_id='audit-session',
            client_name='audit-client',
            server_name='audit-server'
        )
        session = ProxySession(
            id='audit-session',
            client_name='audit-client',
            server_config={},
            security_context=security_context
        )
        
        # Audit messages
        for msg in messages:
            action = await interceptor.intercept(msg, session)
            print(f"  Audited message {msg.id}: {action.metadata.get('audited', False)}")
        
        # Get stats
        stats = interceptor.get_stats()
        print(f"\nAudit Statistics:")
        print(f"  Total entries: {stats['total_entries']}")
        print(f"  Chain valid: {stats['chain_valid']}")
        print(f"  Compliance mode: {stats['compliance_mode']}")
        print(f"  DB size: {stats['db_size']} bytes")
        
        # Verify chain integrity
        chain_valid = interceptor.verify_chain_integrity()
        print(f"  Chain integrity: {'✅ Valid' if chain_valid else '❌ Invalid'}")
    
    return True


async def test_python_function_interceptor():
    """Test the Python function interceptor"""
    print("\n=== Testing Python Function Interceptor ===")
    
    from src.driftcop_interceptors.python_function import PythonFunctionInterceptor
    from src.driftcop_proxy.message import MCPMessage, MessageDirection
    from src.driftcop_proxy.session import ProxySession
    
    # Test 1: Block dangerous tools
    print("\nTest 1: Block dangerous tools")
    config = {
        'script': '''
def process_message(msg_direction, msg_type, raw_msg):
    import json
    msg = json.loads(raw_msg)
    
    if msg.get('method') == 'tools/call':
        tool = msg.get('params', {}).get('tool', '')
        if tool in ['rm', 'delete']:
            global drop_reason
            drop_reason = f"Dangerous tool blocked: {tool}"
            return 'drop'
    
    return 'send'
''',
        'safe_mode': True
    }
    
    interceptor = PythonFunctionInterceptor(config)
    
    # Test dangerous tool
    dangerous_msg = MCPMessage.from_dict({
        'jsonrpc': '2.0',
        'method': 'tools/call',
        'params': {'tool': 'rm', 'arguments': {'path': '/important'}},
        'id': 'danger-1'
    }, MessageDirection.OUTBOUND)
    
    from src.driftcop_proxy.session import SecurityContext
    security_context = SecurityContext(
        session_id='py-session',
        client_name='py-client',
        server_name='py-server'
    )
    session = ProxySession(
        id='py-session',
        client_name='py-client',
        server_config={},
        security_context=security_context
    )
    
    action = await interceptor.intercept(dangerous_msg, session)
    print(f"  Dangerous tool action: {action.type.value}")
    print(f"  Reason: {action.reason}")
    
    # Test safe tool
    safe_msg = MCPMessage.from_dict({
        'jsonrpc': '2.0',
        'method': 'tools/call',
        'params': {'tool': 'list', 'arguments': {}},
        'id': 'safe-1'
    }, MessageDirection.OUTBOUND)
    
    action = await interceptor.intercept(safe_msg, session)
    print(f"  Safe tool action: {action.type.value}")
    
    # Test 2: Message modification
    print("\nTest 2: Message modification")
    config = {
        'script': '''
def process_message(msg_direction, msg_type, raw_msg):
    import json
    msg = json.loads(raw_msg)
    
    # Add metadata to all messages
    msg['metadata'] = {'processed': True, 'timestamp': '2024-01-01'}
    
    global modified_msg
    modified_msg = msg
    return 'modify'
''',
        'safe_mode': True
    }
    
    mod_interceptor = PythonFunctionInterceptor(config)
    
    original_msg = MCPMessage.from_dict({
        'jsonrpc': '2.0',
        'method': 'test/method',
        'params': {},
        'id': 'mod-1'
    }, MessageDirection.OUTBOUND)
    
    action = await mod_interceptor.intercept(original_msg, session)
    print(f"  Modification action: {action.type.value}")
    if action.message:
        modified_dict = action.message.to_dict()
        print(f"  Metadata added: {modified_dict.get('metadata', {})}")
    
    # Get stats
    stats = interceptor.get_stats()
    print(f"\nPython Function Stats:")
    print(f"  Executions: {stats['executions']}")
    print(f"  Success rate: {stats['success_rate']:.1f}%")
    
    return True


async def test_profile_with_interceptors():
    """Test loading and using a complete profile"""
    print("\n=== Testing Complete Profile Execution ===")
    
    from src.driftcop_proxy.profiles import ProfileManager
    from src.driftcop_interceptors.factory import InterceptorFactory
    from src.driftcop_interceptors.chain import InterceptorChain
    from src.driftcop_proxy.message import MCPMessage, MessageDirection
    from src.driftcop_proxy.session import ProxySession
    
    # Load strict compliance profile
    manager = ProfileManager()
    profile = manager.load_profile('block-dangerous-tools', 'builtin')
    
    if not profile:
        print("  ❌ Failed to load profile")
        return False
    
    print(f"  Loaded profile: {profile.name}")
    print(f"  Interceptors: {len(profile.interceptors)}")
    
    # Create interceptors from profile
    factory = InterceptorFactory()
    interceptors = []
    
    for config in profile.interceptors:
        interceptor = factory.create(config)
        if interceptor:
            interceptors.append(interceptor)
            print(f"    - Created {config['type']} interceptor")
    
    # Create chain
    chain = InterceptorChain(interceptors)
    
    # Test with dangerous message
    dangerous_msg = MCPMessage.from_dict({
        'jsonrpc': '2.0',
        'method': 'tools/call',
        'params': {
            'tool': 'rm',
            'arguments': {'path': '/etc/passwd'}
        },
        'id': 'profile-test-1'
    }, MessageDirection.OUTBOUND)
    
    from src.driftcop_proxy.session import SecurityContext
    security_context = SecurityContext(
        session_id='profile-session',
        client_name='profile-client',
        server_name='profile-server'
    )
    session = ProxySession(
        id='profile-session',
        client_name='profile-client',
        server_config={},
        security_context=security_context
    )
    
    # Process through chain
    action = await chain.process(dangerous_msg, session)
    
    print(f"\n  Final action: {action.type.value}")
    print(f"  Reason: {action.reason}")
    
    return action.type.value == 'block'


def main():
    """Run all guardrails tests"""
    print("=" * 60)
    print("DriftCop Guardrails Test Suite")
    print("=" * 60)
    
    results = {}
    
    try:
        # Test profile manager
        results['profile_manager'] = test_profile_manager()
    except Exception as e:
        print(f"\n❌ Profile manager test failed: {e}")
        import traceback
        traceback.print_exc()
        results['profile_manager'] = False
    
    try:
        # Test logging interceptor
        results['logging_interceptor'] = asyncio.run(test_logging_interceptor())
    except Exception as e:
        print(f"\n❌ Logging interceptor test failed: {e}")
        import traceback
        traceback.print_exc()
        results['logging_interceptor'] = False
    
    try:
        # Test audit interceptor
        results['audit_interceptor'] = asyncio.run(test_audit_interceptor())
    except Exception as e:
        print(f"\n❌ Audit interceptor test failed: {e}")
        import traceback
        traceback.print_exc()
        results['audit_interceptor'] = False
    
    try:
        # Test Python function interceptor
        results['python_function'] = asyncio.run(test_python_function_interceptor())
    except Exception as e:
        print(f"\n❌ Python function test failed: {e}")
        import traceback
        traceback.print_exc()
        results['python_function'] = False
    
    try:
        # Test complete profile
        results['complete_profile'] = asyncio.run(test_profile_with_interceptors())
    except Exception as e:
        print(f"\n❌ Complete profile test failed: {e}")
        import traceback
        traceback.print_exc()
        results['complete_profile'] = False
    
    print("\n" + "=" * 60)
    print("Test Summary:")
    for feature, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"  {feature}: {status}")
    
    total_passed = sum(1 for v in results.values() if v)
    print(f"\nTotal: {total_passed}/{len(results)} tests passed")
    print("=" * 60)
    
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())