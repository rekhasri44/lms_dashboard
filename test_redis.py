import redis

def test_redis_connection():
    try:
        # Test different Redis connection options
        connection_options = [
            {'host': 'localhost', 'port': 6379, 'db': 0},
            {'host': '127.0.0.1', 'port': 6379, 'db': 0},
        ]
        
        for opts in connection_options:
            try:
                print(f"Testing Redis connection to {opts['host']}:{opts['port']}...")
                r = redis.Redis(**opts, socket_connect_timeout=5)
                response = r.ping()
                if response:
                    print(f"✅ SUCCESS: Redis connected at {opts['host']}:{opts['port']}")
                    return opts
            except Exception as e:
                print(f"❌ Failed: {e}")
        
        print("❌ No Redis connection available. Using memory storage instead.")
        return None
        
    except Exception as e:
        print(f"❌ Redis test failed: {e}")
        return None

if __name__ == "__main__":
    test_redis_connection()