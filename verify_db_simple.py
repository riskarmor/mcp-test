#!/usr/bin/env python3
"""
Simple Database Connection Test
================================
Test PostgreSQL connection with hardcoded credentials.
"""

import socket

# Database configuration from .env file
db_config = {
    'host': 'localhost',
    'port': 5432,
    'database': 'mcp_security',
    'user': 'postgres_user',
    'password': 'r$quaZ'
}

print("📊 Database Configuration:")
print(f"  Host: {db_config['host']}")
print(f"  Port: {db_config['port']}")
print(f"  Database: {db_config['database']}")
print(f"  User: {db_config['user']}")
print(f"  Password: {'*' * len(db_config['password'])}")

print("\n🔍 Checking PostgreSQL port...")

try:
    # Check if PostgreSQL port is open
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    result = sock.connect_ex((db_config['host'], db_config['port']))
    sock.close()

    if result == 0:
        print(f"✅ PostgreSQL is running on {db_config['host']}:{db_config['port']}")
        print("\n📝 To fully test the credentials, you need to:")
        print("   1. Install psycopg2: pip install psycopg2-binary")
        print("   2. Run: python3 verify_db_connection.py")
        print("\n📝 Or test manually with psql:")
        print(f"   PGPASSWORD='{db_config['password']}' psql -h {db_config['host']} -U {db_config['user']} -d {db_config['database']}")
    else:
        print(f"❌ Cannot connect to PostgreSQL on {db_config['host']}:{db_config['port']}")
        print("   PostgreSQL may not be running or the port may be blocked")

except Exception as e:
    print(f"❌ Error checking connection: {e}")

print("\n📄 The credentials have been saved in .env file")
print("   The system will use these when connecting to the database.")