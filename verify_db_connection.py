#!/usr/bin/env python3
"""
Verify Database Connection
===========================
Script to verify PostgreSQL database credentials from .env file.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
env_path = Path(__file__).parent / '.env'
if env_path.exists():
    load_dotenv(env_path)
    print(f"✅ Loaded .env file from: {env_path}")
else:
    print(f"❌ .env file not found at: {env_path}")
    sys.exit(1)

# Get database credentials from environment
db_config = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', '5432'),
    'database': os.getenv('DB_NAME', 'mcp_security'),
    'user': os.getenv('DB_USER', 'postgres_user'),
    'password': os.getenv('DB_PASSWORD', 'r$quaZ')
}

print("\n📊 Database Configuration:")
print(f"  Host: {db_config['host']}")
print(f"  Port: {db_config['port']}")
print(f"  Database: {db_config['database']}")
print(f"  User: {db_config['user']}")
print(f"  Password: {'*' * len(db_config['password'])}")

print("\n🔍 Testing connection...")

try:
    import psycopg2

    # Attempt connection
    conn = psycopg2.connect(**db_config)
    cursor = conn.cursor()

    # Test query
    cursor.execute('SELECT version()')
    version = cursor.fetchone()[0]

    print(f"\n✅ Connection successful!")
    print(f"📌 PostgreSQL version: {version.split(',')[0]}")

    # Check current user and database
    cursor.execute('SELECT current_user, current_database()')
    user, database = cursor.fetchone()
    print(f"📌 Connected as: {user}")
    print(f"📌 Connected to database: {database}")

    # Check if mcp_security schema exists
    cursor.execute("""
        SELECT EXISTS(
            SELECT 1 FROM information_schema.schemata
            WHERE schema_name = 'mcp_security'
        )
    """)
    schema_exists = cursor.fetchone()[0]

    if schema_exists:
        print(f"✅ Schema 'mcp_security' exists")

        # Count tables in schema
        cursor.execute("""
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = 'mcp_security'
        """)
        table_count = cursor.fetchone()[0]
        print(f"📊 Tables in mcp_security schema: {table_count}")
    else:
        print(f"ℹ️  Schema 'mcp_security' does not exist yet")
        print("   Run the database initialization script to create it")

    cursor.close()
    conn.close()

    print("\n✅ All database checks passed!")
    print("   The credentials in .env are valid and working.")

except ImportError:
    print("\n❌ psycopg2 module not installed")
    print("   Run: pip install psycopg2-binary")
    sys.exit(1)

except psycopg2.OperationalError as e:
    print(f"\n❌ Connection failed: {e}")
    print("\nPossible issues:")
    print("  1. PostgreSQL is not running")
    print("  2. Database 'mcp_security' does not exist")
    print("  3. User 'postgres_user' does not exist")
    print("  4. Password is incorrect")
    print("  5. PostgreSQL is not configured to accept connections")
    print("\nTo create the database and user, run as PostgreSQL superuser:")
    print("  CREATE USER postgres_user WITH PASSWORD 'r$quaZ';")
    print("  CREATE DATABASE mcp_security OWNER postgres_user;")
    sys.exit(1)

except Exception as e:
    print(f"\n❌ Unexpected error: {e}")
    sys.exit(1)