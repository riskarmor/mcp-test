#!/usr/bin/env python3
"""
Create Database Schema
======================
Executes the schema.sql file to create all tables and structures.
"""

import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from pathlib import Path

# Add parent directory to path
sys.path.append('/mnt/prod/mcp')

from dotenv import load_dotenv

# Load environment variables
load_dotenv('/mnt/prod/mcp/.env')


def create_schema():
    """Create database schema from schema.sql file."""

    db_params = {
        'host': os.getenv('DB_HOST', 'localhost'),
        'port': os.getenv('DB_PORT', '5432'),
        'database': os.getenv('DB_NAME', 'mcp_security'),
        'user': os.getenv('DB_USER', 'postgres_user'),
        'password': os.getenv('DB_PASSWORD', 'r$quaZ')
    }

    try:
        # Connect to database
        conn = psycopg2.connect(**db_params)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()

        print(f"✅ Connected to database: {db_params['database']}")

        # Read schema file
        schema_file = Path('/mnt/prod/mcp/database/schema.sql')
        if not schema_file.exists():
            print(f"❌ Schema file not found: {schema_file}")
            return False

        with open(schema_file, 'r') as f:
            schema_sql = f.read()

        print("📋 Executing schema.sql...")

        # Split by semicolons and execute each statement
        statements = [s.strip() for s in schema_sql.split(';') if s.strip()]

        success_count = 0
        error_count = 0

        for i, statement in enumerate(statements, 1):
            try:
                # Skip comments
                if statement.startswith('--'):
                    continue

                cursor.execute(statement + ';')
                success_count += 1

                # Progress indicator
                if i % 10 == 0:
                    print(f"  Executed {i}/{len(statements)} statements...")

            except psycopg2.errors.DuplicateTable:
                # Table already exists, that's okay
                success_count += 1
            except psycopg2.errors.DuplicateObject:
                # Object already exists, that's okay
                success_count += 1
            except Exception as e:
                error_count += 1
                if 'already exists' not in str(e):
                    print(f"⚠️ Statement {i} failed: {str(e)[:100]}")

        print(f"\n✅ Schema execution complete!")
        print(f"  Successful statements: {success_count}")
        if error_count > 0:
            print(f"  Failed statements: {error_count}")

        # Verify key tables were created
        cursor.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name IN (
                'organizations', 'users', 'mcp_repositories',
                'repository_versions', 'scans', 'scores'
            )
            ORDER BY table_name;
        """)

        tables = cursor.fetchall()
        print(f"\n📊 Key tables created: {len(tables)}")
        for table in tables:
            print(f"  ✅ {table[0]}")

        cursor.close()
        conn.close()

        return True

    except Exception as e:
        print(f"❌ Failed to create schema: {e}")
        return False


if __name__ == "__main__":
    print("\n" + "="*60)
    print("DATABASE SCHEMA CREATION")
    print("="*60)

    if create_schema():
        print("\n✅ Database schema created successfully!")
        print("\nYou can now run: python /mnt/prod/mcp/database/populate_mcps.py")
    else:
        print("\n❌ Failed to create database schema")
        sys.exit(1)