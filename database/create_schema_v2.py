#!/usr/bin/env python3
"""
Create Database Schema V2
=========================
Executes the schema.sql file as a single transaction.
"""

import os
import sys
import psycopg2
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

        try:
            # Execute the entire schema as one command
            cursor.execute(schema_sql)
            conn.commit()
            print("✅ Schema executed successfully!")

        except Exception as e:
            print(f"⚠️ Schema execution failed, trying statement by statement...")
            conn.rollback()

            # Try a more careful approach
            # Remove comments and split properly
            lines = schema_sql.split('\n')
            current_statement = []
            in_function = False

            for line in lines:
                # Skip empty lines and comments
                stripped = line.strip()
                if not stripped or stripped.startswith('--'):
                    continue

                current_statement.append(line)

                # Check if we're in a function definition
                if '$$' in line:
                    in_function = not in_function

                # Execute when we hit a semicolon at the end of line (not in function)
                if not in_function and line.rstrip().endswith(';'):
                    statement = '\n'.join(current_statement)
                    try:
                        cursor.execute(statement)
                        conn.commit()
                    except psycopg2.errors.DuplicateTable:
                        conn.rollback()  # Table exists, that's okay
                    except psycopg2.errors.DuplicateObject:
                        conn.rollback()  # Object exists, that's okay
                    except psycopg2.ProgrammingError as pe:
                        if 'already exists' in str(pe):
                            conn.rollback()
                        else:
                            print(f"⚠️ Failed: {str(pe)[:100]}")
                            conn.rollback()
                    except Exception as ex:
                        print(f"⚠️ Error: {str(ex)[:100]}")
                        conn.rollback()

                    current_statement = []

        # Verify key tables were created
        cursor.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name IN (
                'organizations', 'users', 'mcp_repositories',
                'repository_versions', 'scans', 'scores',
                'scan_semgrep_findings', 'scan_trufflehog_secrets',
                'scan_osv_vulnerabilities', 'sboms'
            )
            ORDER BY table_name;
        """)

        tables = cursor.fetchall()
        print(f"\n📊 Tables created: {len(tables)}/10")
        for table in tables:
            print(f"  ✅ {table[0]}")

        # Check if we have the minimum required tables
        required_tables = ['organizations', 'mcp_repositories']
        existing_required = [t[0] for t in tables if t[0] in required_tables]

        cursor.close()
        conn.close()

        if len(existing_required) == len(required_tables):
            print("\n✅ Core tables ready!")
            return True
        else:
            print(f"\n⚠️ Missing required tables: {set(required_tables) - set(existing_required)}")
            return False

    except Exception as e:
        print(f"❌ Failed to create schema: {e}")
        return False


if __name__ == "__main__":
    print("\n" + "="*60)
    print("DATABASE SCHEMA CREATION V2")
    print("="*60)

    if create_schema():
        print("\n✅ Database schema created successfully!")
        print("\nYou can now run:")
        print("  source /mnt/prod/venv/bin/activate")
        print("  python /mnt/prod/mcp/database/populate_mcps.py")
    else:
        print("\n❌ Failed to create database schema")
        sys.exit(1)