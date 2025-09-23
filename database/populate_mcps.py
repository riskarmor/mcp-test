#!/usr/bin/env python3
"""
Populate Database with MCP Repositories
========================================
Loads MCP repositories from JSON file and populates the database.
Creates initial organization and imports all MCPs.
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

# Add parent directory to path
sys.path.append('/mnt/prod/mcp')

import psycopg2
from psycopg2.extras import execute_batch
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/mnt/prod/mcp/.env')


class MCPDatabasePopulator:
    """Populates database with MCP repositories from JSON file."""

    def __init__(self):
        """Initialize database connection."""
        self.db_params = {
            'host': os.getenv('DB_HOST', 'localhost'),
            'port': os.getenv('DB_PORT', '5432'),
            'database': os.getenv('DB_NAME', 'mcp_security'),
            'user': os.getenv('DB_USER', 'postgres_user'),
            'password': os.getenv('DB_PASSWORD', 'r$quaZ')
        }
        self.conn = None
        self.cursor = None

    def connect(self):
        """Connect to PostgreSQL database."""
        try:
            self.conn = psycopg2.connect(**self.db_params)
            self.cursor = self.conn.cursor()
            print(f"✅ Connected to database: {self.db_params['database']}")
            return True
        except psycopg2.Error as e:
            print(f"❌ Database connection failed: {e}")
            return False

    def close(self):
        """Close database connection."""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    def create_default_organization(self):
        """Create a default organization for initial MCP imports."""
        try:
            org_id = str(uuid4())
            workos_org_id = "org_default_" + org_id[:8]

            query = """
                INSERT INTO organizations (
                    id, workos_org_id, name, slug,
                    subscription_tier, is_active, created_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (workos_org_id) DO UPDATE
                SET updated_at = CURRENT_TIMESTAMP
                RETURNING id;
            """

            self.cursor.execute(query, (
                org_id,
                workos_org_id,
                "Default Organization",
                "default",
                "enterprise",
                True,
                datetime.utcnow()
            ))

            result = self.cursor.fetchone()
            if result:
                print(f"✅ Default organization created/updated: {result[0]}")
                return result[0]

        except psycopg2.Error as e:
            print(f"❌ Failed to create organization: {e}")
            self.conn.rollback()
            return None

    def parse_github_url(self, url):
        """
        Parse GitHub URL to extract owner and repository name.

        Args:
            url: GitHub repository URL

        Returns:
            Tuple of (owner, repo_name) or (None, None) if invalid
        """
        try:
            # Remove trailing slash and .git extension
            url = url.rstrip('/').replace('.git', '')

            # Parse URL
            parsed = urlparse(url)

            # Extract path components
            path_parts = parsed.path.strip('/').split('/')

            if len(path_parts) >= 2:
                owner = path_parts[0]
                repo_name = path_parts[1]
                return owner, repo_name

        except Exception as e:
            print(f"⚠️ Failed to parse URL {url}: {e}")

        return None, None

    def load_repositories_from_json(self, json_file):
        """
        Load repositories from JSON file.

        Args:
            json_file: Path to JSON file with MCP repositories

        Returns:
            List of repository dictionaries
        """
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            print(f"✅ Loaded {len(data)} repositories from {json_file}")
            return data

        except Exception as e:
            print(f"❌ Failed to load JSON file: {e}")
            return []

    def insert_repositories(self, repositories, organization_id=None):
        """
        Insert repositories into database.

        Args:
            repositories: List of repository dictionaries
            organization_id: Optional organization ID to associate with repos
        """
        if not repositories:
            print("No repositories to insert")
            return

        # Prepare data for batch insert
        insert_data = []
        skipped = 0

        for repo in repositories:
            owner, repo_name = self.parse_github_url(repo['url'])

            if not owner or not repo_name:
                print(f"⚠️ Skipping invalid URL: {repo['url']}")
                skipped += 1
                continue

            repo_id = str(uuid4())

            insert_data.append((
                repo_id,
                organization_id,
                repo['url'],
                owner,
                repo_name,
                repo['name'],  # display_name
                None,  # description (to be fetched later)
                None,  # primary_language (to be fetched later)
                True,  # is_public
                False,  # is_archived
                True,  # is_active
                json.dumps([]),  # tags
                json.dumps({}),  # metadata
                datetime.utcnow(),  # first_seen_at
                datetime.utcnow(),  # created_at
                datetime.utcnow()   # updated_at
            ))

        if not insert_data:
            print("❌ No valid repositories to insert")
            return

        # Batch insert repositories
        try:
            insert_query = """
                INSERT INTO mcp_repositories (
                    id, organization_id, github_url, github_owner, github_name,
                    display_name, description, primary_language,
                    is_public, is_archived, is_active,
                    tags, metadata, first_seen_at, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (github_url) DO UPDATE
                SET
                    display_name = EXCLUDED.display_name,
                    updated_at = CURRENT_TIMESTAMP;
            """

            # Execute in batches of 100
            batch_size = 100
            total_inserted = 0

            for i in range(0, len(insert_data), batch_size):
                batch = insert_data[i:i + batch_size]
                execute_batch(self.cursor, insert_query, batch, page_size=batch_size)
                total_inserted += len(batch)

                # Progress indicator
                if total_inserted % 500 == 0:
                    print(f"  Inserted {total_inserted}/{len(insert_data)} repositories...")

            self.conn.commit()
            print(f"✅ Successfully inserted/updated {len(insert_data)} repositories")
            if skipped > 0:
                print(f"⚠️ Skipped {skipped} invalid URLs")

        except psycopg2.Error as e:
            print(f"❌ Failed to insert repositories: {e}")
            self.conn.rollback()

    def get_statistics(self):
        """Get statistics about imported repositories."""
        try:
            # Total repositories
            self.cursor.execute("SELECT COUNT(*) FROM mcp_repositories WHERE is_active = true;")
            total_repos = self.cursor.fetchone()[0]

            # Repositories by owner (top 10)
            self.cursor.execute("""
                SELECT github_owner, COUNT(*) as count
                FROM mcp_repositories
                WHERE is_active = true
                GROUP BY github_owner
                ORDER BY count DESC
                LIMIT 10;
            """)
            top_owners = self.cursor.fetchall()

            print("\n" + "="*60)
            print("DATABASE STATISTICS")
            print("="*60)
            print(f"Total Active MCPs: {total_repos}")
            print("\nTop 10 Repository Owners:")
            for owner, count in top_owners:
                print(f"  {owner}: {count} repositories")

            # Sample repositories
            self.cursor.execute("""
                SELECT display_name, github_url
                FROM mcp_repositories
                WHERE is_active = true
                ORDER BY RANDOM()
                LIMIT 5;
            """)
            samples = self.cursor.fetchall()

            print("\nSample Repositories:")
            for name, url in samples:
                print(f"  - {name}")
                print(f"    {url}")

        except psycopg2.Error as e:
            print(f"❌ Failed to get statistics: {e}")


def main():
    """Main function to populate database with MCPs."""
    print("\n" + "="*60)
    print("MCP DATABASE POPULATION")
    print("="*60)

    # Initialize populator
    populator = MCPDatabasePopulator()

    # Connect to database
    if not populator.connect():
        print("Failed to connect to database. Exiting.")
        return 1

    try:
        # Create default organization
        org_id = populator.create_default_organization()

        # Load repositories from JSON
        json_file = '/mnt/prod/mcp/mcp_repositories.json'
        repositories = populator.load_repositories_from_json(json_file)

        if repositories:
            print(f"\nInserting {len(repositories)} repositories into database...")
            populator.insert_repositories(repositories, org_id)

            # Show statistics
            populator.get_statistics()

        print("\n✅ Database population complete!")
        return 0

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return 1

    finally:
        populator.close()


if __name__ == "__main__":
    sys.exit(main())