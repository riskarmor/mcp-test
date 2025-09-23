#!/usr/bin/env python3
"""
Populate MCP Tools Table
========================
Extracts and populates all 4,828 unique tool implementations from JSON,
properly handling monorepos and tracking occurrence counts.
"""

import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime
from uuid import uuid4

# Add parent directory to path
sys.path.append('/mnt/prod/mcp')

import psycopg2
from psycopg2.extras import execute_batch
from dotenv import load_dotenv

# Load environment variables
load_dotenv('/mnt/prod/mcp/.env')


class MCPToolsPopulator:
    """Populates mcp_tools table with all tool implementations."""

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

    def analyze_json_data(self, json_file):
        """
        Analyze JSON to extract unique tools and identify monorepos.

        Returns:
            tuple: (combo_counts, monorepos, stats)
        """
        print(f"\n📊 Analyzing {json_file}...")

        with open(json_file, 'r') as f:
            data = json.load(f)

        # Count occurrences of each (URL, tool_name) combination
        combo_counts = Counter((e['url'], e['name']) for e in data)

        # Group by repository to identify monorepos
        repo_tools = defaultdict(set)
        for (url, name), count in combo_counts.items():
            repo_tools[url].add(name)

        # Identify monorepos (repositories with >1 unique tool)
        monorepos = {url: list(tools) for url, tools in repo_tools.items()
                     if len(tools) > 1}

        # Calculate statistics
        stats = {
            'total_entries': len(data),
            'unique_repos': len(repo_tools),
            'unique_tools': len(set(e['name'] for e in data)),
            'unique_combos': len(combo_counts),
            'monorepo_count': len(monorepos),
            'monorepo_tools': sum(len(tools) for tools in monorepos.values()),
            'single_tool_repos': len(repo_tools) - len(monorepos)
        }

        return combo_counts, monorepos, stats

    def get_repository_mapping(self):
        """Get mapping of GitHub URLs to repository IDs."""
        self.cursor.execute("""
            SELECT id, github_url
            FROM mcp_repositories
        """)

        return {url: repo_id for repo_id, url in self.cursor.fetchall()}

    def populate_tools(self, combo_counts, monorepos):
        """
        Insert all tool implementations into mcp_tools table.

        Args:
            combo_counts: Counter of (url, tool_name) -> occurrence_count
            monorepos: Dict of monorepo URLs -> list of tool names
        """
        # Get repository ID mapping
        repo_mapping = self.get_repository_mapping()

        # Prepare insert data
        insert_data = []
        skipped = 0

        for (url, tool_name), occurrence_count in combo_counts.items():
            if url not in repo_mapping:
                print(f"⚠️ Repository not found in DB: {url}")
                skipped += 1
                continue

            repo_id = repo_mapping[url]
            is_monorepo = url in monorepos
            tool_id = str(uuid4())

            insert_data.append((
                tool_id,
                repo_id,
                tool_name,
                None,  # tool_path (to be determined later)
                is_monorepo,
                occurrence_count,
                True,  # is_active
                json.dumps({}),  # metadata
                datetime.utcnow(),  # created_at
                datetime.utcnow()   # updated_at
            ))

        if not insert_data:
            print("❌ No tools to insert")
            return

        # Batch insert
        print(f"\n📝 Inserting {len(insert_data)} tool implementations...")

        try:
            insert_query = """
                INSERT INTO mcp_tools (
                    id, repository_id, tool_name, tool_path,
                    is_monorepo_tool, occurrence_count, is_active,
                    metadata, created_at, updated_at
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (repository_id, tool_name) DO UPDATE
                SET
                    occurrence_count = EXCLUDED.occurrence_count,
                    updated_at = CURRENT_TIMESTAMP
            """

            # Execute in batches
            batch_size = 100
            for i in range(0, len(insert_data), batch_size):
                batch = insert_data[i:i + batch_size]
                execute_batch(self.cursor, insert_query, batch, page_size=batch_size)

                if (i + batch_size) % 1000 == 0:
                    print(f"  Inserted {min(i + batch_size, len(insert_data))}/{len(insert_data)} tools...")

            self.conn.commit()
            print(f"✅ Successfully inserted/updated {len(insert_data)} tools")
            if skipped > 0:
                print(f"⚠️ Skipped {skipped} tools (repository not in DB)")

        except psycopg2.Error as e:
            print(f"❌ Failed to insert tools: {e}")
            self.conn.rollback()

    def get_statistics(self):
        """Get statistics about imported tools."""
        try:
            # Total tools
            self.cursor.execute("SELECT COUNT(*) FROM mcp_tools")
            total_tools = self.cursor.fetchone()[0]

            # Monorepo tools
            self.cursor.execute("SELECT COUNT(*) FROM mcp_tools WHERE is_monorepo_tool = true")
            monorepo_tools = self.cursor.fetchone()[0]

            # Single-tool repos
            self.cursor.execute("SELECT COUNT(*) FROM mcp_tools WHERE is_monorepo_tool = false")
            single_tools = self.cursor.fetchone()[0]

            # Most common tool names
            self.cursor.execute("""
                SELECT tool_name, COUNT(*) as impl_count, SUM(occurrence_count) as total_occurrences
                FROM mcp_tools
                GROUP BY tool_name
                HAVING COUNT(*) > 1
                ORDER BY impl_count DESC
                LIMIT 10
            """)
            common_tools = self.cursor.fetchall()

            # Sample monorepo
            self.cursor.execute("""
                SELECT r.github_url, COUNT(t.id) as tool_count
                FROM mcp_repositories r
                JOIN mcp_tools t ON t.repository_id = r.id
                WHERE t.is_monorepo_tool = true
                GROUP BY r.github_url
                ORDER BY tool_count DESC
                LIMIT 5
            """)
            top_monorepos = self.cursor.fetchall()

            print("\n" + "="*60)
            print("TOOL STATISTICS")
            print("="*60)
            print(f"Total tool implementations: {total_tools}")
            print(f"  Monorepo tools: {monorepo_tools}")
            print(f"  Single-tool repos: {single_tools}")

            if common_tools:
                print("\nMost implemented tool names:")
                for tool_name, impl_count, total_occur in common_tools:
                    print(f"  {tool_name}: {impl_count} implementations ({total_occur} total occurrences)")

            if top_monorepos:
                print("\nTop monorepos by tool count:")
                for url, count in top_monorepos:
                    repo_name = url.split('/')[-2] + '/' + url.split('/')[-1]
                    print(f"  {repo_name}: {count} tools")

        except psycopg2.Error as e:
            print(f"❌ Failed to get statistics: {e}")


def main():
    """Main function to populate mcp_tools table."""
    print("\n" + "="*60)
    print("MCP TOOLS POPULATION")
    print("="*60)

    # Initialize populator
    populator = MCPToolsPopulator()

    # Connect to database
    if not populator.connect():
        print("Failed to connect to database. Exiting.")
        return 1

    try:
        # Analyze JSON data
        json_file = '/mnt/prod/mcp/mcp_repositories.json'
        combo_counts, monorepos, stats = populator.analyze_json_data(json_file)

        # Print analysis results
        print("\n📊 Analysis Results:")
        print(f"  Total JSON entries: {stats['total_entries']:,}")
        print(f"  Unique repositories: {stats['unique_repos']:,}")
        print(f"  Unique tool names: {stats['unique_tools']:,}")
        print(f"  Unique (repo, tool) combinations: {stats['unique_combos']:,}")
        print(f"  Monorepos: {stats['monorepo_count']}")
        print(f"  Tools in monorepos: {stats['monorepo_tools']}")
        print(f"  Single-tool repos: {stats['single_tool_repos']}")

        # Populate tools
        populator.populate_tools(combo_counts, monorepos)

        # Show final statistics
        populator.get_statistics()

        print("\n✅ Tool population complete!")
        return 0

    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    finally:
        populator.close()


if __name__ == "__main__":
    sys.exit(main())