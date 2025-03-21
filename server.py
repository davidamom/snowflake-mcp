#!/usr/bin/env python
import os
import asyncio
import logging
import json
import time
import snowflake.connector
from dotenv import load_dotenv
import mcp.server.stdio
from mcp.server import Server
from mcp.types import Tool, ServerResult, TextContent
from contextlib import closing
from typing import Optional, Any, List, Dict

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('snowflake_mcp')

# Load environment variables from .env file
load_dotenv()

class SnowflakeConnection:
    """
    Snowflake database connection management class
    """
    def __init__(self):
        # Initialize base configuration from environment variables
        self.config = {
            "user": os.getenv("SNOWFLAKE_USER"),
            "account": os.getenv("SNOWFLAKE_ACCOUNT"),
            "database": os.getenv("SNOWFLAKE_DATABASE"),
            "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
        }
        
        # Determine authentication method
        private_key_file = os.getenv("SNOWFLAKE_PRIVATE_KEY_FILE")
        if private_key_file and os.path.exists(private_key_file):
            # Key pair authentication
            self._setup_key_pair_auth(private_key_file)
            logger.info("Using key pair authentication")
        else:
            # Password authentication
            self.config["password"] = os.getenv("SNOWFLAKE_PASSWORD")
            logger.info("Using password authentication")
            
        self.conn: Optional[snowflake.connector.SnowflakeConnection] = None
        
        # Log config (excluding sensitive info)
        safe_config = {k: v for k, v in self.config.items() 
                      if k not in ['password', 'private_key', 'private_key_passphrase']}
        logger.info(f"Initialized with config: {json.dumps(safe_config)}")
    
    def _setup_key_pair_auth(self, private_key_file: str):
        """
        Set up key pair authentication
        
        Args:
            private_key_file (str): Path to private key file
        """
        try:
            # Read private key file
            with open(private_key_file, "rb") as key_file:
                private_key = key_file.read()
                
            # Try to load the key using snowflake's recommended approach
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            
            logger.info(f"Attempting to load private key from {private_key_file}")
            p_key = load_pem_private_key(
                private_key,
                password=os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE").encode() if os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE") else None,
                backend=default_backend()
            )
            
            # Set private key to the properly loaded version
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
            pkb = p_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
            
            # Add to config (this is what Snowflake expects)
            self.config["private_key"] = pkb
            
            # Add passphrase if provided
            passphrase = os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE")
            if passphrase:
                self.config["private_key_passphrase"] = passphrase
                
        except Exception as e:
            logger.error(f"Error setting up key pair authentication: {str(e)}")
            logger.error("Details:", exc_info=True)
            # Fall back to password auth if key file can't be read
            self.config["password"] = os.getenv("SNOWFLAKE_PASSWORD")
            logger.info("Falling back to password authentication")
    
    def ensure_connection(self) -> snowflake.connector.SnowflakeConnection:
        """
        Ensure database connection is available, create new connection if it doesn't exist or is disconnected
        """
        try:
            # Check if connection needs to be re-established
            if self.conn is None:
                logger.info("Creating new Snowflake connection...")
                self.conn = snowflake.connector.connect(
                    **self.config,
                    client_session_keep_alive=True,
                    network_timeout=15,
                    login_timeout=15
                )
                self.conn.cursor().execute("ALTER SESSION SET TIMEZONE = 'UTC'")
                logger.info("New connection established and configured")
            
            # Test if connection is valid
            try:
                self.conn.cursor().execute("SELECT 1")
            except:
                logger.info("Connection lost, reconnecting...")
                self.conn = None
                return self.ensure_connection()
                
            return self.conn
        except Exception as e:
            logger.error(f"Connection error: {str(e)}")
            raise

    def execute_query(self, query: str) -> List[Dict[str, Any]]:
        """
        Execute SQL query and return results
        
        Args:
            query (str): SQL query statement
            
        Returns:
            List[Dict[str, Any]]: List of query results
        """
        start_time = time.time()
        logger.info(f"Executing query: {query[:200]}...")  # Log only first 200 characters
        
        try:
            conn = self.ensure_connection()
            with conn.cursor() as cursor:
                # For write operations use transaction
                if any(query.strip().upper().startswith(word) for word in ['INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']):
                    cursor.execute("BEGIN")
                    try:
                        cursor.execute(query)
                        conn.commit()
                        logger.info(f"Write query executed in {time.time() - start_time:.2f}s")
                        return [{"affected_rows": cursor.rowcount}]
                    except Exception as e:
                        conn.rollback()
                        raise
                else:
                    # Read operations
                    cursor.execute(query)
                    if cursor.description:
                        columns = [col[0] for col in cursor.description]
                        rows = cursor.fetchall()
                        results = [dict(zip(columns, row)) for row in rows]
                        logger.info(f"Read query returned {len(results)} rows in {time.time() - start_time:.2f}s")
                        return results
                    return []
                
        except snowflake.connector.errors.ProgrammingError as e:
            logger.error(f"SQL Error: {str(e)}")
            logger.error(f"Error Code: {getattr(e, 'errno', 'unknown')}")
            raise
        except Exception as e:
            logger.error(f"Query error: {str(e)}")
            logger.error(f"Error type: {type(e).__name__}")
            raise

    def close(self):
        """
        Close database connection
        """
        if self.conn:
            try:
                self.conn.close()
                logger.info("Connection closed")
            except Exception as e:
                logger.error(f"Error closing connection: {str(e)}")
            finally:
                self.conn = None

class SnowflakeMCPServer(Server):
    """
    Snowflake MCP server class, handles client interactions
    """
    def __init__(self):
        super().__init__(name="snowflake-mcp-server")
        self.db = SnowflakeConnection()
        logger.info("SnowflakeMCPServer initialized")

        @self.list_tools()
        async def handle_tools():
            """
            Return list of available tools
            """
            return [
                Tool(
                    name="execute_query",
                    description="Execute a SQL query on Snowflake",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "SQL query to execute"
                            }
                        },
                        "required": ["query"]
                    }
                )
            ]

        @self.call_tool()
        async def handle_call_tool(name: str, arguments: dict):
            """
            Handle tool call requests
            
            Args:
                name (str): Tool name
                arguments (dict): Tool arguments
                
            Returns:
                list[TextContent]: Execution results
            """
            if name == "execute_query":
                start_time = time.time()
                try:
                    result = self.db.execute_query(arguments["query"])
                    execution_time = time.time() - start_time
                    
                    return [TextContent(
                        type="text",
                        text=f"Results (execution time: {execution_time:.2f}s):\n{result}"
                    )]
                except Exception as e:
                    error_message = f"Error executing query: {str(e)}"
                    logger.error(error_message)
                    return [TextContent(
                        type="text",
                        text=error_message
                    )]

    def __del__(self):
        """
        Clean up resources, close database connection
        """
        if hasattr(self, 'db'):
            self.db.close()

async def main():
    """
    Main function, starts server and handles requests
    """
    try:
        server = SnowflakeMCPServer()
        initialization_options = server.create_initialization_options()
        logger.info("Starting server")
        
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await server.run(
                read_stream,
                write_stream,
                initialization_options
            )
    except Exception as e:
        logger.critical(f"Server failed: {str(e)}", exc_info=True)
        raise
    finally:
        logger.info("Server shutting down")

if __name__ == "__main__":
    asyncio.run(main())