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
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('snowflake_mcp')

# Load environment variables from .env file
load_dotenv()

# Define the allowed base path for CSV exports, defaulting to /export
# This directory MUST be mounted as a volume in Docker.
EXPORT_BASE_PATH = os.getenv("EXPORT_BASE_PATH", "/export")
if not os.path.exists(EXPORT_BASE_PATH):
    try:
        os.makedirs(EXPORT_BASE_PATH)
        logger.info(f"Created export directory: {EXPORT_BASE_PATH}")
    except OSError as e:
        logger.error(f"Failed to create export directory {EXPORT_BASE_PATH}: {e}. CSV exports will likely fail.")
elif not os.path.isdir(EXPORT_BASE_PATH):
    logger.error(f"Configured EXPORT_BASE_PATH '{EXPORT_BASE_PATH}' exists but is not a directory. CSV exports will likely fail.")
else:
    logger.info(f"Using export base path: {EXPORT_BASE_PATH}")

class SnowflakeConnection:
    """
    Snowflake database connection management class
    """
    def __init__(self):
        # Initialize configuration from environment variables
        self.config = {
            "user": os.getenv("SNOWFLAKE_USER"),
            "account": os.getenv("SNOWFLAKE_ACCOUNT"),
            "database": os.getenv("SNOWFLAKE_DATABASE"),
            "warehouse": os.getenv("SNOWFLAKE_WAREHOUSE"),
        }
        
        # Log authentication configuration start
        logger.info("=== CONFIGURING AUTHENTICATION ===")
        
        # Check authentication methods available
        private_key_file = os.getenv("SNOWFLAKE_PRIVATE_KEY_FILE")
        private_key_passphrase = os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE")
        
        # Treat empty string passphrase as None
        if private_key_passphrase == "" or private_key_passphrase is None or (isinstance(private_key_passphrase, str) and private_key_passphrase.strip() == ""):
            private_key_passphrase = None
            logger.info("No passphrase provided or empty passphrase detected, treating as None")
        
        password = os.getenv("SNOWFLAKE_PASSWORD")
        
        # Priority 1: Key pair authentication (always preferred if available)
        if private_key_file:
            # First, check if the file exists
            if not os.path.exists(private_key_file):
                logger.error(f"Private key file does not exist: {private_key_file}")
                logger.info("Will try password authentication instead")
                
                # Fallback to password authentication
                if password:
                    self.config["password"] = password
                    logger.info("SELECTED AUTH: PASSWORD (fallback)")
                    logger.info("Using password authentication as fallback")
                else:
                    logger.error("No password available for fallback. Authentication will fail.")
            else:
                # Private key file exists, use key pair authentication
                if private_key_passphrase is not None:
                    logger.info("SELECTED AUTH: KEY PAIR WITH PASSPHRASE")
                    logger.info(f"Key file: {private_key_file}")
                else:
                    logger.info("SELECTED AUTH: KEY PAIR WITHOUT PASSPHRASE")
                    logger.info(f"Key file: {private_key_file}")
                    # Ensure passphrase is None
                    private_key_passphrase = None
                
                # Try to setup key pair authentication
                auth_success = self._setup_key_pair_auth(private_key_file, private_key_passphrase)
                
                # If key pair auth failed for any reason, try password as fallback
                if not auth_success:
                    logger.warning("Failed to set up key pair authentication")
                    
                    # Only use password fallback if available
                    if password:
                        logger.info("FALLBACK AUTH: PASSWORD")
                        logger.info("Using password authentication as fallback")
                        self.config["password"] = password
                    else:
                        logger.error("No password available for fallback after key auth failure")
                        logger.error("Authentication will likely fail")
        
        # Priority 2: Password authentication (if no key is available)
        elif password:
            self.config["password"] = password
            logger.info("SELECTED AUTH: PASSWORD")
            logger.info("Using password authentication (no key file configured)")
        
        # No authentication method available
        else:
            logger.error("NO AUTHENTICATION METHOD AVAILABLE")
            logger.error("Please configure either a private key or password")
        
        # Log authentication configuration end
        logger.info("=== AUTHENTICATION CONFIGURED ===")
        
        self.conn: Optional[snowflake.connector.SnowflakeConnection] = None
        
        # Log config (excluding sensitive info)
        safe_config = {k: v for k, v in self.config.items() 
                      if k not in ['password', 'private_key', 'private_key_passphrase']}
        logger.info(f"Initialized with config: {json.dumps(safe_config)}")
        # Store the base path for exports
        self.export_base_path = EXPORT_BASE_PATH
        if not self.export_base_path:
             logger.warning("EXPORT_BASE_PATH is not set. CSV export functionality might be limited or fail.")
        elif not os.path.isdir(self.export_base_path):
             logger.warning(f"Export base path '{self.export_base_path}' is not a valid directory. CSV exports might fail.")
    
    def _setup_key_pair_auth(self, private_key_file: str, passphrase: str = None) -> bool:
        """
        Set up key pair authentication
        
        Args:
            private_key_file (str): Path to private key file
            passphrase (str, optional): Passphrase for the private key (NOT the Snowflake password)
            
        Returns:
            bool: True if key pair authentication was set up successfully, False otherwise
        """
        try:
            # Read private key file
            with open(private_key_file, "rb") as key_file:
                private_key = key_file.read()
                
            # Try to load the key using snowflake's recommended approach
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            
            logger.info(f"Loading private key from {private_key_file}")
            
            # Only pass passphrase if it's not None and not empty
            if passphrase is not None and passphrase.strip() != "":
                logger.info("Using passphrase to decrypt private key")
                p_key = load_pem_private_key(
                    private_key,
                    password=passphrase.encode(),
                    backend=default_backend()
                )
                # Add passphrase to config for encrypted keys
                self.config["private_key_passphrase"] = passphrase
                logger.info("Private key with passphrase loaded successfully")
            else:
                logger.info("Using private key without passphrase")
                p_key = load_pem_private_key(
                    private_key,
                    password=None,
                    backend=default_backend()
                )
                logger.info("Private key without passphrase loaded successfully")
            
            # Convert key to DER format
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
            pkb = p_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
            
            # Add private key to config (required for Snowflake key pair auth)
            self.config["private_key"] = pkb
                
            return True
                
        except Exception as e:
            logger.error(f"Error setting up key pair authentication: {str(e)}")
            logger.error("Details:", exc_info=True)
            return False
    
    def ensure_connection(self) -> snowflake.connector.SnowflakeConnection:
        """
        Ensure database connection is available, create new connection if it doesn't exist or is disconnected
        """
        try:
            # Check if connection needs to be re-established
            if self.conn is None:
                logger.info("Creating new Snowflake connection...")
                
                # Determine the auth method we're actually using
                auth_method = "UNKNOWN"
                if "private_key" in self.config:
                    auth_method = "KEY_PAIR"
                    if "private_key_passphrase" in self.config and self.config.get("private_key_passphrase") is not None:
                        auth_method += "_WITH_PASSPHRASE"
                    else:
                        auth_method += "_WITHOUT_PASSPHRASE"
                elif "password" in self.config:
                    auth_method = "PASSWORD"
                
                logger.info(f"Connecting with authentication method: {auth_method}")
                
                # Attempt connection
                self.conn = snowflake.connector.connect(
                    **self.config,
                    client_session_keep_alive=True,
                    network_timeout=15,
                    login_timeout=15
                )
                
                self.conn.cursor().execute("ALTER SESSION SET TIMEZONE = 'UTC'")
                
                # Log successful connection details
                logger.info(f"=== CONNECTION ESTABLISHED ===")
                logger.info(f"Authentication Method: {auth_method}")
                logger.info(f"Connected to: {self.config['account']}")
                logger.info(f"User: {self.config['user']}")
                logger.info(f"Database: {self.config['database']}")
                logger.info(f"Warehouse: {self.config['warehouse']}")
                logger.info(f"==============================")
                
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

    def export_to_csv(self, query: str, relative_file_path: str) -> Dict[str, Any]:
        """
        Execute SQL query and export results to a CSV file within the configured base path.

        Args:
            query (str): SQL query statement.
            relative_file_path (str): The relative path and filename for the CSV file (e.g., 'my_report.csv' or 'subdir/data.csv').
                                      This will be joined with the EXPORT_BASE_PATH.

        Returns:
            Dict[str, Any]: A dictionary containing the full path to the exported file and the number of rows exported.

        Raises:
            ValueError: If the relative_file_path attempts to escape the export base path or is invalid.
            FileNotFoundError: If the export base path does not exist or is not a directory.
            Exception: Propagates exceptions from database query or file writing.
        """
        start_time = time.time()
        logger.info(f"Exporting query to CSV: {query[:200]}...")
        logger.info(f"Target relative path: {relative_file_path}")

        if not self.export_base_path or not os.path.isdir(self.export_base_path):
             error_msg = f"Export base path '{self.export_base_path}' is not configured or not a valid directory."
             logger.error(error_msg)
             raise FileNotFoundError(error_msg)

        # Prevent path traversal attacks and ensure the path is relative
        if relative_file_path.startswith('/') or '..' in relative_file_path:
            error_msg = f"Invalid relative file path: '{relative_file_path}'. Must not start with '/' or contain '..'."
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Construct the full path safely
        full_path = os.path.abspath(os.path.join(self.export_base_path, relative_file_path))

        # Double-check it's still within the base path after resolving
        if not full_path.startswith(os.path.abspath(self.export_base_path)):
             error_msg = f"Resolved path '{full_path}' is outside the allowed export directory '{self.export_base_path}'."
             logger.error(error_msg)
             raise ValueError(error_msg)

        # Ensure the target directory exists
        target_dir = os.path.dirname(full_path)
        if not os.path.exists(target_dir):
            try:
                os.makedirs(target_dir)
                logger.info(f"Created directory for export: {target_dir}")
            except OSError as e:
                logger.error(f"Failed to create directory {target_dir}: {e}")
                raise

        logger.info(f"Full export path: {full_path}")

        try:
            conn = self.ensure_connection()
            with conn.cursor() as cursor:
                # Execute the query (read operations only for export)
                 if any(query.strip().upper().startswith(word) for word in ['INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']):
                     raise ValueError("Only SELECT queries can be exported to CSV.")

                 cursor.execute(query)

                 if cursor.description:
                    # Fetch data using pandas for efficient CSV writing
                    df = cursor.fetch_pandas_all()
                    row_count = len(df)

                    # Write DataFrame to CSV
                    df.to_csv(full_path, index=False)

                    execution_time = time.time() - start_time
                    logger.info(f"Exported {row_count} rows to '{full_path}' in {execution_time:.2f}s")
                    return {
                        "message": f"Successfully exported {row_count} rows.",
                        "file_path": full_path, # Return the full path on the server's filesystem
                        "rows_exported": row_count
                    }
                 else:
                    # Handle queries that return no description (e.g., USE DATABASE)
                    logger.info("Query did not return results to export.")
                    # Create an empty file or return specific message? Let's return 0 rows.
                    # Create an empty file to signify the query ran but had no output columns/rows
                    pd.DataFrame().to_csv(full_path, index=False)
                    execution_time = time.time() - start_time
                    logger.info(f"Exported 0 rows (query returned no data/columns) to '{full_path}' in {execution_time:.2f}s")

                    return {
                        "message": "Query executed but returned no data/columns to export.",
                        "file_path": full_path,
                        "rows_exported": 0
                    }

        except snowflake.connector.errors.ProgrammingError as e:
            logger.error(f"SQL Error during export: {str(e)}")
            logger.error(f"Error Code: {getattr(e, 'errno', 'unknown')}")
            raise
        except Exception as e:
            logger.error(f"Error during CSV export: {str(e)}")
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
                    description="Execute a SQL query on Snowflake and return results directly.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "SQL query to execute (SELECT, INSERT, UPDATE, etc.)."
                            }
                        },
                        "required": ["query"]
                    }
                ),
                Tool( # Add the new tool definition
                    name="export_query_to_csv",
                    description=f"Execute a SELECT SQL query on Snowflake and export the results to a CSV file within the designated export directory ('{EXPORT_BASE_PATH}' on the server).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "SELECT SQL query to execute."
                            },
                            "relative_file_path": {
                                "type": "string",
                                "description": f"The relative path and filename for the CSV file (e.g., 'my_data.csv' or 'reports/quarterly.csv'). This will be saved relative to the server's base export path: {EXPORT_BASE_PATH}. Do not use '..' or start with '/'."
                            }
                        },
                        "required": ["query", "relative_file_path"]
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
            elif name == "export_query_to_csv": # Handle the new tool call
                start_time = time.time()
                try:
                    query = arguments["query"]
                    relative_path = arguments["relative_file_path"]
                    result = self.db.export_to_csv(query, relative_path)
                    execution_time = time.time() - start_time

                    return [TextContent(
                        type="text",
                        text=f"Export successful (execution time: {execution_time:.2f}s):\n{json.dumps(result, indent=2)}"
                    )]
                except (ValueError, FileNotFoundError) as e: # Catch specific configuration/path errors
                     error_message = f"Error preparing export: {str(e)}"
                     logger.error(error_message)
                     return [TextContent(type="text", text=error_message)]
                except Exception as e: # Catch database or file writing errors
                    error_message = f"Error exporting query to CSV: {str(e)}"
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