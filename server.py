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
        
        # Auth decision logs
        logger.info("🔐 Determining authentication method...")
        
        # Determine authentication method
        private_key_file = os.getenv("SNOWFLAKE_PRIVATE_KEY_FILE")
        password = os.getenv("SNOWFLAKE_PASSWORD")
        
        # Log available auth methods
        auth_methods = []
        if private_key_file:
            auth_methods.append("key pair")
        if password:
            auth_methods.append("password")
            
        if auth_methods:
            logger.info(f"🔐 Available authentication methods: {', '.join(auth_methods)}")
        else:
            logger.warning("⚠️ No authentication methods configured. Connection will likely fail.")
            
        # Try key pair auth first (preferred)
        if private_key_file and os.path.exists(private_key_file):
            logger.info(f"🔑 Found private key file at {private_key_file}")
            if self._setup_key_pair_auth(private_key_file):
                logger.info("✅ Using key pair authentication (preferred method)")
            else:
                # If key pair auth setup failed, fall back to password if available
                if password:
                    logger.info("⚠️ Falling back to password authentication")
                    self.config["password"] = password
                else:
                    logger.error("❌ Key pair authentication failed and no password provided as fallback")
        else:
            # No key or key file doesn't exist, try password auth
            if private_key_file and not os.path.exists(private_key_file):
                logger.warning(f"⚠️ Private key file not found at {private_key_file}")
                
            if password:
                logger.info("🔑 Using password authentication")
                self.config["password"] = password
            else:
                logger.error("❌ No valid authentication methods available - connection will fail")
            
        self.conn: Optional[snowflake.connector.SnowflakeConnection] = None
        
        # Log config (excluding sensitive info)
        safe_config = {k: v for k, v in self.config.items() 
                      if k not in ['password', 'private_key', 'private_key_passphrase']}
        logger.info(f"Initialized with config: {json.dumps(safe_config)}")
        
        # Log authentication method used
        if "private_key" in self.config:
            logger.info("🔒 Final authentication method: KEY PAIR")
        elif "password" in self.config:
            logger.info("🔒 Final authentication method: PASSWORD")
        else:
            logger.error("❌ No authentication method configured")
        
        # Validate connection on startup
        self.test_connection()
    
    def test_connection(self):
        """
        Test the connection to Snowflake and log detailed information
        """
        # Determine authentication method for logging
        auth_method = "UNKNOWN"
        if "private_key" in self.config:
            auth_method = "KEY PAIR"
        elif "password" in self.config:
            auth_method = "PASSWORD"
            
        logger.info(f"🔍 Testing connection to Snowflake using {auth_method} authentication...")
        try:
            conn = self.ensure_connection()
            with conn.cursor() as cursor:
                # Test basic connection
                cursor.execute("SELECT CURRENT_USER(), CURRENT_ROLE(), CURRENT_DATABASE(), CURRENT_WAREHOUSE()")
                row = cursor.fetchone()
                logger.info("✅ Connection successful!")
                logger.info(f"👤 Authenticated as: {row[0]}")
                logger.info(f"🔑 Current role: {row[1]}")
                logger.info(f"🗄️ Current database: {row[2]}")
                logger.info(f"⚙️ Current warehouse: {row[3]}")
                
                # Get session info
                cursor.execute("SELECT current_session()")
                session_id = cursor.fetchone()[0]
                logger.info(f"🔄 Session ID: {session_id}")
                
                # Get server version
                cursor.execute("SELECT current_version()")
                version = cursor.fetchone()[0]
                logger.info(f"📊 Snowflake version: {version}")
                
                # Confirm authentication method
                logger.info(f"🔐 Successfully connected using {auth_method} authentication")
                
                # Return True for successful connection
                return True
        except Exception as e:
            logger.error(f"❌ Connection test failed: {str(e)}")
            logger.error(f"Error type: {type(e).__name__}")
            if isinstance(e, snowflake.connector.errors.ProgrammingError):
                logger.error(f"Error code: {getattr(e, 'errno', 'unknown')}")
            # Return False for failed connection
            return False
    
    def _setup_key_pair_auth(self, private_key_file: str) -> bool:
        """
        Set up key pair authentication
        
        Args:
            private_key_file (str): Path to private key file
            
        Returns:
            bool: True if key pair auth was successfully configured, False otherwise
        """
        try:
            # Read private key file
            with open(private_key_file, "rb") as key_file:
                private_key = key_file.read()
                
            # Try to load the key using snowflake's recommended approach
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            
            logger.info(f"Attempting to load private key from {private_key_file}")
            
            # Get passphrase if provided
            passphrase = os.getenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE")
            
            # Decide whether to use passphrase based on if it's provided
            if passphrase:
                logger.info("Passphrase provided, attempting to use it with private key")
                p_key = load_pem_private_key(
                    private_key,
                    password=passphrase.encode(),
                    backend=default_backend()
                )
                logger.info("Private key loaded successfully with passphrase")
                
                # Add passphrase to config
                self.config["private_key_passphrase"] = passphrase
            else:
                logger.info("No passphrase provided, attempting to load unencrypted private key")
                p_key = load_pem_private_key(
                    private_key,
                    password=None,
                    backend=default_backend()
                )
                logger.info("Unencrypted private key loaded successfully")
            
            # Convert the key to the format Snowflake expects
            from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
            pkb = p_key.private_bytes(
                encoding=Encoding.DER,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
            
            # Add to config (this is what Snowflake expects)
            self.config["private_key"] = pkb
                
            # Key setup was successful
            if passphrase:
                logger.info("✅ Private key with passphrase successfully configured")
            else:
                logger.info("✅ Unencrypted private key successfully configured")
            return True
                
        except Exception as e:
            logger.error(f"❌ Error setting up key pair authentication: {str(e)}")
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
        query_type = "unknown"
        
        # Determine query type
        if query.strip().upper().startswith('SELECT'):
            query_type = "SELECT"
        elif query.strip().upper().startswith('SHOW'):
            query_type = "SHOW"
        elif query.strip().upper().startswith('DESCRIBE'):
            query_type = "DESCRIBE"
        elif query.strip().upper().startswith('INSERT'):
            query_type = "INSERT"
        elif query.strip().upper().startswith('UPDATE'):
            query_type = "UPDATE"
        elif query.strip().upper().startswith('DELETE'):
            query_type = "DELETE"
        elif query.strip().upper().startswith('CREATE'):
            query_type = "CREATE"
        elif query.strip().upper().startswith('DROP'):
            query_type = "DROP"
        elif query.strip().upper().startswith('ALTER'):
            query_type = "ALTER"
        
        logger.info(f"📝 Executing {query_type} query: {query[:200]}..." + ("..." if len(query) > 200 else ""))
        
        try:
            conn = self.ensure_connection()
            with conn.cursor() as cursor:
                # For write operations use transaction
                if any(query.strip().upper().startswith(word) for word in ['INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']):
                    cursor.execute("BEGIN")
                    try:
                        cursor.execute(query)
                        conn.commit()
                        execution_time = time.time() - start_time
                        logger.info(f"✅ Write query executed successfully in {execution_time:.2f}s")
                        return [{"affected_rows": cursor.rowcount}]
                    except Exception as e:
                        conn.rollback()
                        logger.error(f"❌ Write query failed, transaction rolled back: {str(e)}")
                        raise
                else:
                    # Read operations
                    cursor.execute(query)
                    execution_time = time.time() - start_time
                    
                    if cursor.description:
                        columns = [col[0] for col in cursor.description]
                        rows = cursor.fetchall()
                        results = [dict(zip(columns, row)) for row in rows]
                        logger.info(f"✅ Read query returned {len(results)} rows in {execution_time:.2f}s")
                        
                        # Log a preview of results if not too many
                        if len(results) > 0 and len(results) <= 5:
                            logger.info(f"📊 Result preview: {json.dumps(results[:3], default=str)}")
                        
                        return results
                    
                    logger.info(f"✅ Query executed successfully (no rows returned) in {execution_time:.2f}s")
                    return []
                
        except snowflake.connector.errors.ProgrammingError as e:
            logger.error(f"❌ SQL Error: {str(e)}")
            logger.error(f"Error Code: {getattr(e, 'errno', 'unknown')}")
            raise
        except Exception as e:
            logger.error(f"❌ Query error: {str(e)}")
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
        # Print banner
        print("""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║  🌨️  Snowflake MCP Server                                 ║
║  Model Context Protocol for Snowflake Data Access          ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
        """)
        
        logger.info("Starting Snowflake MCP Server...")
        logger.info(f"Environment: {os.environ.get('ENV', 'development')}")
        logger.info(f"Python version: {os.sys.version}")
        
        # Create server instance
        server = SnowflakeMCPServer()
        initialization_options = server.create_initialization_options()
        
        # Connection health check
        if hasattr(server.db, 'conn') and server.db.conn:
            logger.info("✅ Snowflake connection established and ready")
        else:
            logger.warning("⚠️ Snowflake connection not ready - will attempt reconnection when needed")
        
        logger.info("Starting MCP server loop...")
        
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            # Log that we're ready to accept connections
            logger.info("🚀 MCP Server ready to accept connections")
            
            await server.run(
                read_stream,
                write_stream,
                initialization_options
            )
    except Exception as e:
        logger.critical(f"❌ Server failed: {str(e)}", exc_info=True)
        raise
    finally:
        logger.info("🛑 Server shutting down")

if __name__ == "__main__":
    asyncio.run(main())