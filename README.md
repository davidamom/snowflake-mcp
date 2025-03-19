# Snowflake MCP Service

A Model Context Protocol (MCP) server that provides Claude access to Snowflake databases.

![GitHub repo](https://img.shields.io/badge/GitHub-snowflake--mcp-blue)

This server implements the Model Context Protocol to allow Claude to:
- Execute SQL queries on Snowflake databases
- Automatically handle database connection lifecycle (connect, reconnect on timeout, close)
- Handle query results and errors
- Perform database operations safely

## Installation

1. Clone this repository
```bash
git clone https://github.com/davidamom/snowflake-mcp.git
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

## Configuration

### MCP Client Configuration Example

Add the following configuration to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "snowflake": {
      "command": "C:\\Users\\YourUsername\\path\\to\\python.exe",
      "args": ["C:\\path\\to\\snowflake-mcp\\server.py"]
    }
  }
}
```

Configuration parameters:
- `command`: Full path to your Python interpreter. Please modify this according to your Python installation location.
- `args`: Full path to the server script. Please modify this according to where you cloned the repository.

Example paths for different operating systems:

Windows:
```json
{
  "mcpServers": {
    "snowflake": {
      "command": "C:\\Users\\YourUsername\\anaconda3\\python.exe",
      "args": ["C:\\Path\\To\\snowflake-mcp\\server.py"]
    }
  }
}
```

MacOS/Linux:
```json
{
  "mcpServers": {
    "snowflake": {
      "command": "/usr/bin/python3",
      "args": ["/path/to/snowflake-mcp/server.py"]
    }
  }
}
```

### Snowflake Configuration

Create a `.env` file in the project root directory and add the following configuration:

```env
SNOWFLAKE_USER=your_username      # Your username
SNOWFLAKE_PASSWORD=your_password  # Your password
SNOWFLAKE_ACCOUNT=YourAccount.Region    # Example: MyOrg.US-WEST-2
SNOWFLAKE_DATABASE=your_database  # Your database
SNOWFLAKE_WAREHOUSE=your_warehouse # Your warehouse
```

## Connection Management

The server provides automatic connection management features:

- Automatic connection initialization
  - Creates connection when first query is received
  - Validates connection parameters

- Connection maintenance
  - Keeps track of connection state
  - Handles connection timeouts
  - Automatically reconnects if connection is lost

- Connection cleanup
  - Properly closes connections when server stops
  - Releases resources appropriately

## Usage

The server will start automatically with the Claude Desktop client. No manual startup is required. Once the server is running, Claude will be able to execute Snowflake queries.

For development testing, you can start the server manually using:

```bash
python server.py
```

Note: Manual server startup is not needed for normal use. The Claude Desktop client will automatically manage server startup and shutdown based on the configuration.

## Features

- Secure Snowflake database access
- Robust error handling and reporting
- Automatic connection management
- Query execution and result processing

## License

This project is licensed under the MIT License.