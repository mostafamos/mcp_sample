from mcp.server.fastmcp import FastMCP
import time
import signal
import sys
import datetime
import os
import logging
import re
from pathlib import Path
from typing import Optional, Dict, Any, Union

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("text-saver-mcp")

# Configuration
MAX_TEXT_SIZE = 10 * 1024 * 1024  # 10MB max file size
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ALLOWED_SAVE_DIR = SCRIPT_DIR
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_\-\.]*$')

class TextSaverError(Exception):
    """Base exception for text saver errors"""
    pass

class InvalidFilenameError(TextSaverError):
    """Exception raised when filename is invalid or unsafe"""
    pass

class TextTooLargeError(TextSaverError):
    """Exception raised when text exceeds maximum size"""
    pass

# Handle SIGINT (Ctrl+C) gracefully
def signal_handler(sig, frame):
    logger.info("Received signal %s. Shutting down text saver server gracefully...", sig)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)  # Also handle SIGTERM

def validate_filename(filename: str) -> bool:
    """
    Validate that a filename is safe and doesn't contain path traversal attempts.
    
    Args:
        filename: The filename to validate
        
    Returns:
        bool: True if filename is safe, False otherwise
    """
    # Check for path traversal attempts
    if os.path.isabs(filename) or '..' in filename or '/' in filename or '\\' in filename:
        return False
        
    # Check filename matches safe pattern
    return bool(SAFE_FILENAME_PATTERN.match(filename))

def sanitize_path(filename: str) -> str:
    """
    Sanitize a filename by removing unsafe characters and ensuring it's within allowed directory.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        str: A sanitized, safe filename
    """
    # Get just the base filename without any path
    base_filename = os.path.basename(filename)
    
    # Replace any unsafe characters with underscores
    safe_filename = ''.join(c if SAFE_FILENAME_PATTERN.match(c) else '_' for c in base_filename)
    
    # If filename is empty after sanitization, use a default
    if not safe_filename:
        safe_filename = "file.txt"
        
    return safe_filename

# Create an MCP server with increased timeout
mcp = FastMCP(
    name="text-saver",
    host="127.0.0.1",
    port=8080,
    timeout=30  # Increase timeout to 30 seconds
)

@mcp.tool()
def save_text(text: str, filename: Optional[str] = None) -> Union[str, Dict[str, Any]]:
    """
    Save text to a file with security and error handling.
    
    This tool saves the provided text content to a file on the local filesystem.
    If no filename is specified, it generates a timestamped filename automatically.
    
    Args:
        text: The text content to save to the file
        filename: Optional filename. If not provided, will use timestamp
                 in format: 'year-month-date-hour-minute-second.txt'
    
    Returns:
        A success message with the path to the saved file, or an error message
        
    Raises:
        TextTooLargeError: If the text exceeds the maximum allowed size
        InvalidFilenameError: If the provided filename is invalid or unsafe
        IOError: If there's an issue writing to the file
    """
    try:
        # Validate input
        if not isinstance(text, str):
            return {"status": "error", "message": "Error: Text must be a string"}
            
        # Check text size
        if len(text.encode('utf-8')) > MAX_TEXT_SIZE:
            raise TextTooLargeError(f"Text size exceeds maximum allowed ({MAX_TEXT_SIZE} bytes)")
            
        # Generate or validate filename
        if not filename:
            # Generate timestamp filename
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
            filename = timestamp + ".txt"
        else:
            # If filename is provided, validate it
            if not validate_filename(filename):
                logger.warning("Unsafe filename attempted: %s", filename)
                filename = sanitize_path(filename)
                logger.info("Sanitized filename to: %s", filename)
        
        # Make sure filename has .txt extension
        if not filename.endswith('.txt'):
            filename += '.txt'
        
        # Create the directory if it doesn't exist
        Path(ALLOWED_SAVE_DIR).mkdir(parents=True, exist_ok=True)
        
        # Create full path within allowed directory
        filepath = os.path.join(ALLOWED_SAVE_DIR, filename)
        
        # Log the operation
        logger.info(f"Current working directory: {os.getcwd()}")
        logger.info(f"Script directory: {os.path.dirname(os.path.abspath(__file__))}")
        logger.info(f"Attempting to save to: {filepath}")
        
        # Save the text to the file
        try:
            with open(filepath, 'w', encoding='utf-8') as file:
                file.write(text)
        except PermissionError:
            return {"status": "error", "message": f"Permission denied when writing to file: {filename}"}
        except IOError as e:
            return {"status": "error", "message": f"IO error when writing to file: {str(e)}"}
        
        # Get absolute path for better user feedback
        abs_path = os.path.abspath(filepath)
        
        # Verify file was written successfully
        if not os.path.exists(filepath):
            return {"status": "error", "message": f"File was not created successfully at: {abs_path}"}
            
        # Verify file size
        file_size = os.path.getsize(filepath)
        if file_size == 0 and len(text) > 0:
            return {"status": "error", "message": f"File was created but appears to be empty: {abs_path}"}
        
        return {
            "status": "success", 
            "message": f"Successfully saved text to file: {abs_path}",
            "path": abs_path,
            "size": file_size,
            "filename": filename
        }
        
    except TextTooLargeError as e:
        logger.error("Text too large error: %s", str(e))
        return {"status": "error", "message": str(e)}
    except InvalidFilenameError as e:
        logger.error("Invalid filename error: %s", str(e))
        return {"status": "error", "message": str(e)}
    except Exception as e:
        # Catch-all for unexpected errors
        logger.exception("Unexpected error saving text: %s", str(e))
        return {"status": "error", "message": f"Unexpected error: {str(e)}"}

def main() -> None:
    """Main entry point for the MCP server"""
    try:
        logger.info("Starting TextSaver MCP server 'text-saver' on 127.0.0.1:8080")
        logger.info("Saving files to directory: %s", ALLOWED_SAVE_DIR)
        logger.info("Maximum allowed file size: %d bytes", MAX_TEXT_SIZE)
        
        # Create the save directory if it doesn't exist
        Path(ALLOWED_SAVE_DIR).mkdir(parents=True, exist_ok=True)
        
        # Use this approach to keep the server running
        mcp.run(transport='stdio')
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
    except Exception as e:
        logger.exception("Error starting server: %s", str(e))
        # Sleep before exiting to give time for error logs
        time.sleep(5)
    finally:
        logger.info("Server shutdown complete")

if __name__ == "__main__":
    main() 
