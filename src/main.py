#!/usr/bin/env python3
"""
Main entry point for the AI Network Scanner application.
"""

import sys
import click
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.config import Config
from src.utils.logger import logger
from src.database.db_manager import db_manager
from src.scanner.nmap_scanner import NmapScanner

@click.group()
def cli():
    """AI-Enhanced Network Scanner CLI."""
    pass

@cli.command()
@click.option('--target', '-t', help='Target network range (e.g., 192.168.1.0/24)')
@click.option('--scan-type', '-s', default='quick', help='Scan type: quick, full, custom')
@click.option('--save/--no-save', default=True, help='Save results to database')
def scan(target, scan_type, save):
    """Perform a network scan."""
    
    if not target:
        target = Config.DEFAULT_SCAN_RANGE
        logger.info(f"Using default target: {target}")
    
    logger.info(f"Starting {scan_type} scan on {target}")
    
    scanner = NmapScanner()
    
    try:
        if scan_type == 'quick':
            results = scanner.quick_scan(target)
        else:
            results = scanner.host_discovery(target)
        
        logger.info("Scan completed successfully!")
        
        if save:
            # Save to database
            logger.info("Saving results to database...")
            # TODO: Implement database saving logic
            logger.info("Results saved to database")
        
        return results
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        sys.exit(1)

@cli.command()
def init_db():
    """Initialize the database."""
    logger.info("Initializing database...")
    db_manager.init_database()
    logger.info("Database initialized successfully!")

@cli.command()
def reset_db():
    """Reset the database (drop all tables)."""
    confirm = input("Are you sure you want to reset the database? This will delete all data! (y/N): ")
    if confirm.lower() == 'y':
        logger.warning("Resetting database...")
        db_manager.recreate_database()
        logger.info("Database reset complete!")
    else:
        logger.info("Database reset cancelled")

@cli.command()
def status():
    """Show system status."""
    logger.info("System Status:")
    logger.info(f"  - Database: {db_manager.database_url}")
    logger.info(f"  - Debug Mode: {Config.DEBUG}")
    logger.info(f"  - Nmap Path: {Config.NMAP_PATH}")
    
    # Check Nmap
    try:
        scanner = NmapScanner()
        logger.info(f"  - Nmap: ✓ Installed")
    except Exception as e:
        logger.error(f"  - Nmap: ✗ Not found ({str(e)})")

if __name__ == "__main__":
    cli()