#!/usr/bin/env python3
"""
=============================================================================
 MAGENTO SECURITY INCIDENT RESPONSE SCANNER (CENTRALIZED SERVICE)
 ---------------------------------------------------------------
 Usage:
   sudo python3 security_scanner.py --config config.json
   sudo python3 security_scanner.py /path/to/project
=============================================================================
"""

import os
import sys
import json
import argparse
from pathlib import Path
from core_scanner import SecurityScanner
from utils import Colors, log_info, log_critical

def load_config(config_path):
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"{Colors.RED}Error loading config file: {e}{Colors.RESET}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='Magento Security Incident Response Scanner (Centralized Service)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('project_root', nargs='?', help='Path to a single Magento project root')
    parser.add_argument('--config', '-c', help='Path to JSON configuration file for multiple projects')
    parser.add_argument('--email', '-e', help='Target email for single-project scan (ignored if using --config)')

    args = parser.parse_args()

    if os.geteuid() != 0:
        print(f"{Colors.YELLOW}[WARNING] Running without sudo. Some checks may fail.{Colors.RESET}")
        print()

    # Case 1: Multiple projects via config.json
    if args.config:
        config_data = load_config(args.config)
        projects = config_data.get('projects', [])
        smtp_config = config_data.get('smtp', {})
        report_dir = config_data.get('report_directory', './reports')
        
        if not projects:
            print(f"{Colors.YELLOW}No projects defined in config file.{Colors.RESET}")
            return

        os.makedirs(report_dir, exist_ok=True)
        log_info(f"Starting batch scan of {len(projects)} projects...")
        log_info(f"Reports will be saved to: {report_dir}")

        for project_path in projects:
            if not os.path.isdir(project_path):
                log_critical(f"Skipping: {project_path} is not a valid directory")
                continue
            
            print(f"\n{Colors.BOLD}{Colors.CYAN}>>> Scanning Project: {project_path}{Colors.RESET}")
            
            env_config = config_data.get('environment', {})
            docker_config = config_data.get('docker', {})
            host_config = config_data.get('host', {})
            db_config = config_data.get('database', {})
            
            scanner = SecurityScanner(
                project_root=project_path,
                smtp_config=smtp_config,
                report_dir=report_dir,
                env_config=env_config,
                docker_config=docker_config,
                host_config=host_config,
                db_config=db_config
            )
            scanner.run()

    # Case 2: Single project via CLI argument
    elif args.project_root:
        if not os.path.isdir(args.project_root):
            print(f"{Colors.RED}Error: {args.project_root} is not a valid directory{Colors.RESET}")
            sys.exit(1)
            
        smtp_config = {'to_email': args.email} if args.email else None
        
        scanner = SecurityScanner(
            project_root=args.project_root,
            smtp_config=smtp_config
        )
        scanner.run()
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
