"""Utility functions and visual output for Magento Security Scanner."""

# ─────────────────────────────────────────────────────────────────────────────
# COLOR OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    print(f"""{Colors.RED}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║         MAGENTO SECURITY INCIDENT RESPONSE SCANNER             ║
║                 ⚠  BREACH DETECTED  ⚠                          ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.RESET}""")

def log_critical(msg):
    print(f"  {Colors.RED}[CRITICAL]{Colors.RESET} {msg}")

def log_warning(msg):
    print(f"  {Colors.YELLOW}[WARNING]{Colors.RESET}  {msg}")

def log_info(msg):
    print(f"  {Colors.BLUE}[INFO]{Colors.RESET}     {msg}")

def log_ok(msg):
    print(f"  {Colors.GREEN}[OK]{Colors.RESET}       {msg}")

def log_action(msg):
    print(f"  {Colors.MAGENTA}[ACTION]{Colors.RESET}   {msg}")

def section_header(title):
    width = 64
    print(f"\n{Colors.CYAN}{Colors.BOLD}{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}{Colors.RESET}")