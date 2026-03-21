# TokenGuard - Token Risk Analysis CLI

A powerful Rust-based command-line tool for analyzing cryptocurrency tokens and detecting potential rug pulls. TokenGuard aggregates data from multiple blockchain APIs and uses AI-powered analysis to provide comprehensive risk assessments.

## Features

- **🔍 Multi-Source Data Aggregation**: Fetches data from Etherscan, GoPlus, Covalent, Moralis, BitQuery, and more
- **🤖 AI-Powered Risk Analysis**: Integrates with Groq LLM for intelligent risk assessment
- **📊 Comprehensive Reports**: Generates detailed HTML, JSON, and Markdown reports
- **🎯 Real-Time Security Scoring**: Calculates rug pull probability based on multiple factors
- **🖥️ TUI Interface**: Beautiful terminal user interface for interactive analysis
- **⚡ High Performance**: Built with Rust for speed and reliability

## Quick Start

### Prerequisites

- **Rust 1.70+** (edition 2024) - [Install Rust](https://rustup.rs/)
- **API Keys** - See setup instructions below

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd rustLlmAgentCli

# Build release version
cargo build --release

# Verify build
./target/release/rust_llm_agent --version
```

### Configuration - API Keys Setup

**⚠️ IMPORTANT:** Never commit your `.env` file! It's already in `.gitignore`.

#### Step 1: Copy the template

```bash
cp .env.example .env
```

#### Step 2: Get Your FREE API Keys

You need to sign up for the following services and get API keys:

| Service | Purpose | Free Tier | Sign Up Link |
|---------|---------|-----------|--------------|
| **Groq** | LLM AI Analysis | 14,400 req/day | https://console.groq.com/keys |
| **Etherscan** | Ethereum Contract Data | 100k req/day | https://etherscan.io/myapikey |
| **GoPlus** | Security Analysis | FREE | https://docs.gopluslabs.io/ |
| **Covalent** | Token Holders Data | 100k req/month | https://www.covalenthq.com/platform/ |
| **Moralis** | On-Chain Data | 40k ops/month | https://moralis.io/ |
| **BitQuery** | Blockchain Analytics | FREE tier | https://bitquery.io/ |

#### Step 3: Fill in `.env`

Edit the `.env` file and add your API keys:

```bash
# REQUIRED - LLM API
GROQ_API_KEY=gsk_your_actual_key_here

# REQUIRED - Blockchain APIs
ETHERSCAN_API_KEY=your_actual_key_here
API_KEY=your_goplus_key_here
API_SECRET=your_goplus_secret_here

# OPTIONAL - Enhanced data sources
COVALENT_API_KEY=your_key_here
MORALIS_API_KEY=your_key_here
BITQUERY_API_TOKEN=your_key_here
```

**Detailed signup instructions:**

1. **Groq (Required for AI analysis)**
   - Visit: https://console.groq.com/keys
   - Sign up with GitHub or Google
   - Create a new API key
   - Copy the key starting with `gsk_`

2. **Etherscan (Required for Ethereum data)**
   - Visit: https://etherscan.io/myapikey
   - Create a free account
   - Go to API Keys section
   - Create a new key (rate limited: 5 req/sec)

3. **GoPlus Security (Required for security analysis)**
   - Visit: https://docs.gopluslabs.io/
   - No signup required for basic usage
   - API key is optional but recommended

4. **Covalent (Optional - for holder data)**
   - Visit: https://www.covalenthq.com/platform/
   - Sign up for free account
   - Get your API key from dashboard

5. **Moralis (Optional - for on-chain data)**
   - Visit: https://moralis.io/
   - Create free account
   - Get API key from dashboard

6. **BitQuery (Optional - for analytics)**
   - Visit: https://bitquery.io/
   - Sign up for free account
   - Get API token from developer section

#### Step 4: Verify Setup

```bash
# Test your configuration
cargo run --release -- --chain ethereum --token 0x1f9840a85d5af5bf1d1762f925bdaddc4201f984
```

### Usage

#### TUI Mode (Interactive) - RECOMMENDED

**Start the TUI:**
```bash
cargo run --release
```

**TUI Commands:**

Once in the TUI, you can use these commands:

| Command | Description | Example |
|---------|-------------|---------|
| `/scan <token_address>` | Scan a token for rug pull risks | `/scan 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9` |
| `/scan <token> --chain <chain>` | Scan token on specific chain | `/scan 0x1f9840a8 --chain ethereum` |
| `/scan <token> --include-market-data` | Include market data in scan | `/scan 0x1f9840a8 --include-market-data` |
| `/scan <token> --analyze-with-llm` | Enable AI analysis | `/scan 0x1f9840a8 --analyze-with-llm` |
| `/help` | Show all available commands | `/help` |
| `/clear` | Clear the chat history | `/clear` |
| `/quit` or `/exit` | Exit the TUI | `/quit` |

**Example TUI Session:**

```
> /scan 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9 --chain ethereum --include-market-data --analyze-with-llm

Scanning token: 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9 on ethereum...
✅ Scan complete!
📊 Risk Score: 15/100 (LOW)
🎯 Rug Probability: 12.5%
📈 TRI Score: 22.0/100 [LOW RISK]

Reports saved to: /home/serverhp/qwenAg/reports/
```

**TUI Navigation:**

- **Arrow Keys** - Navigate through messages
- **Page Up/Down** - Scroll through history
- **Enter** - Send command
- **Ctrl+C** - Exit TUI
- **Tab** - Auto-complete commands

#### CLI Mode (Command Line)

```bash
# Scan a token
cargo run --release -- --chain ethereum --token 0x1f9840a85d5af5bf1d1762f925bdaddc4201f984

# Specify output format
cargo run --release -- --chain ethereum --token 0x1f9840a85d5af5bf1d1762f925bdaddc4201f984 --format both

# Include market data
cargo run --release -- --chain ethereum --token 0x1f9840a85d5af5bf1d1762f925bdaddc4201f984 --include-market-data
```

#### Command Line Options

```
--chain <CHAIN>           Blockchain network (ethereum, base, arbitrum, etc.)
--token <ADDRESS>         Token contract address to analyze
--format <FORMAT>         Output format: json, markdown, html, both [default: markdown]
--include-market-data     Include price and market data in report
--llm-url <URL>           LLM API base URL [default: https://api.groq.com]
--model <MODEL>           LLM model to use [default: llama-3.1-8b-instant]
--no-tui                  Disable TUI (CLI mode only)
-v, --verbose             Enable verbose output
-h, --help                Show help
--version                 Show version
```

### Supported Chains

| Chain | Chain ID |
|-------|----------|
| Ethereum | 1 |

## API Integration

TokenGuard integrates with multiple data providers:

| Provider | Purpose | Free Tier |
|----------|---------|-----------|
| **Groq** | LLM Inference | 14,400 req/day |
| **Etherscan** | Contract Data | 100,000 req/day |
| **GoPlus** | Security Analysis | Free |
| **Covalent** | Token Holders | 100k req/month |
| **Moralis** | On-Chain Data | 40k ops/month |
| **BitQuery** | Blockchain Analytics | Free tier available |

See [SECURITY.md](SECURITY.md) for links to obtain API keys.

## Output

Reports are saved to the `reports/` directory:

```
reports/
└── 0x1f9840a8/
    └── 12_03_2026_09_30/
        ├── token_analysis.md      # Human-readable analysis
        ├── scan_manifest.json     # Scan metadata
        ├── json/                   # Raw API responses
        │   ├── etherscan.json
        │   ├── goplus.json
        │   └── ...
        └── reports/                # Generated reports
            ├── security_report.html
            └── security_report.json
```

## Development

### Setup and Build Commands

Run these commands in order to set up, build, and test the project:

```bash
# 1. Update dependencies
cargo update

# 2. Format code
cargo fmt

# 3. Run benchmarks (optional - tests performance)
cargo bench --bench pipeline_bench

# 4. Build release version
cargo build --workspace --all-features --release

# 5. Run clippy (strict linting - should pass with no warnings)
cargo clippy --workspace --all-targets -- -D warnings -D clippy::all -D clippy::pedantic

# 6. Run TokenGuard with external reports directory
cargo run --bin tokenguard -- --chain ethereum --token 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9 --format both --include-market-data --analyze-with-llm --output-dir /home/serverhp/qwenAg/reports
```

### Creating External Reports Directory

Reports are saved **outside the application directory** to keep them separate from source code.

**Step 1: Create the reports directory**
```bash
mkdir -p /home/serverhp/qwenAg/reports
cd /home/serverhp/qwenAg/reports
```

**Step 2: Initialize git repository (optional - for auto-sync to GitHub)**
```bash
git init
git remote add origin https://github
```

**Step 3: Run TokenGuard with custom output directory**
```bash
cd /home/serverhp/qwenAg/rustLlmAgentCli
cargo run --bin tokenguard -- \
  --chain ethereum \
  --token 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9 \
  --format both \
  --include-market-data \
  --analyze-with-llm \
  --output-dir /home/serverhp/qwenAg/reports
```

**Step 4: Verify reports were created**
```bash
ls -la /home/serverhp/qwenAg/reports/
```

**Expected output structure:**
```
/home/serverhp/qwenAg/reports/
├── token_report_0x7fc66500_YYYYMMDD_HHMMSS.json    # JSON report
├── token_report_0x7fc66500_YYYYMMDD_HHMMSS.html    # HTML report
└── 0x7fc66500/                                      # Organized by token
    └── DD_MM_YYYY_HH_MM/
        ├── scan_manifest.json
        ├── token_analysis.md
        ├── json/           # Raw API responses
        └── reports/        # Final reports
```

### Command Breakdown

| Command | Purpose |
|---------|---------|
| `cargo update` | Update all dependencies to latest compatible versions |
| `cargo fmt` | Format all code according to Rust style guidelines |
| `cargo bench --bench pipeline_bench` | Run performance benchmarks |
| `cargo build --workspace --all-features --release` | Build optimized release binary |
| `cargo clippy ...` | Run strict linting (must pass with 0 warnings) |
| `cargo run --bin tokenguard ...` | Run TokenGuard scanner |

### CLI Options

```bash
--chain <CHAIN>           Blockchain network (ethereum, base, arbitrum, etc.)
--token <ADDRESS>         Token contract address to scan
--format <FORMAT>         Output: json, html, or both
--include-market-data     Include price and market data
--analyze-with-llm        Enable AI-powered risk analysis
--output-dir <PATH>       Custom reports directory (default: ./reports)
-v, --verbose             Show detailed output
--help                    Show all options
```

### Example: Scan AAVE Token

```bash
cargo run --bin tokenguard -- \
  --chain ethereum \
  --token 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9 \
  --format both \
  --include-market-data \
  --analyze-with-llm \
  --output-dir /home/serverhp/qwenAg/reports
```

### Project Structure

```
rustLlmAgentCli/
├── src/
│   ├── main.rs              # CLI entry point
│   ├── lib.rs               # Library root
│   ├── agent/               # AI agent system
│   ├── api/                 # API integrations
│   ├── app/                 # Application layer
│   ├── scanner/             # Token scanning logic
│   ├── report/              # Report generation
│   ├── llm/                 # LLM client
│   └── tui/                 # TUI interface
├── config/                  # Configuration files
└── .env.example            # Environment template
```

Reports are saved to: `/home/serverhp/qwenAg/reports/` (external directory)

## Troubleshooting

### Common Issues

**"API key not set" error:**
- Ensure `.env` file exists in the project root
- Verify all required API keys are set (see Configuration section)

**"Connection timeout" error:**
- Check your internet connection
- Verify API endpoints are accessible
- Increase timeout in `.env` if needed

**Build fails:**
- Ensure Rust 1.70+ is installed: `rustc --version`
- Update Rust: `rustup update`
- Clear build cache: `cargo clean && cargo build`

## Security

⚠️ **Important Security Guidelines:**

- Never commit `.env` file or API keys to version control
- Use separate API keys for development and production
- Rotate API keys periodically

## License

MIT License - See LICENSE file for details

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

---

**Built with Rust 🦀 | Powered by AI 🤖 | Secured by Multiple APIs 🔐**
