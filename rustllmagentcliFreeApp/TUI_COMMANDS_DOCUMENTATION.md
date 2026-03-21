# TUI Commands Documentation - Complete

## ✅ What Was Added to README.md

Comprehensive TUI (Terminal User Interface) startup and usage instructions.

---

## 🖥️ Starting the TUI

**Command:**
```bash
cargo run --release
```

**Status:** Marked as **RECOMMENDED** interface for users.

---

## 📋 TUI Commands

Once inside the TUI, users can use these slash commands:

| Command | Description | Example |
|---------|-------------|---------|
| `/scan <token_address>` | Scan a token for rug pull risks | `/scan 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9` |
| `/scan <token> --chain <chain>` | Scan token on specific chain | `/scan 0x1f9840a8 --chain ethereum` |
| `/scan <token> --include-market-data` | Include market data in scan | `/scan 0x1f9840a8 --include-market-data` |
| `/scan <token> --analyze-with-llm` | Enable AI-powered analysis | `/scan 0x1f9840a8 --analyze-with-llm` |
| `/help` | Show all available commands | `/help` |
| `/clear` | Clear the chat history | `/clear` |
| `/quit` or `/exit` | Exit the TUI | `/quit` |

---

## 💡 Example TUI Session

```
> /scan 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9 --chain ethereum --include-market-data --analyze-with-llm

Scanning token: 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9 on ethereum...
✅ Scan complete!
📊 Risk Score: 15/100 (LOW)
🎯 Rug Probability: 12.5%
📈 TRI Score: 22.0/100 [LOW RISK]

Reports saved to: /home/serverhp/qwenAg/reports/
```

---

## ⌨️ TUI Navigation Keys

| Key | Action |
|-----|--------|
| **Arrow Keys** ↑↓ | Navigate through messages |
| **Page Up** | Scroll up through history |
| **Page Down** | Scroll down through history |
| **Enter** | Send command |
| **Ctrl+C** | Exit TUI |
| **Tab** | Auto-complete commands |

---

## 🔍 Complete /scan Command Options

The `/scan` command supports all the same options as the CLI:

```bash
/scan <token_address> [OPTIONS]

Options:
  --chain <CHAIN>           Blockchain network (ethereum, base, arbitrum, etc.)
  --format <FORMAT>         Output: json, html, or both
  --include-market-data     Include price and market data in report
  --analyze-with-llm        Enable AI-powered risk analysis
  --output-dir <PATH>       Custom reports directory
```

### Examples

**Basic scan:**
```
/scan 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9
```

**Full scan with all options:**
```
/scan 0x7fc66500c84a76ad7e9c93437bfc5ac33e2ddae9 --chain ethereum --include-market-data --analyze-with-llm --format both
```

**Scan on different chains:**
```
/scan 0x1f9840a85d5af5bf1d1762f925bdaddc4201f984 --chain base
/scan 0x1f9840a85d5af5bf1d1762f925bdaddc4201f984 --chain arbitrum
```

---

## 📊 TUI Output Example

When you run a scan, the TUI displays:

```
📊 Risk Score: 15/100 (LOW)
🎯 Rug Probability: 12.5%
📈 TRI Score: 22.0/100 [LOW RISK]
🚩 Red Flags: 2
✅ Green Flags: 5

=== Groq LLM Analysis ===
Recommendation: ✅ SAFE
Confidence: 85%
Explanation: This token shows low risk indicators...

LLM Red Flags:
  • Low liquidity
  • Recent deployment

Reports saved to: /home/serverhp/qwenAg/reports/
```

---

## 🎯 Benefits of Using TUI

✅ **Interactive** - Real-time conversation with the agent  
✅ **Easy to use** - Simple slash commands  
✅ **Visual feedback** - See progress and results immediately  
✅ **Command history** - Navigate previous scans  
✅ **Auto-complete** - Tab completion for commands  
✅ **Persistent session** - Run multiple scans without restarting  

---

## 📝 Files Modified

| File | Changes |
|------|---------|
| `README.md` | Added TUI commands and navigation documentation |

---

## 🔍 Verification

Check the README:

```bash
# View TUI commands section
grep -A 50 "TUI Mode (Interactive)" README.md

# View TUI commands table
grep -A 15 "/scan <token_address>" README.md

# View navigation keys
grep -A 10 "TUI Navigation" README.md
```

---

**Status: ✅ Complete - TUI startup and commands fully documented!**
