#!/bin/bash

echo "🔍 Analyzing actual files in SPR{K}3 repository..."

# Function to safely move files
move_if_exists() {
    if [ -f "$1" ]; then
        mv "$1" "$2"
        echo "✓ Moved $1 to $2"
    else
        echo "⚠️ File not found: $1"
    fi
}

# First, let's see what we have
echo -e "\n📊 Current file inventory:"
echo "Python files: $(ls -la *.py 2>/dev/null | wc -l)"
echo "Markdown files: $(ls -la *.md 2>/dev/null | wc -l)"
echo "JSON files: $(ls -la *.json 2>/dev/null | wc -l)"
echo "Text files: $(ls -la *.txt 2>/dev/null | wc -l)"

# Move SPR{K}3 engine files
echo -e "\n⚙️ Organizing SPR{K}3 Engine Files..."
move_if_exists "sprk3_engine.py" "engines/"
move_if_exists "sprk3_engine_v3.py" "engines/"
move_if_exists "engine5_sprk3_integration.py" "engines/supply_chain/"
move_if_exists "engine5_supply_chain_v2.py" "engines/supply_chain/"
move_if_exists "sprk3_processor.py" "engines/"
move_if_exists "sprk3_false_positive_filter.py" "engines/"
move_if_exists "sprk3_security.py" "engines/"

# Move braided scan files
echo -e "\n🔗 Organizing Braided Scan Files..."
move_if_exists "sprk3_braided_scan_fast.py" "scanners/production/"
move_if_exists "sprk3_braided_scan_orchestration.py" "scanners/production/"
move_if_exists "sprk3_braided_scan_architecture.md" "docs/"

# Move other Python files
echo -e "\n🐍 Organizing Other Python Files..."
move_if_exists "brainguard_monitor.py" "engines/brainguard/"
move_if_exists "agentland_integration.py" "engines/brainguard/"
move_if_exists "bounty_hunter.py" "tools/automation/"
move_if_exists "improved_bounty_hunter.py" "tools/automation/"
move_if_exists "find_new_targets.py" "tools/automation/"
move_if_exists "find_new_llm_projects.py" "tools/automation/"
move_if_exists "find_new_vulns.py" "tools/automation/"
move_if_exists "find_real_bugs.py" "tools/automation/"
move_if_exists "scan_paying_targets.py" "tools/automation/"
move_if_exists "hunt_ml_repos.py" "tools/automation/"
move_if_exists "create_exploit.py" "tools/utilities/"
move_if_exists "fix_scanner.py" "tools/utilities/"
move_if_exists "fix_torch_vulnerability.py" "tools/utilities/"
move_if_exists "quick_temporal_fix.py" "tools/utilities/"
move_if_exists "compare_scanners.py" "tools/utilities/"
move_if_exists "add_security.py" "tools/utilities/"
move_if_exists "langchain_command_injection_poc.py" "tools/utilities/"

# Move test files
echo -e "\n🧪 Organizing Test Files..."
for file in test_*.py; do
    if [ -f "$file" ]; then
        mv "$file" "tests/unit/"
        echo "✓ Moved $file to tests/unit/"
    fi
done
move_if_exists "demo.py" "tests/integration/"
move_if_exists "demo_all_attacks.py" "tests/integration/"
move_if_exists "test_malicious_model.pkl" "tests/fixtures/"

# Move JSON files
echo -e "\n📊 Organizing JSON Evidence Files..."
for file in *.json; do
    if [ -f "$file" ]; then
        case "$file" in
            *SCAN* | *scan* | *Scan*)
                mv "$file" "evidence/scans/"
                echo "✓ Moved $file to evidence/scans/"
                ;;
            *bounty* | *evidence* | *VALIDATED*)
                mv "$file" "evidence/validation/"
                echo "✓ Moved $file to evidence/validation/"
                ;;
            *)
                mv "$file" "evidence/"
                echo "✓ Moved $file to evidence/"
                ;;
        esac
    fi
done

# Move Markdown files
echo -e "\n📝 Organizing Documentation Files..."
for file in *.md; do
    if [ -f "$file" ] && [ "$file" != "README.md" ]; then
        case "$file" in
            *submission* | *bounty_report* | *VULNERABILITY*)
                mv "$file" "reports/bug_bounty/"
                echo "✓ Moved $file to reports/bug_bounty/"
                ;;
            *analysis* | *_analysis.md)
                mv "$file" "reports/analysis/"
                echo "✓ Moved $file to reports/analysis/"
                ;;
            *GUIDE* | *QUICKSTART* | *START_HERE*)
                mv "$file" "docs/guides/"
                echo "✓ Moved $file to docs/guides/"
                ;;
            *SUMMARY* | *LOG* | *COMPLETE* | *REPORT*)
                mv "$file" "docs/"
                echo "✓ Moved $file to docs/"
                ;;
            *)
                mv "$file" "docs/"
                echo "✓ Moved $file to docs/"
                ;;
        esac
    fi
done

# Move text files
echo -e "\n📄 Organizing Text Files..."
for file in *.txt; do
    if [ -f "$file" ]; then
        case "$file" in
            *email* | *submission*)
                mv "$file" "reports/bug_bounty/"
                echo "✓ Moved $file to reports/bug_bounty/"
                ;;
            my_bounty_targets.txt)
                mv "$file" "archive/"
                echo "✓ Archived $file"
                ;;
            *)
                mv "$file" "archive/"
                echo "✓ Archived $file"
                ;;
        esac
    fi
done

# Move HTML files
echo -e "\n🌐 Organizing HTML Files..."
move_if_exists "sprk3_dashboard.html" "docs/"

# Move shell scripts
echo -e "\n🔧 Organizing Shell Scripts..."
for file in *.sh; do
    if [ -f "$file" ] && [ "$file" != "organize_actual_files.sh" ]; then
        mv "$file" "tools/utilities/"
        echo "✓ Moved $file to tools/utilities/"
    fi
done

# Move directories
echo -e "\n📁 Organizing Directories..."
for dir in */; do
    dir=${dir%/}  # Remove trailing slash
    case "$dir" in
        *_verify | *verify)
            if [ "$dir" != "verification" ]; then
                mv "$dir" "verification/" 2>/dev/null && echo "✓ Moved $dir to verification/"
            fi
            ;;
        temporal_analysis | complexity_analysis | braided_scan* | cloaking_results | brainguard_reports)
            mv "$dir" "evidence/analysis/" 2>/dev/null && echo "✓ Moved $dir to evidence/analysis/"
            ;;
        aic_certificates)
            mkdir -p evidence/certificates
            mv "$dir" "evidence/certificates/" 2>/dev/null && echo "✓ Moved $dir to evidence/certificates/"
            ;;
        unified_detector)
            mv "$dir" "engines/" 2>/dev/null && echo "✓ Moved $dir to engines/"
            ;;
        quarantine | openai-python | src)
            mv "$dir" "archive/" 2>/dev/null && echo "✓ Moved $dir to archive/"
            ;;
    esac
done

echo -e "\n✅ Organization complete!"
echo -e "\n📊 Final Summary:"
echo "  Engines: $(find engines/ -name "*.py" 2>/dev/null | wc -l) Python files"
echo "  Scanners: $(find scanners/ -name "*.py" 2>/dev/null | wc -l) Python files"
echo "  Tools: $(find tools/ -name "*.py" 2>/dev/null | wc -l) Python files"
echo "  Tests: $(find tests/ -name "*.py" 2>/dev/null | wc -l) Python files"
echo "  Evidence: $(find evidence/ -type f 2>/dev/null | wc -l) files"
echo "  Reports: $(find reports/ -type f 2>/dev/null | wc -l) files"
echo "  Docs: $(find docs/ -type f 2>/dev/null | wc -l) files"

echo -e "\n📋 Files remaining in root directory:"
ls -1 | grep -v "^engines$" | grep -v "^scanners$" | grep -v "^reports$" | grep -v "^evidence$" | grep -v "^docs$" | grep -v "^tests$" | grep -v "^tools$" | grep -v "^verification$" | grep -v "^archive$" | head -20
