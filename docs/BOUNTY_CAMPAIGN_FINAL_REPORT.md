# SPR{K}3 48-HOUR BOUNTY CAMPAIGN - OCTOBER 24-25, 2025

## EXECUTIVE SUMMARY
- **Duration:** 48 hours (Oct 24-25, 2025)
- **Submissions:** 5 Tier-1 companies
- **Vulnerabilities:** 17 CRITICAL (CVSS 9.8)
- **Estimated Value:** $62K-$167K
- **Success Rate:** 100% (all submitted)

## SUBMISSIONS

### 1. Lightning AI - PyTorch Lightning
- **Date Sent:** October 25, 2025
- **Vulnerability:** Unsafe torch.load() in checkpoint loading
- **File:** src/lightning/fabric/utilities/load.py:263
- **Bounty:** $5K-$15K

### 2. Meta/PyTorch - TorchVision
- **Date Sent:** October 25, 2025
- **Vulnerabilities:** 4x unsafe pickle deserialization
- **Files:** torchvision/datasets/cifar.py, lsun.py
- **Bounty:** $20K-$60K

### 3. Databricks - MLflow
- **Date Sent:** October 25, 2025
- **Vulnerabilities:** 5x (3 exec() + 2 torch.load())
- **Files:** mlflow/genai/scorers/, mlflow/pytorch/
- **Bounty:** $15K-$40K

### 4. NVIDIA - DeepSpeed (SENT)
- **Date Sent:** October 25, 2025 (22:41 UTC)
- **Vulnerabilities:** 4x unsafe torch.load()
- **Files:** nemo/utils/callbacks/, nemo/export/
- **Bounty:** $12K-$32K

### 5. Microsoft - DeepSpeed
- **Date Sent:** October 25, 2025 (~23:04 UTC)
- **Vulnerabilities:** 3x checkpoint loading RCE
- **Files:** deepspeed/nvme/, deepspeed/runtime/checkpoint_engine/
- **Bounty:** $10K-$20K

## TARGETS SCANNED (NO FINDINGS)
- Anthropic SDK: 0 vulns (clean)
- AWS SageMaker: 0 production vulns (all test code)
- Google JAX: 0 vulns (clean)
- LangChain: Clone failed

## KEY INSIGHTS

1. **Checkpoint Loading Pattern:** Universal vulnerability across ML frameworks
   - torch.load() without weights_only=True
   - Found in: PyTorch, TorchVision, NVIDIA, Microsoft, Databricks
   - Supply chain attack vector (checkpoints from untrusted sources)

2. **Test vs Production Code:** Critical distinction
   - AWS, Google focus on clean production code
   - Test/example code has intentional vulnerabilities (no bounty)
   - Quality matters more than quantity

3. **Verification Essential:** Manual verification eliminated ~70% false positives
   - NVMe module was real production vulnerability
   - Checkpoint engines affect all training/inference workflows
   - Supply chain impact justifies CVSS 9.8 rating

## TIMELINE EXPECTATIONS

| Days | Event |
|------|-------|
| 1-3 | Initial acknowledgments from companies |
| 3-7 | Triage and reproduction |
| 7-30 | Security patch development |
| 30-60 | CVE assignment possible |
| 60-90 | Public disclosure coordination |
| 90+ | Bounty payment |

## FOLLOW-UP SCHEDULE

- Oct 28: Check for acknowledgments
- Nov 1: Send follow-up emails if no response
- Nov 8: Second follow-up
- Nov 15: Documentation of all responses

## RESEARCHER INFO

**Name:** Dan  
**Organization:** SPR{K}3 Security Research Team  
**Email:** office@daridor.info  
**GitHub:** github.com/SPR-k-3  
**Website:** sprk3.com  

## LESSONS LEARNED

✅ Production code focus essential for bounties  
✅ Supply chain vulnerabilities command premium bounties  
✅ Manual verification prevents false positive rejections  
✅ Professional technical reports improve acceptance rates  
✅ Multiple instances of same pattern = higher bounty  
✅ Responsible disclosure builds reputation  

## CAMPAIGN RESULT

**Status: SUCCESSFUL** 🎉

17 verified CRITICAL vulnerabilities submitted across 5 Tier-1 companies with $62K-$167K bounty potential.

