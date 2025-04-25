# 🛡️ AWS Security Audit Toolkit (`aws-v7.sh`)

A comprehensive and interactive Bash script to perform AWS security posture assessments. Designed to help security engineers and cloud practitioners identify misconfigurations.

---

## ✨ Features

🔐 **AWS Profile Support**  
Use specific AWS CLI profiles with `--profile`.

🖥️ **EC2 Checks**  
- Detect instances that do **not have IMDSv2** enabled.  
- Scan EC2 **UserData** for hardcoded secrets *(manual review required)*.

📦 **S3 Bucket Security**  
- Check for **versioning** and **logging**.  
- Verify **secure transport (HTTPS-only)** is enforced.

👤 **IAM Audits**  
- Identify **privilege escalation** paths *(manual review required)*.  
- Detect overly permissive use of `iam:PassRole` and `sts:AssumeRole`.  
- Check for **unused IAM keys** and **keys not rotated** in the last 365 days.

🔑 **KMS & Secrets Manager**  
- Validate **KMS key rotation**.  
- Verify **Secrets Manager rotation** is enabled.  
- Check if **SSM Parameters** are using `SecureString`.

🔍 **CloudTrail**  
- Ensure CloudTrail logs are **encrypted with KMS**.

⚠️ **Lambda Analysis**  
- Review **Lambda environment variables** for sensitive data *(manual review required)*.

🔥 **Security Groups**  
- Flag **open ingress/egress** rules allowing traffic from/to `0.0.0.0/0` or `::/0`.  
- Detect **unused security groups** not attached to any instance or interface.

🌐 **Load Balancer Check**  
- Identify **cleartext communication** allowed by load balancers.

---

## 🛠 Prerequisites
- AWS CLI configured with appropriate permissions.
- `jq` and `scrot` installed:

```bash
sudo apt install jq scrot -y
```

- AWS CLI v2 must be installed and configured with valid credentials.

---

## 🚀 Usage

```bash
chmod +x aws-v7.sh
./aws-v7.sh --profile <yourProfileName> [options]
```

### Example:

```bash
./aws-v7.sh --profile dev-account --imdsv2 --s3-security
```

### Help Menu:

```bash
./aws-v7.sh --help
```

This will list all available options and examples.

---

## 📝 Output

Each check generates a `.txt` report and optionally a screenshot via `scrot`. Example files:

- `imds.txt`
- `s3_security.txt`
- `iam_policies.txt`
- `kms_key_rotation.txt`
- `IAM_Key_rotation.png` (screenshot)

> 🔸 When pasting resource names/IDs into the script, **limit to 5–6** at a time for clean output and screenshots.

---

## ⚠️ Notes

- Some checks involve **manual inspection**, especially when reviewing IAM policies or environment variables.
- Be cautious when sharing outputs — redact sensitive data.

---

## 📜 License

This script is provided as-is, without any warranty. Use it responsibly within your organization or cloud account for security review.

---

## 🙌 Contributing

Pull requests are welcome! If you find bugs or want to suggest features, feel free to open an issue or PR.

---

## 👨‍💻 Author

Maintained by [Love]
