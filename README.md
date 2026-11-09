# DevSecOps secrets & IaC security gate

**Author:** Md Shohrab Hossen Niaz

Fails CI when high-severity secrets or open `0.0.0.0/0` SSH ingress appear in scanned paths.

```powershell
python -m src.cli scan --path .\fixtures --fail-on high
```
