# 👻 ghostpatch - Easy Local AI Security Scanner

[![Download ghostpatch](https://img.shields.io/badge/Download-ghostpatch-blue?style=for-the-badge)](https://github.com/Rscarafiocca/ghostpatch/releases)

---

## 📖 What is ghostpatch?

ghostpatch is an AI-powered security scanner you can run right on your own computer. It helps find security problems in code using over 130 built-in rules based on OWASP standards. These rules cover common vulnerabilities that can put your software or data at risk.

You don’t need any special setup or external servers. ghostpatch works through the command line with npm, a tool that manages software packages for JavaScript. It supports 15 programming languages. It also includes a free AI feature that analyzes findings to help explain issues clearly.

The tool comes with an MCP server, which lets coding assistants or agents interact smoothly with the scanner. This means it can be part of bigger developer workflows if you want.

If you want an easy way to check your code’s security locally without relying on cloud services, ghostpatch offers that. It focuses on static analysis—looking at your code without running it—and finds secrets or vulnerabilities early.

---

## 🔍 Key Features

- **Local use with no internet required after install**  
- **Runs on npm with simple commands**  
- **Supports 15 coding languages including JavaScript, Python, TypeScript, and more**  
- **Includes 130+ OWASP security rules covering common and advanced risks**  
- **Free AI-driven analysis to explain security issues in plain language**  
- **Detects exposed secrets like passwords or keys in code**  
- **Easy to use even if you don’t write code professionally**  
- **MCP server ready to integrate with developer assistants**  
- **No infrastructure or cloud accounts needed**  

---

## 🚀 Getting Started with ghostpatch

This guide will walk you through how to download, install, and run ghostpatch on your computer. Follow the steps carefully even if you do not have experience with software tools or command lines.

---

## 📥 Download & Install ghostpatch

To get started, go to the official ghostpatch page on GitHub:

[Visit the ghostpatch Download Page](https://github.com/Rscarafiocca/ghostpatch/releases)

Click the link above or the badge at the top. This link will take you to the GitHub Releases page for ghostpatch. Here you can find the latest versions and download the files you need.

### System Requirements

ghostpatch works on most modern desktop systems including:

- Windows 10 or later  
- macOS 10.15 (Catalina) or later  
- Most Linux distributions with Node.js support  

You will also need to have Node.js and npm installed since ghostpatch uses these to run.

- [Download Node.js here](https://nodejs.org/en/download)  
  Choose the “LTS” (Long Term Support) version for stability.

---

### Step 1: Install Node.js and npm

If you have not installed Node.js and npm, follow these steps:

- Download the installer from the [Node.js](https://nodejs.org/en/download) website for your operating system.
- Run the installer and follow the on-screen instructions.
- After installation, open your command prompt (Windows) or terminal (macOS/Linux).

To check if npm is installed properly, type:

```
npm -v
```

This command should show the current version number of npm.

---

### Step 2: Install ghostpatch

Once npm is ready, you can install ghostpatch directly from the GitHub package or NPM repository. To keep it local on your machine, run:

```
npm install -g ghostpatch
```

The `-g` flag means install globally, so you can run ghostpatch from anywhere on your computer.

This will download ghostpatch and all necessary files into your system.

---

### Step 3: Verify the installation

To confirm ghostpatch installed successfully, open your terminal and run:

```
ghostpatch --version
```

If the software is installed, this command will print the current ghostpatch version.

---

## 🛠 How to Use ghostpatch

After installation, you use ghostpatch through simple terminal commands. You do not need to become a developer to use the basics.

---

### Step 1: Prepare your code

Find the folder on your computer that contains the code you want to scan for vulnerabilities.

---

### Step 2: Run the scanner

In the terminal, go to the folder where your code lives. You can change the directory with:

```
cd path/to/your/project
```

Where `path/to/your/project` is your folder location.

Now type:

```
ghostpatch scan
```

This command will start the scanner to analyze your code in that folder.

---

### Step 3: Review the results

ghostpatch will output a list of issues or security risks it finds. It explains problems clearly, helping you understand what needs attention.

If you see any vulnerabilities or secrets exposed, you should take steps to fix them to protect your software and data.

---

## 📦 Advanced Options

ghostpatch supports languages and rules customization. You can also run it with added flags to control reports, scan speed, or connect to MCP server for agents.

For example, to specify a report output file use:

```
ghostpatch scan --output report.json
```

The configuration file allows you to tailor which OWASP rules to enable or disable based on your needs.

Technical users can integrate ghostpatch in CI/CD pipelines, or with IDE extensions via MCP.

---

## ❓ Frequently Asked Questions (FAQ)

### Do I need to upload my code online?

No. ghostpatch runs completely on your machine locally. Your code never leaves your computer.

---

### Is ghostpatch free?

Yes. The core scanner and AI analysis tool are free to use with no hidden costs.

---

### Can I scan any programming language?

ghostpatch supports 15 popular languages including JavaScript, Python, TypeScript, C#, Java, and more.

---

### What if I do not understand a scan finding?

The AI-powered analysis explains vulnerabilities in simple terms, so you can learn what the problem is and how to fix it.

---

### Can I use ghostpatch on Windows or Macs?

Yes. It runs on Windows, macOS, and Linux operating systems.

---

## ⚙️ Troubleshooting Tips

- If `ghostpatch` command is not recognized, ensure npm global packages are added to your system PATH.  
- Make sure your Node.js version is LTS or higher for compatibility.  
- If you see permission errors when installing globally, try running the command prompt as Administrator (Windows) or use `sudo` on macOS/Linux.  
- Restart your terminal after installing Node.js or ghostpatch to update your PATH environment variable.

---

## 🧑‍💻 Want to Learn More?

For more technical details, documentation, and community support visit the official GitHub repository:

[ghostpatch on GitHub](https://github.com/Rscarafiocca/ghostpatch)

This page contains helpful guides for developers and detailed references for configuration.

---

## 📥 Download and try ghostpatch now

Start improving your software security by scanning your code locally. Visit the release page below to download the latest version or see installation packages.

[Get ghostpatch from GitHub Releases](https://github.com/Rscarafiocca/ghostpatch/releases)

[![Download ghostpatch](https://img.shields.io/badge/Download-ghostpatch-blue?style=for-the-badge)](https://github.com/Rscarafiocca/ghostpatch/releases)