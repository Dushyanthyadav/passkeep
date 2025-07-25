# 🔐 passkeep

**passkeep** is a simple, secure, and local password manager written in Rust.  
It uses **Argon2** for key derivation and **AES-GCM** for encryption. All data is securely stored on your local Linux system — **no internet, no cloud, and no tracking**.

> ⚠️ **Linux-only:** This project is currently tested and supported only on **Linux systems**. Support for Windows/macOS may be added in the future.

---

## ✨ Features

- Add and manage multiple account entries
- Securely store:
  - Account names
  - Usernames
  - Emails
  - Passwords
  - Comments
- Encrypts all data using AES-GCM
- Derives keys from your master password using Argon2
- CLI-based interface (lightweight and simple)

---

## 🧰 Tech Stack

- **Rust** – systems programming language
- **Argon2** – password-based key derivation
- **AES-GCM** – authenticated encryption
- **serde / serde_json** – for data serialization
- **Linux config directory** – stores data in `~/.config/passkeep/`

---

## 🚀 Getting Started

### 1. Create a custom folder and clone the repo

```bash
mkdir my_projects
cd my_projects
git clone https://github.com/Dushyanthyadav/passkeep.git
cd passkeep
