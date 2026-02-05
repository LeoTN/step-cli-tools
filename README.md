<div align="center">

[![step-cli-tools](https://raw.githubusercontent.com/LeoTN/step-cli-tools/main/assets/logo/readme_logo.svg)](https://github.com/LeoTN/step-cli-tools)

[![latest-version](https://img.shields.io/github/v/release/LeoTN/step-cli-tools?&filter=*.*.*&display_name=release&style=for-the-badge&logo=Rocket&logoColor=green&label=LATEST&color=green)](https://github.com/LeoTN/step-cli-tools/releases/latest)
[![latest-beta-version](https://img.shields.io/github/v/release/LeoTN/step-cli-tools?&include_prereleases&filter=*.*.*b*&display_name=release&style=for-the-badge&logo=Textpattern&logoColor=orange&label=LATEST%20BETA&color=orange)](https://github.com/LeoTN/step-cli-tools/releases)
[![license](https://img.shields.io/github/license/LeoTN/step-cli-tools?&style=for-the-badge&logo=Google%20Docs&logoColor=blue&label=License&color=blue)](https://github.com/LeoTN/step-cli-tools/blob/main/LICENSE)

step-cli-tools is designed to **simplify** using the [step-ca](https://github.com/smallstep/certificates) command-line interface **step-cli** whilst adding a few extra features.

</div>

##


* [About](#about)
* [Getting Started](#getting-started)
* [Features](#features)
* [Supported Platforms](#supported-platforms)
* [Credits & License](#credits--license)

<img src="https://raw.githubusercontent.com/LeoTN/step-cli-tools/main/assets/readme.gif">

## About

I made this tool to learn  more about Python and publishing packages to PyPI. Since I am running my own step-ca server for my private infrastructure, I was looking for a way to easily request certificates for my various services. Basically, I threw a bunch of libraries together and this was the result.

There is probably a better way to do this, but this is what I came up with. Maybe you will find it useful too!

## Getting Started

**Install / upgrade with pip:**
```bash
pip install step-cli-tools --upgrade
```

**Start the tool:**
```bash
sct
```

## Features

| Feature | Description |
|---------|-------------|
| **Manage** root CA certificates | Install & uninstall your root CA certificate easily |
| **Request** certificates        | Request TLS certificates from your step-ca server   |

## Supported Platforms

| Platform              | Status     |
|-----------------------|:----------:|
| Ubuntu Server         | ✅         |
| Windows 11            | ✅         |
| Debian                | Unverified |
| macOS                 | Unverified |
| Windows 10            | Unverified |

The tool should work on the unverified platforms, but they have not been actively tested. User feedback on these systems is welcome!

## Credits & License

* [**vhs**](https://github.com/charmbracelet/vhs) → creation of the terminal GIF
* [**step-cli**](https://github.com/smallstep/cli) → the magic under the hood
* [**Inkscape**](https://inkscape.org) → program used to design the logo
* [**Python dependencies**](https://github.com/LeoTN/step-cli-tools/blob/main/pyproject.toml) → several useful libraries

I appreciate your **constructive** and **honest** feedback. Feel free to create an **issue** or **feature** request.

*This repository is licensed under the [MIT License](https://github.com/LeoTN/step-cli-tools/blob/main/LICENSE).*