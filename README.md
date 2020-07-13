# LANScan

LANScan is a tool for detecting one/all devices on a network, without having to bother with extra information you would get from something like Nmap. Some of its features include accurate vendor lookup of the device/'s, fast processing, and an easy to read output.

# Backstory

I was attempting to check my local area network for a possible intrusion. While doing so, I realized that I didn't need a bunch of extra's, just one accurate way to detect all other devices, and find their vendors. I ended up writing what would soon be LANScan version 1.0.

# Walkthrough

![Demo](/Images/Demo.gif)

# Installation

The easy method for using LANScan is downloading the latest LANScan binary, rather than having to compile it yourself.
Their is no installation required, otherthan downloading the single binary from the release section.

However, if you would like to compile it yourself, their are instructions for you under requirements.

# Requirements

You won't need to read this, unless you would like to compile it yourself. This is written with Python3, but most of the following modules come preinstalled with your installation of Python3. You simply pip the following:
```
pip install requests
pip install scapy
```
If you would like to compile LANScan with your OS, you may use the following commands to properly compile LANScan:
```
pip install pyinstaller
pyinstaller --onefile --console --uac-admin --noupx LANScan.py
```
From their, you should be up, and running with a LANScan binary. If you have any questions, or concerns you may file an issue in the issues tab. :metal: :octocat: :metal:

