 
# DiskInsightPro

## Overview
DiskInsightPro is an educational disk space analysis tool that helps users visualize and manage their storage space through an intuitive graphical interface. It provides detailed insights into file distribution, sizes, and types across drives.

## Purpose
Created to help users, particularly students and professionals, better understand and manage their disk space usage. The tool emphasizes educational value by providing clear visualizations and detailed statistics about file distribution.

## Features
- Interactive GUI with dark theme for reduced eye strain
- Real-time scanning progress visualization
- Advanced filtering options (file type, size, date)
- Detailed statistics and file analysis
- Export/Import functionality for scan results
- Context menu for file operations
- Cross-platform compatibility

## Requirements
- Python 3.7+
- Required packages:
  - tkinter
  - humanize
  - psutil

## Installation
1. Clone the repository:
   git clone https://github.com/yourusername/DiskInsightPro.git

2. Install required packages:
   pip install -r requirements.txt

3. Run the application:
   python diskinsightpro.py

## Use Case Example
Sarah, a photography student, needs to free up space on her laptop. Using DiskInsightPro, she:
1. Scans her main drive
2. Filters for large image files (.raw, .jpg) older than 30 days
3. Identifies redundant or unnecessary files
4. Uses the built-in file management to organize or remove files
5. Exports the scan results for future reference