# Shodan Camera Discovery Script

This Python script helps identify potentially exposed camera systems using the Shodan API. It leverages various search queries based on common camera manufacturers, ports, titles, and known vulnerabilities to provide a broad scan.

**Note:** This tool is intended for security research and educational purposes only.

## Features

*   Uses a diverse set of Shodan queries to maximize discovery.
*   Loads your Shodan API key securely from a `.env` file.
*   Aggregates and deduplicates results from multiple queries.
*   Provides basic analysis of findings (common orgs, ports, products, countries, vulns).
*   Saves detailed results to a CSV file (`open_cameras_found.csv` by default).
*   Includes configurable limits and delays to manage API usage.
*   Basic logging for execution tracking.

## !! Ethical Disclaimer !!

**IMPORTANT:** Accessing camera streams or devices without explicit authorization is illegal and unethical in most jurisdictions. This script only queries Shodan's publicly aggregated data and **does not** interact directly with any discovered devices.

*   **Use this tool responsibly.** The data gathered should only be used for legitimate security research, vulnerability analysis (following responsible disclosure), or understanding internet exposure trends.
*   **Do not attempt unauthorized access.** Simply finding a device listed on Shodan does not grant permission to access it.
*   **Anonymize and protect data.** If sharing research findings, ensure sensitive information (like precise locations or identifiable details) is removed or aggregated.
*   **Comply with local laws and regulations** regarding data privacy and network scanning.

Misuse of this tool or the data it generates can have serious legal and ethical consequences. The authors assume no liability for misuse.

## Requirements

*   Python 3.8+
*   Shodan API Key (Paid plan recommended for extensive use due to query credits)
*   Python libraries: `shodan`, `pandas`, `python-dotenv` (Managed via `pyproject.toml`)
*   `uv` package manager (Recommended, see Installation)

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ShivamB25/shodan-cam
    cd shodan-cam
    ```

2.  **Set up a virtual environment (Recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3.  **Install `uv` (if you don't have it):**
    `uv` is a fast Python package installer and resolver. Follow the official installation instructions: [https://github.com/astral-sh/uv#installation](https://github.com/astral-sh/uv#installation)
    (Common methods include `pip install uv`, `pipx install uv`, or using system package managers).

4.  **Install dependencies using `uv`:**
    This command installs dependencies based on `pyproject.toml` and `uv.lock`, ensuring consistent environments.
    ```bash
    uv pip sync
    ```
    *Alternatively, if you prefer not to use `uv` or encounter issues:*
    ```bash
    # Make sure pip is up-to-date
    pip install --upgrade pip
    # Install from pyproject.toml (requires pip 21.1+)
    pip install .
    # Or if a requirements.txt is generated:
    # pip install -r requirements.txt
    ```

## Configuration (`.env` file)

1.  Create a file named `.env` in the project's root directory.
2.  Add your Shodan API key to this file:
    ```dotenv
    # .env
    SHODAN_API_KEY=YourShodanAPIKeyGoesHere 
    ```
    *Replace `YourShodanAPIKeyGoesHere` with your actual key.* This file is included in `.gitignore` to prevent accidentally committing your key.

## Usage & Output

Run the script from the command line:

```bash
python main.py
```

**Free API Key Mode:**

If you are using a free Shodan API key, many advanced filters (`product:`, `vuln:`, `tag:`, `has_screenshot:`) might be restricted, causing "Access denied (403 Forbidden)" errors. Use the `--free` flag to run the script with a limited set of queries that are more likely to work on a free plan:

```bash
python main.py --free
```

The script will automatically switch to free mode if it detects you're using a free API key (oss plan) or if you have 0 query credits.

**What's different in free mode?**
- Uses extremely simple queries without complex filters to avoid Access Denied errors
- Completely avoids using the `product:` filter which often causes Access Denied errors
- Uses single-term searches like 'webcam', 'camera', 'nvr', 'dvr', 'cctv' instead of complex filters
- Uses basic port searches without additional filters
- Provides detailed error messages when Access Denied errors occur
- Automatically tries simplified versions of failed queries
- Adds longer delays between queries to respect rate limits

The script will:
1.  Connect to the Shodan API using your key.
2.  Generate and execute a series of search queries.
3.  Log progress and query details to the console.
4.  Print a summary of findings (total count, top orgs, ports, etc.).
5.  Save the full, deduplicated results to `open_cameras_found.csv` in the project directory.

**Output CSV Columns:**
The CSV file includes columns like `ip`, `port`, `org`, `isp`, `hostnames`, `country_code`, `product`, `vulns`, `http_title`, `has_screenshot`, `last_seen`, `shodan_query`, etc.

## Example Queries (Internal)

The script automatically generates queries based on combinations like:

**In standard mode (paid API):**
*   `server:"Hikvision-Webs" OR http.favicon.hash:-1670171499 OR http.html:"Hikvision" OR product:"Hikvision" port:554`
*   `http.title:"IP Camera" port:80 has_screenshot:true`
*   `product:"Axis" port:8080`
*   `vuln:CVE-2021-36260`
*   `has_screenshot:true tag:"webcam"`

**In free mode (extremely simple queries):**
*   `webcam`
*   `camera`
*   `port:554`
*   `webcam port:80`
*   `hikvision`
*   `ipcam`
*   `dvr`

*(See the `generate_queries` function in `main.py` for the full logic)*

## Code Overview

*   `main.py`: The main executable script. Handles configuration, API interaction, query generation, data processing, and output.
*   `.env`: Stores your Shodan API key (you need to create this).
*   `.gitignore`: Ensures `.env` and other sensitive/temporary files are not tracked by Git.
*   `pyproject.toml` / `uv.lock`: Define project metadata and dependencies (if using `uv` or `poetry`).

## Contributing

Interested in improving the script? Please see the [CONTRIBUTING.md](CONTRIBUTING.md) guide.

## License

(Optional: Add license information here, e.g., MIT License)

## Troubleshooting

### Access Denied (403 Forbidden) Errors

If you encounter "Access denied (403 Forbidden)" errors even when using the `--free` flag:

1. **Check your API key**: Make sure your Shodan API key is valid and correctly set in the `.env` file.

2. **Query credits**: Free Shodan accounts have limited query credits that reset monthly. Check your available credits with:
   ```bash
   shodan info
   ```

3. **Try even simpler queries**: The script now uses extremely simple queries in free mode, but you can modify the `generate_queries` function to use even simpler queries if needed.

4. **Consider a paid plan**: For extensive camera discovery, a paid Shodan plan is recommended as it provides more query credits and access to advanced filters.