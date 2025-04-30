# main.py
import shodan
import pandas as pd
import os
import logging
import time
import argparse # Added for command-line arguments
from dotenv import load_dotenv # Using python-dotenv to load env vars from .env file

# --- Configuration ---
# Load environment variables from a .env file if it exists
load_dotenv()
# Fetch API key from environment variable
API_KEY = os.getenv("SHODAN_API_KEY")
# Maximum results to fetch per query (adjust based on API plan and needs)
MAX_RESULTS_PER_QUERY = 500 
# Total maximum results across all queries (prevents excessive data collection)
TOTAL_MAX_RESULTS = 10000 
# Output file name
OUTPUT_CSV = 'open_cameras_found.csv'
# Delay between API query batches (in seconds) to respect rate limits
QUERY_DELAY = 1 

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# --- Shodan Queries ---
# Based on report sections 2.1, 2.2, 6.1 and common knowledge
# Combine manufacturers, ports, titles, generic terms, and known vulns
# Define two sets of manufacturer queries - one for paid plans and one for free plans
# Free plan queries avoid using the product: filter which often causes Access Denied errors
camera_manufacturers = {
    'Hikvision': {
        'paid': 'server:"Hikvision-Webs" OR http.favicon.hash:-1670171499 OR http.html:"Hikvision" OR product:"Hikvision"',
        'free': 'server:"Hikvision-Webs" OR http.favicon.hash:-1670171499 OR http.html:"Hikvision"'
    },
    'Dahua': {
        'paid': 'http.favicon.hash:-1024525048 OR http.html:"Dahua" OR product:"Dahua"',
        'free': 'http.favicon.hash:-1024525048 OR http.html:"Dahua"'
    },
    'Axis': {
        'paid': 'html:"AXIS Video Server" OR product:"Axis"',
        'free': 'html:"AXIS Video Server"'
    },
    'Foscam': {
        'paid': 'title:"IPCamera Login" OR product:"Foscam"',
        'free': 'title:"IPCamera Login"'
    },
    'Vivotek': {
        'paid': 'http.component:"Vivotek" OR product:"Vivotek"',
        'free': 'http.component:"Vivotek"'
    },
    'GeoVision': {
        'paid': 'server:"GeoHttpServer" OR product:"GeoVision"',
        'free': 'server:"GeoHttpServer"'
    },
    'Bosch': {
        'paid': 'http.html:"Bosch Security" OR product:"Bosch"',
        'free': 'http.html:"Bosch Security"'
    },
    'Hanwha': {
        'paid': 'ssl:"Wisenet" OR product:"Hanwha" OR product:"Wisenet"',
        'free': 'ssl:"Wisenet"'
    },
    'Reolink': {
        'paid': 'product:"Reolink"',
        'free': 'http.html:"Reolink"'
    },
    'Amcrest': {
        'paid': 'product:"Amcrest"',
        'free': 'http.html:"Amcrest"'
    }
}

common_ports = ['554', '80', '8080', '88', '81', '443', '8443']
common_titles = ['"IP Camera"', '"Live View"', '"Network Camera"', '"Webcam"', '"ViewerFrame?Mode="']
# Define two sets of generic terms - one for paid plans and one for free plans
generic_terms_paid = ['webcam', 'product:"Network Video Recorder"', 'product:"NVR"', 'product:"DVR"', 'device:"webcam"']
generic_terms_free = ['webcam', 'http.title:"Network Video Recorder"', 'http.title:"NVR"', 'http.title:"DVR"', 'device:"webcam"']
vulnerability_filters = ['vuln:CVE-2021-36260', 'vuln:CVE-2017-7921', 'vuln:CVE-2023-21428'] # Add more relevant CVEs

def generate_queries(free_mode=False):
    """
    Generates a diverse list of Shodan search queries.
    If free_mode is True, excludes filters likely restricted on free plans.
    """
    queries = set() # Use a set to avoid duplicate queries
    if free_mode:
        logging.warning("Running in FREE MODE. Excluding queries with potentially restricted filters (product:, vuln:, tag:, has_screenshot:).")
        logging.warning("Free mode uses alternative queries that avoid the product: filter which often causes Access Denied errors.")

    # 1. Manufacturer + Port combinations
    for manu_name, manu_options in camera_manufacturers.items():
        # Select the appropriate query based on mode
        manu_query = manu_options['free'] if free_mode else manu_options['paid']
        
        for port in common_ports:
            queries.add(f'{manu_query} port:{port}')
            # Add screenshot filter only if not in free mode
            if not free_mode:
                queries.add(f'{manu_query} port:{port} has_screenshot:true')

    # 2. Generic Terms + Ports
    # Use the appropriate set of generic terms based on mode
    terms = generic_terms_free if free_mode else generic_terms_paid
    for term in terms:
        for port in common_ports:
            queries.add(f'{term} port:{port}')
            if not free_mode:
                queries.add(f'{term} port:{port} has_screenshot:true')

    # 3. Common Titles + Ports
    for title in common_titles:
        for port in common_ports:
            queries.add(f'http.title:{title} port:{port}')
            if not free_mode:
                queries.add(f'http.title:{title} port:{port} has_screenshot:true')

    # 4. Specific Vulnerabilities (Exclude in free mode)
    if not free_mode:
        for vuln in vulnerability_filters:
             queries.add(f'{vuln}')
             # Combine vuln with common camera ports
             for port in common_ports:
                 queries.add(f'{vuln} port:{port}')

    # 5. General Screenshot query (Exclude in free mode)
    if not free_mode:
        queries.add('has_screenshot:true product:"webcam"')
        queries.add('has_screenshot:true tag:"webcam"') # tag: filter might also be restricted
        queries.add('has_screenshot:true port:554') # RTSP often has screenshots

    # Add some basic, likely free queries just in case
    queries.add('webcam')
    # Avoid product: filter in free mode
    if free_mode:
        queries.add('http.title:"ip camera"')
    else:
        queries.add('product:"ip camera"')
    queries.add('port:554') # Basic RTSP check
    
    # Add some additional free-friendly queries
    if free_mode:
        queries.add('http.title:"camera"')
        queries.add('http.title:"RTSP"')
        queries.add('http.title:"surveillance"')
        queries.add('server:"IP Camera"')

    logging.info(f"Generated {len(queries)} unique search queries (Free mode: {free_mode}).")
    return list(queries)

# --- Shodan API Interaction ---
def camera_discovery(api, queries, max_per_query, total_max):
    """
    Performs searches using multiple queries and aggregates results.
    
    Args:
        api: Initialized Shodan API client.
        queries: A list of search strings.
        max_per_query: Max results to fetch for each individual query.
        total_max: Overall maximum results to collect.

    Returns:
        pandas.DataFrame: A DataFrame containing aggregated camera data.
    """
    all_cameras = []
    processed_ips_ports = set() # To track unique IP:Port combinations

    total_collected = 0
    query_count = 0
    total_queries = len(queries)

    for query in queries:
        query_count += 1
        if total_collected >= total_max:
            logging.warning(f"Reached total maximum results limit ({total_max}). Stopping search.")
            break
            
        logging.info(f"Executing query ({query_count}/{total_queries}): {query} (limit: {max_per_query})")
        
        try:
            # Use search_cursor for efficient pagination
            results_cursor = api.search_cursor(
                query,
                # limit=max_per_query, # search_cursor doesn't use limit directly like this
                minify=False, # Get full details
                retries=3     # Add some retries for transient errors
            )
            
            query_collected = 0
            for device in results_cursor:
                if total_collected >= total_max:
                    break 
                if query_collected >= max_per_query:
                    logging.debug(f"Reached max results ({max_per_query}) for query: {query}")
                    break

                ip_port = f"{device['ip_str']}:{device['port']}"
                if ip_port in processed_ips_ports:
                    continue # Skip duplicate entry

                entry = {
                    'ip': device['ip_str'],
                    'port': device['port'],
                    'org': device.get('org', 'N/A'),
                    'isp': device.get('isp', 'N/A'),
                    'hostnames': ', '.join(device.get('hostnames', [])),
                    'domains': ', '.join(device.get('domains', [])),
                    'country_code': device.get('location', {}).get('country_code', 'N/A'),
                    'city': device.get('location', {}).get('city', 'N/A'),
                    'product': device.get('product', 'N/A'),
                    'os': device.get('os', 'N/A'),
                    'transport': device.get('transport', 'N/A'), # tcp or udp
                    'vulns': ', '.join(device.get('vulns', [])), # List known CVEs
                    'tags': ', '.join(device.get('tags', [])),
                    'http_title': device.get('http', {}).get('title', 'N/A'),
                    'http_server': device.get('http', {}).get('server', 'N/A'),
                    'has_screenshot': device.get('has_screenshot', False),
                    'last_seen': device.get('timestamp', 'N/A'),
                    'shodan_query': query # Record which query found this device
                }
                all_cameras.append(entry)
                processed_ips_ports.add(ip_port)
                total_collected += 1
                query_collected += 1

            logging.info(f"Collected {query_collected} new results from query. Total collected: {total_collected}")
            
            # Add a delay to avoid hitting rate limits too quickly
            time.sleep(QUERY_DELAY)

        except shodan.APIError as e:
            error_message = str(e)
            logging.error(f"API Error for query '{query}': {error_message}")
            if "access denied" in error_message.lower() or "403 forbidden" in error_message.lower():
                logging.warning(f" -> This 'Access Denied' error often indicates an issue with the API key (invalid?) or insufficient plan permissions for the filter used in the query: '{query}'. Check your Shodan account/plan.")
                # Check if the query contains product: filter which often causes issues with free API
                if 'product:' in query.lower():
                    logging.warning(f" -> The 'product:' filter in this query may be causing the Access Denied error with a free API key.")
            # Consider adding more robust error handling, e.g., backoff delay based on error type
            time.sleep(QUERY_DELAY * 5) # Longer delay after error
        except Exception as e:
            logging.error(f"Unexpected error for query '{query}': {e}")
            time.sleep(QUERY_DELAY * 2)

    if not all_cameras:
        logging.warning("No camera data collected.")
        return pd.DataFrame() # Return empty DataFrame

    return pd.DataFrame(all_cameras)

# --- Main Execution ---
if __name__ == "__main__":
    logging.info("Starting Shodan Camera Discovery Script")

    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="Discover potentially exposed cameras using Shodan.")
    parser.add_argument(
        '--free',
        action='store_true',
        help='Run in free mode, excluding queries with filters likely restricted on free Shodan plans (e.g., vuln:, tag:, has_screenshot:).'
    )
    args = parser.parse_args()
    # --- End Argument Parsing ---

    if not API_KEY:
        logging.error("SHODAN_API_KEY environment variable not set. Exiting.")
        exit(1)
        
    try:
        api = shodan.Shodan(API_KEY)
        # Check API connectivity and plan info
        api_info = api.info()
        logging.info(f"Shodan API connection successful. Plan: {api_info.get('plan', 'N/A')}, Credits: {api_info.get('query_credits', 'N/A')}")
        # Add a check relevant to free mode
        if args.free and api_info.get('plan', 'N/A').lower() != 'oss' and api_info.get('query_credits', 0) > 0:
             logging.warning("Running in --free mode, but API key seems to belong to a paid plan. You might get fewer results than expected.")
        elif not args.free and api_info.get('plan', 'N/A').lower() == 'oss':
             logging.warning("Running in standard mode with a free API key. Many queries may fail due to filter restrictions. Consider using the --free flag.")
             logging.warning("Automatically switching to --free mode to avoid Access Denied errors.")
             args.free = True

    except shodan.APIError as e:
        logging.error(f"Failed to connect to Shodan API: {e}")
        exit(1)

    # Generate the list of queries, passing the free mode flag
    search_queries = generate_queries(free_mode=args.free)

    # Discover cameras
    logging.info(f"Starting camera discovery with {len(search_queries)} queries...")
    results_df = camera_discovery(api, search_queries, MAX_RESULTS_PER_QUERY, TOTAL_MAX_RESULTS)

    if not results_df.empty:
        logging.info(f"--- Discovery Summary ---")
        logging.info(f"Total unique cameras found: {len(results_df)}")
        
        # Basic Analysis (from report section 3.2)
        logging.info(f"Unique organizations: {results_df['org'].nunique()}")
        logging.info(f"Top 5 most common ports:\n{results_df['port'].value_counts().head(5)}")
        logging.info(f"Top 5 most common products:\n{results_df['product'].value_counts().head(5)}")
        logging.info(f"Top 5 most common countries:\n{results_df['country_code'].value_counts().head(5)}")
        
        # Vulnerability Analysis
        # Explode the comma-separated CVEs into individual rows for counting
        vuln_counts = results_df['vulns'].str.split(', ').explode().str.strip()
        vuln_counts = vuln_counts[vuln_counts != ''] # Remove empty strings from non-vulnerable devices
        if not vuln_counts.empty:
             logging.info(f"Vulnerability distribution (Top 10):\n{vuln_counts.value_counts().head(10)}")
        else:
             logging.info("No specific CVE vulnerabilities found in the collected results.")

        # Save results
        try:
            results_df.to_csv(OUTPUT_CSV, index=False, encoding='utf-8')
            logging.info(f"Results saved successfully to {OUTPUT_CSV}")
        except Exception as e:
            logging.error(f"Failed to save results to CSV: {e}")
            
        logging.info("--- Ethical Reminder ---")
        logging.info("Remember to handle this data responsibly and ethically.")
        logging.info("Do not attempt to access or interact with these devices without authorization.")
        logging.info("Refer to responsible disclosure guidelines if vulnerabilities are found.")

    else:
        logging.info("No results were collected or saved.")

    logging.info("Script finished.")
