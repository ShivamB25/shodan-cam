# Contributing to Shodan Camera Discovery Script

First off, thank you for considering contributing! We welcome improvements and fixes from the community. Whether it's adding new query types, improving efficiency, fixing bugs, or enhancing documentation, your help is appreciated.

This guide provides instructions to get you started.

## Getting Started

1.  **Fork the Repository:** Click the "Fork" button on the top right of the repository page on GitHub/GitLab/etc. This creates your own copy.
2.  **Clone Your Fork:** Clone your forked repository to your local machine:
    ```bash
    git clone <your_fork_repository_url>
    cd shodan-cam # Assuming the repo name is shodan-cam
    ```
3.  **Set Upstream Remote:** Add the original repository as the `upstream` remote. This helps you keep your fork synced.
    ```bash
    git remote add upstream https://github.com/ShivamB25/shodan-cam
    ```

## Development Setup

We recommend using a virtual environment to manage dependencies and avoid conflicts.

1.  **Create & Activate Virtual Environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

2.  **Install `uv` (if you don't have it):**
    `uv` is the recommended fast Python package installer for this project. Follow the official installation instructions: [https://github.com/astral-sh/uv#installation](https://github.com/astral-sh/uv#installation)
    (Common methods include `pip install uv`, `pipx install uv`, or using system package managers).

3.  **Install Dependencies using `uv`:**
    This command installs dependencies based on `pyproject.toml` and `uv.lock`, ensuring a consistent development environment.
    ```bash
    uv pip sync
    ```
    *Alternatively, if you prefer not to use `uv`:*
    ```bash
    # Make sure pip is up-to-date
    pip install --upgrade pip
    # Install from pyproject.toml (requires pip 21.1+)
    pip install .
    # Or if a requirements.txt is generated:
    # pip install -r requirements.txt
    ```

4.  **Set up `.env`:**
    Copy the Shodan API key configuration as described in the `README.md`. You'll need a valid key to run the script during development. Create a `.env` file in the root directory:
    ```dotenv
    # .env
    SHODAN_API_KEY=YourShodanAPIKeyForTesting
    ```

## Code Structure Overview

*   `main.py`: Contains the core logic for argument parsing (if added later), query generation (`generate_queries`), Shodan interaction (`camera_discovery`), data processing, and CSV output.
*   `README.md`: General information, usage instructions, ethical guidelines.
*   `CONTRIBUTING.md`: This file.
*   `.env`: (Not tracked by Git) Your local API key.
*   `.gitignore`: Specifies intentionally untracked files.
*   `pyproject.toml` / `uv.lock`: Project metadata and dependency definitions.

## Running Tests

(Currently, there are no automated tests. Adding tests using `pytest` would be a valuable contribution!)

If you add tests:
1.  Place them in a `tests/` directory.
2.  Use `pytest` to run them:
    ```bash
    pytest
    ```

## Submission Guidelines

1.  **Create a Branch:** Before making changes, create a new branch off the `main` (or `develop`) branch:
    ```bash
    # Make sure you're up-to-date with upstream
    git fetch upstream
    git checkout main # or develop
    git pull upstream main # or develop

    # Create your feature branch
    git checkout -b your-feature-or-fix-branch-name 
    ```
    (e.g., `feature/add-proxy-support`, `fix/improve-query-logic`)

2.  **Make Changes:** Implement your feature or fix. Keep commits logical and well-described.

3.  **Code Style:** Please try to follow PEP 8 guidelines for Python code style. Consider using a formatter like `black` or `ruff format`.

4.  **Update Documentation:** If your changes affect usage, configuration, or add new features, please update the `README.md` accordingly.

5.  **Push and Create Pull Request (PR):**
    *   Push your branch to your fork:
        ```bash
        git push origin your-feature-or-fix-branch-name
        ```
    *   Go to the original repository on GitHub/GitLab.
    *   Click the "New pull request" button.
    *   Choose your fork and branch to compare against the original repository's `main` (or `develop`) branch.
    *   Provide a clear title and description for your PR, explaining the changes and why they are needed. Reference any related issues if applicable.

6.  **Review:** We will review your PR, provide feedback if necessary, and merge it once it's ready.

Thank you again for your interest in contributing!