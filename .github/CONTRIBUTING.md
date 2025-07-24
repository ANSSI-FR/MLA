# Contributing Guidelines

Thank you for your interest in contributing to MLA! We are happy and excited to review and accept your pull requests.

## Before you begin contributing

### Code of conduct

Please review and adhere to the [code of conduct](CODE_OF_CONDUCT.md) before contributing any pull requests.

### Contribution process

All submissions, including submissions by project members, require review. We use GitHub pull requests for this purpose. Consult [GitHub Help][pull-requests] for more information on using pull requests.

### Issues

Do you just want to file an issue for the project? Please do so in GitHub under the `Issues` tab.

[pull-requests]: https://help.github.com/articles/about-pull-requests/

## Getting started

1. **Fork the repository**: start by forking the MLA repository to your GitHub account.
2. **Clone the repository**: clone your forked repository to your local machine using:
    ```bash
    git clone https://github.com/your-username/MLA.git
    ```
3. **Set upstream remote**: add the original repository as an upstream remote to keep your fork in sync:
    ```bash
    git remote add upstream https://github.com/ANSSI-FR/MLA.git
    ```

### Making changes

1. **Create a branch**: create a new branch for your changes:
    ```bash
    git checkout -b feature/your-feature-name
    ```
2. **Make your changes**: edit the code or documentation as needed.
3. **Test your changes**: ensure your changes do not break existing functionality by running tests.
4. **Commit your changes**: write clear and concise commit messages:
    ```bash
    git add .
    git commit -m "Add a brief description of your changes"
    ```

### Submitting your changes

1. **Push your branch**: push your branch to your forked repository:
    ```bash
    git push origin feature/your-feature-name
    ```
2. **Open a pull request**: navigate to the original repository and open a pull request from your branch.

### Code style and guidelines

- Follow the existing code style and conventions.

#### Documentation

- Write clear and concise comments where necessary.
- Ensure your code is well-documented, you can use `cargo doc` to generate documentation.

#### Linting and formatting

- Use `cargo fmt` to format your code according to Rust's style guidelines.
- Use `cargo clippy` to lint your code and fix any warnings or errors.

#### Testing

- Ensure your code is compatible with the latest stable version of Rust.
- Add tests for any new functionality.
- Use `cargo test` to run all tests and ensure they pass.

### Need help?

If you have any questions or need assistance, feel free to open an issue or reach out to the maintainers.

Thank you for contributing to MLA!
