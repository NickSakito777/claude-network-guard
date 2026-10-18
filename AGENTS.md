# Guard integration contract

Read docs/guard-contract.md before changing Guard behavior. Keep existing CCBaga features and local asset protections; user-approved Guard product/navigation overrides upstream BAGA branding rules.

- Work only in this independent checkout. Do not install/launch the app, alter the live guard, bind protection ports, or modify network, identities, system settings, credentials, services, or user profiles.
- User approved Rust/Bun and lockfile dependencies only under this checkout's .tools and node_modules. Do not modify global PATH or shell profiles. No installer/dev:install/release scripts.
- Use pinned dependencies and ignore dependency lifecycle scripts unless separately reviewed. Avoid live OS integration tests; use isolated fixtures. Never set GITHUB_ACTIONS to enable privileged CI tests on this host.
- The framework and shared acceptance cases are the source of truth. Tests/simulations never imply installed enforcement. An unavailable backend refuses protected starts and live-environment mutation; inspection and repair navigation remain accessible.
- Preserve existing helpers and upstream feature implementations. Add no generic plugin/workflow framework. Do not copy live config/credentials into this repository.
- Other agents share the checkout. Respect assigned ownership and do not revert their changes.
