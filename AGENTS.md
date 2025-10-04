# Repository Guidelines

## Project Structure & Module Organization
This project follows the standard Maven layout. Core sources live in `src/main/java/com/github/oogasawa/utility/security`, grouped by domain packages such as `usn` and `log`. Shared configuration files belong under `src/main/resources`. Tests mirror that structure in `src/test/java` with fixtures in `src/test/resources`. Release artifacts are created in `target/`. The root holds `pom.xml` for dependency and plugin management plus `run.sh` for a pre-baked CLI invocation.

## Build, Test, and Development Commands
Run `mvn clean package` to compile, execute tests, and produce the shaded jar (`target/Utility-security-<version>.jar`). Use `mvn test` for a quicker unit-test pass, or `mvn verify` before release to run integration tests and packaging checks. Execute the CLI locally via `java -jar target/Utility-security-1.5.0.jar ubuntu:report -i path/to/maildump.txt`. For repeatable log processing, `./run.sh 2505A` reads `~/logs-security/ubuntu-security.2505A.txt` and tees output to `~/logs-security/outfile.2505A.txt`. Ensure the `Utility-cli 3.1.0` dependency is installed into your local Maven repo (`mvn clean install` in that project) before building here.

## Coding Style & Naming Conventions
Target Java 23 with four-space indentation and braces on the same line as declarations. Keep packages all lowercase (`com.github.oogasawa.utility.security.*`), classes in PascalCase, and methods/fields in camelCase. Prefer descriptive option names that match existing CLI verbs (`ubuntu:report`, `--srcDir`). Avoid introducing new logging frameworks; rely on the existing SLF4J setup.

## Testing Guidelines
Tests use JUnit 5 via Surefire. Unit tests end with `Test`, while broader flows (e.g., log processors) adopt `*IntegrationTest`. Place synthetic fixtures under `src/test/resources` and document any large sample inputs. Run `mvn test` before pushing; add new coverage when extending commands or parsers so JSON export and log rename paths remain exercised.

## Commit & Pull Request Guidelines
Follow the existing concise, imperative commit style (`Add USNProcessingLogDiagnostic class`, `Fix LogFile filter tests`). Each PR should include a short summary of the change, affected commands, and manual test evidence (e.g., CLI invocation output). Link related issues when available and call out any new dependencies or configuration steps reviewers must perform.

## Security & Configuration Tips
Sanitize sensitive log data before checking it into fixtures or sharing sample outputs. Network fetchers retry automatically; keep timeout or retry tweaks localized to `usn` classes. If you modify `run.sh`, note the expected working directories so operators do not unintentionally overwrite archives.
