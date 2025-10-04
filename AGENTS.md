# Repository Guidelines

## Project Structure & Module Organization
Utility-security is a Maven CLI under `src/main/java/com/github/oogasawa/utility/security`. Feature modules live in `gmail`, `log`, and `usn`; shared DTOs and CLI wiring stay beside them. CLI resources (Logback config) sit in `src/main/resources`. Tests mirror the package layout in `src/test/java`, with logging overrides at `src/test/resources/logback.xml`. The shaded jar and build artifacts land in `target/`, while `run.sh` wraps the ubuntu digest pipeline.

## Build, Test, and Development Commands
Use `mvn clean package` to compile, run the full test suite, and produce `target/Utility-security-1.5.0.jar`. Run `mvn test` for the fast JUnit pass, or `mvn verify` before release to include integration checks and shade verification. Execute the CLI via `java -jar target/Utility-security-1.5.0.jar ubuntu:report -i path/to/maildump.txt`. For batch log pulls, `./run.sh 2505A` reads `~/logs-security/ubuntu-security.2505A.txt` and tees output to `~/logs-security/outfile.2505A.txt`.

## Coding Style & Naming Conventions
Source targets Java 23 with four-space indentation and K&R braces. Packages remain lowercase, classes in PascalCase, and members in camelCase. Keep CLI option names kebab-case to align with existing verbs. Maintain SLF4J/Logback for logging; extend configurations via `logback.xml` rather than ad-hoc print statements. Document public APIs with Javadoc when introducing new subcommands.

## Testing Guidelines
JUnit 5 (Surefire 3.x) drives tests. Name unit tests `*Test` and broader flows `*IntegrationTest`. Place reusable fixtures in `src/test/resources`, and slim large samples before committing. Run `mvn test` locally before pushing; prefer `mvn -DskipTests=false clean package` prior to tagging. Include assertions that cover JSON export, digest fetchers, and log rename paths when modifying those features.

## Commit & Pull Request Guidelines
Commits use short, imperative summaries (`Add USNProcessingLogDiagnostic`, `Fix LogFile filter`). Reference related issues in the body and describe manual CLI runs when relevant. Pull requests should outline the change surface, note any configuration updates (e.g., Gmail credentials requirements), and attach terminal excerpts or screenshots for new command outputs.

## Security & Configuration Tips
The CLI depends on `Utility-cli` 3.1.0; install it locally with `mvn clean install` before building. Never commit real Gmail app passwords or raw security digests—use sanitized fixtures. When editing `run.sh`, confirm path defaults still point to `~/logs-security` to avoid overwriting operator archives.
